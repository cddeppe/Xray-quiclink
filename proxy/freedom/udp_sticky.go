package freedom

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

// StickyResolver provides per-hostname DNS result stickiness for UDP outbound.
//
// v26.10.15-link fixes:
//   - lastUsed is now atomic.Int64 (was time.Time, mutated under RLock → data race)
//   - wildcard stale-serve fallback no longer panics on entries without a dot
//   - periodic reaper evicts entries unused for > 10× TTL (was unbounded)
//   - refresh coalescing: concurrent expiries of the same hostname result in
//     a single DNS query (was N queries for N concurrent expiries)
type StickyResolver struct {
	entries     map[string]*stickyEntry
	mu          sync.RWMutex
	ttl         time.Duration
	wildcardTTL time.Duration
	PreferIPv4  bool
	PreferIPv6  bool
	// v26.10.27-link: callback to invalidate pool sockets when
	// the resolver gets a new IP. Set by the freedom Handler.
	onIPChanged  func(oldIP, newIP string)
	refreshing   map[string]chan struct{}
	refreshingMu sync.Mutex
	stopCh       chan struct{}
}

type stickyEntry struct {
	ip       net.Address
	lastUsed atomic.Int64 // UnixNano — safe to mutate under RLock
}

func (e *stickyEntry) touch() {
	e.lastUsed.Store(time.Now().UnixNano())
}

func (e *stickyEntry) age() time.Duration {
	return time.Since(time.Unix(0, e.lastUsed.Load()))
}

func NewStickyResolver(ttl time.Duration) *StickyResolver {
	s := &StickyResolver{
		entries:     make(map[string]*stickyEntry),
		refreshing:  make(map[string]chan struct{}),
		ttl:         ttl,
		wildcardTTL: 60 * time.Second,
		stopCh:      make(chan struct{}),
	}
	go s.reaper()
	return s
}

// Close stops the reaper goroutine. Safe to call multiple times.
// v26.10.34-link (M4 fix): without this, every SIGHUP reload leaks one
// reaper goroutine + one time.Ticker per freedom outbound.
func (s *StickyResolver) Close() {
	select {
	case <-s.stopCh:
		// already closed
	default:
		close(s.stopCh)
	}
}

// RefreshByIP proactively refreshes DNS for all hostnames whose cached
// IP matches the given stale IP. Called by the UDP socket pool when it
// detects a stale socket (CDN edge rotation) — the resolver immediately
// re-resolves those hostnames in the background so the next request gets
// the fresh IP without waiting for the TTL to expire.
//
// v26.11.1-link: closes the gap between "pool detects stale socket" and
// "resolver gets new IP". Previously, the resolver would keep returning
// the old (stale) IP for up to TTL seconds (60s default), causing the
// phone to retry into a black hole for that entire window. Now the
// refresh starts immediately when the socket goes stale.
func (s *StickyResolver) RefreshByIP(staleIP string) {
	if staleIP == "" {
		return
	}
	s.mu.RLock()
	var toRefresh []string
	for host, entry := range s.entries {
		if entry.ip.String() == staleIP {
			toRefresh = append(toRefresh, host)
		}
	}
	s.mu.RUnlock()
	for _, host := range toRefresh {
		go s.refreshExact(host)
	}
	if len(toRefresh) > 0 {
		errors.LogInfo(context.Background(), "sticky: proactive refresh triggered for ", len(toRefresh), " host(s) with stale IP ", staleIP)
	}
}

// reaper periodically evicts entries that haven't been used in a while.
// Runs every 5 minutes; evicts entries older than 10× TTL.
// v26.10.15-link: fixes the unbounded cache growth that accumulated
// thousands of stale entries after extended YouTube viewing (each
// unique *.googlevideo.com subdomain added an entry that was never
// removed).
func (s *StickyResolver) reaper() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	maxAge := 10 * s.ttl
	if maxAge < 10*time.Minute {
		maxAge = 10 * time.Minute
	}
	for {
		select {
		case <-s.stopCh:
			return
		case <-t.C:
			s.mu.Lock()
			now := time.Now()
			for host, entry := range s.entries {
				if now.Sub(time.Unix(0, entry.lastUsed.Load())) > maxAge {
					delete(s.entries, host)
				}
			}
			s.mu.Unlock()
		}
	}
}

// Resolve returns a sticky IP for the given hostname.
// Both exact and wildcard matches expire after the TTL (default 5 minutes).
// When an entry expires, we return the stale IP immediately AND
// trigger a background refresh (stale-while-revalidate).
func (s *StickyResolver) Resolve(ctx context.Context, hostname string) (net.Address, error) {
	// Check exact match first (with TTL, stale-while-revalidate)
	s.mu.RLock()
	if entry, ok := s.entries[hostname]; ok {
		if entry.age() < s.ttl {
			s.mu.RUnlock()
			entry.touch() // atomic — safe under RLock
			return entry.ip, nil
		}
		staleIP := entry.ip
		s.mu.RUnlock()
		go s.refreshExact(hostname)
		errors.LogInfo(ctx, "sticky: stale-while-revalidate for ", hostname, " using stale ", staleIP)
		return staleIP, nil
	}

	// Check wildcard match (e.g., *.googlevideo.com)
	// v26.10.42-link (audit H1 from 2-a): iteratively strip labels and
	// check for a wildcard at each level. The old code only stripped the
	// first label, so "x.y.googlevideo.com" would look for
	// "*.y.googlevideo.com" (which doesn't exist) instead of
	// "*.googlevideo.com". Now we strip until we find a match or run
	// out of labels.
	remaining := hostname
	for {
		parent, ok := parentDomain(remaining)
		if !ok {
			break
		}
		wildcardKey := "*." + parent
		if entry, ok := s.entries[wildcardKey]; ok {
			if entry.age() < s.wildcardTTL {
				s.mu.RUnlock()
				entry.touch() // atomic — safe under RLock
				return entry.ip, nil
			}
			staleIP := entry.ip
			s.mu.RUnlock()
			go s.refreshWildcard(hostname, wildcardKey)
			errors.LogInfo(ctx, "sticky: stale-while-revalidate for ", hostname, " using stale ", staleIP)
			return staleIP, nil
		}
		remaining = parent
	}
	s.mu.RUnlock()

	// No cache hit — resolve fresh
	return s.resolveAndCache(ctx, hostname)
}

// parentDomain returns the parent domain of hostname (everything after
// the first dot). Returns ("", false) if hostname has no dot.
// v26.10.15-link: replaces strings.SplitN(hostname, ".", 2)[1] which
// allocated a []string slice and panicked if hostname had no dot.
func parentDomain(hostname string) (string, bool) {
	i := strings.Index(hostname, ".")
	if i < 0 || i == len(hostname)-1 {
		return "", false
	}
	return hostname[i+1:], true
}

// refreshWildcard does a background DNS resolution and updates the cache.
// This runs in a goroutine so the current request isn't blocked.
//
// v26.10.15-link: uses refresh coalescing — if a refresh is already in
// progress for this hostname, this goroutine waits for it instead of
// firing its own DNS query.
func (s *StickyResolver) refreshWildcard(hostname, wildcardKey string) {
	if !s.startRefresh(hostname) {
		return // another goroutine is already refreshing
	}
	defer s.finishRefresh(hostname)

	// v26.10.34-link (M3 fix): bound DNS refresh so a hung resolver
	// doesn't stall all subsequent resolves for this hostname
	// (startRefresh blocks on <-ch for follow-up callers).
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// v26.10.40-link: use xray's DNS client (honors dns.servers domain rules,
	// finalQuery, timeoutMs) instead of Go's net.DefaultResolver (which
	// reads /etc/resolv.conf and bypasses all xray DNS config — important
	// for WireGuard + ctrld setups where xray's DNS config routes specific
	// domains like *.googlevideo.com to a US-geo resolver).
	ips, err := internet.LookupForIP(hostname, internet.DomainStrategy_USE_IP46, nil)
	if err != nil || len(ips) == 0 {
		errors.LogInfo(ctx, "sticky: background refresh failed for ", hostname, ": ", err)
		return
	}
	addrs := make([]net.IPAddr, len(ips))
	for i, ip := range ips {
		addrs[i] = net.IPAddr{IP: ip}
	}
	if err != nil || len(addrs) == 0 {
		errors.LogInfo(ctx, "sticky: background refresh failed for ", hostname, ": ", err)
		return
	}

	// v26.10.26-link: honor PreferIPv4/PreferIPv6 (was addrs[0])
	ip := net.IPAddress(selectAddr(addrs, s.PreferIPv4, s.PreferIPv6))
	if ip == nil {
		return
	}

	now := time.Now().UnixNano()
	s.mu.Lock()
	oldIP := ""
	if oldEntry, ok := s.entries[hostname]; ok {
		oldIP = oldEntry.ip.String()
	}
	// S1 fix: also capture old wildcard IP for sibling invalidation.
	oldWildcardIP := ""
	if oldWcEntry, ok := s.entries[wildcardKey]; ok {
		oldWildcardIP = oldWcEntry.ip.String()
	}
	s.entries[wildcardKey] = &stickyEntry{ip: ip}
	s.entries[wildcardKey].lastUsed.Store(now)
	s.entries[hostname] = &stickyEntry{ip: ip}
	s.entries[hostname].lastUsed.Store(now)
	// S1 fix: invalidate sibling exact entries pointing at old wildcard IP.
	// When YouTube rotates CDN edge, sibling subdomains (r1, r2, r3...)
	// still have the old dead IP. Delete them so they re-resolve on next use.
	if oldWildcardIP != "" && oldWildcardIP != ip.String() {
		for host, entry := range s.entries {
			if !strings.HasPrefix(host, "*.") && entry.ip.String() == oldWildcardIP {
				delete(s.entries, host)
			}
		}
	}
	s.mu.Unlock()

	// v26.10.27-link: notify pool to invalidate old-IP sockets
	// Use oldWildcardIP if available (broader invalidation), else oldIP
	notifyIP := oldWildcardIP
	if notifyIP == "" {
		notifyIP = oldIP
	}
	if s.onIPChanged != nil && notifyIP != "" && notifyIP != ip.String() {
		s.onIPChanged(notifyIP, ip.String())
	}

	errors.LogInfo(ctx, "sticky: background refresh completed for ", hostname, " -> ", ip)
}

// refreshExact does a background DNS resolution and updates the exact-match cache.
// v26.10.15-link: uses refresh coalescing.
func (s *StickyResolver) refreshExact(hostname string) {
	if !s.startRefresh(hostname) {
		return // another goroutine is already refreshing
	}
	defer s.finishRefresh(hostname)

	// v26.10.34-link (M3 fix): bound DNS refresh so a hung resolver
	// doesn't stall all subsequent resolves for this hostname.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// v26.10.40-link: use xray's DNS client (honors dns.servers domain rules,
	// finalQuery, timeoutMs) instead of Go's net.DefaultResolver (which
	// reads /etc/resolv.conf and bypasses all xray DNS config — important
	// for WireGuard + ctrld setups where xray's DNS config routes specific
	// domains like *.googlevideo.com to a US-geo resolver).
	ips, err := internet.LookupForIP(hostname, internet.DomainStrategy_USE_IP46, nil)
	if err != nil || len(ips) == 0 {
		errors.LogInfo(ctx, "sticky: background refresh failed for ", hostname, ": ", err)
		return
	}
	addrs := make([]net.IPAddr, len(ips))
	for i, ip := range ips {
		addrs[i] = net.IPAddr{IP: ip}
	}
	if err != nil || len(addrs) == 0 {
		errors.LogInfo(ctx, "sticky: background refresh failed for ", hostname)
		return
	}

	selectedAddr := selectAddr(addrs, s.PreferIPv4, s.PreferIPv6)
	ip := net.IPAddress(selectedAddr)
	if ip == nil {
		return
	}

	s.mu.Lock()
	oldIP := ""
	if oldEntry, ok := s.entries[hostname]; ok {
		oldIP = oldEntry.ip.String()
	}
	entry := &stickyEntry{ip: ip}
	entry.lastUsed.Store(time.Now().UnixNano())
	s.entries[hostname] = entry
	// v26.10.34-link (M2 fix): invalidate sibling exact entries pointing
	// at the old IP so they re-resolve on next use. Mirrors the S1 fix in
	// refreshWildcard — without this, sibling subdomains keep using a
	// dead IP for up to ttl (default 300s) after the resolver knows better.
	if oldIP != "" && oldIP != ip.String() {
		for host, entry := range s.entries {
			if host != hostname && !strings.HasPrefix(host, "*.") && entry.ip.String() == oldIP {
				delete(s.entries, host)
			}
		}
		// v26.10.42-link (audit H2 from 2-a): also update the wildcard
		// entry if it exists for this hostname's parent domain and still
		// points at the old IP. Without this, siblings that use the
		// wildcard cache keep getting the old IP until the wildcard TTL
		// expires.
		if parent, ok := parentDomain(hostname); ok {
			wildcardKey := "*." + parent
			if wcEntry, ok := s.entries[wildcardKey]; ok && wcEntry.ip.String() == oldIP {
				wcEntry.ip = ip
				wcEntry.lastUsed.Store(time.Now().UnixNano())
			}
		}
	}
	s.mu.Unlock()

	// v26.10.27-link: notify pool to invalidate old-IP sockets
	if s.onIPChanged != nil && oldIP != "" && oldIP != ip.String() {
		s.onIPChanged(oldIP, ip.String())
	}

	errors.LogInfo(ctx, "sticky: background refresh completed for ", hostname, " -> ", ip)
}

// startRefresh attempts to start a refresh for hostname. Returns true if
// this caller should proceed (and later call finishRefresh), false if
// another goroutine is already refreshing this hostname.
// v26.10.15-link: coalesces concurrent refreshes to avoid N DNS queries
// for N concurrent expiries of the same hostname.
func (s *StickyResolver) startRefresh(hostname string) bool {
	s.refreshingMu.Lock()
	defer s.refreshingMu.Unlock()
	if ch, ok := s.refreshing[hostname]; ok {
		// Another goroutine is already refreshing. Wait for it.
		// We release refreshingMu before waiting so other callers
		// can also wait.
		s.refreshingMu.Unlock()
		<-ch
		s.refreshingMu.Lock()
		return false
	}
	s.refreshing[hostname] = make(chan struct{})
	return true
}

// finishRefresh marks the refresh for hostname as complete and wakes
// up any waiting goroutines.
func (s *StickyResolver) finishRefresh(hostname string) {
	s.refreshingMu.Lock()
	ch, ok := s.refreshing[hostname]
	if ok {
		delete(s.refreshing, hostname)
	}
	s.refreshingMu.Unlock()
	if ok {
		close(ch)
	}
}

// selectAddr applies IPv4/IPv6 preference to the address list and
// returns the selected IP. If no preference is set, returns addrs[0].IP.
func selectAddr(addrs []net.IPAddr, preferIPv4, preferIPv6 bool) net.IP {
	if preferIPv4 || preferIPv6 {
		for _, addr := range addrs {
			if preferIPv4 && len(addr.IP) == net.IPv4len {
				return addr.IP
			}
			if preferIPv6 && len(addr.IP) == net.IPv6len {
				return addr.IP
			}
		}
		// M3 fix: return nil if preferred family not found.
		// Callers already check ip == nil. Previously returned
		// addrs[0] (wrong family) causing IPv4/IPv6 flips.
		return nil
	}
	return addrs[0].IP
}

// resolveAndCache does a fresh DNS resolution and caches the result.
func (s *StickyResolver) resolveAndCache(ctx context.Context, hostname string) (net.Address, error) {
	// v26.10.40-link: use xray's DNS client (honors dns.servers domain rules,
	// finalQuery, timeoutMs) instead of Go's net.DefaultResolver (which
	// reads /etc/resolv.conf and bypasses all xray DNS config — important
	// for WireGuard + ctrld setups where xray's DNS config routes specific
	// domains like *.googlevideo.com to a US-geo resolver).
	ips, err := internet.LookupForIP(hostname, internet.DomainStrategy_USE_IP46, nil)
	if err != nil || len(ips) == 0 {
		// Stale-serve fallback: look for any cached wildcard entry
		// whose parent domain matches this hostname.
		// v26.10.15-link: fixed the panic on entries without a dot
		// (the old strings.SplitN(host, ".", 2)[1] crashed on hosts
		// like "youtube.com" that have no dot — well, they have one
		// dot, but SplitN with limit 2 returns ["youtube", "com"]
		// which is fine... the actual crash was on hosts with NO dot
		// at all, like a bare TLD. The new parentDomain helper handles
		// this correctly by returning ok=false).
		s.mu.RLock()
		for host, entry := range s.entries {
			if !strings.HasPrefix(host, "*.") {
				continue
			}
			suffix := host[1:] // ".googlevideo.com"
			if strings.HasSuffix(hostname, suffix) {
				s.mu.RUnlock()
				errors.LogInfo(ctx, "sticky: stale-serve fallback for ", hostname, " using ", entry.ip)
				return entry.ip, nil
			}
		}
		s.mu.RUnlock()
		return nil, errors.New("sticky: failed to resolve and no stale cache for ", hostname)
	}
	addrs := make([]net.IPAddr, len(ips))
	for i, ip := range ips {
		addrs[i] = net.IPAddr{IP: ip}
	}

	selectedAddr := selectAddr(addrs, s.PreferIPv4, s.PreferIPv6)
	ip := net.IPAddress(selectedAddr)
	if ip == nil {
		return nil, errors.New("sticky: resolved IP is nil for ", hostname)
	}

	// Cache exact match and wildcard
	s.mu.Lock()
	now := time.Now().UnixNano()
	exactEntry := &stickyEntry{ip: ip}
	exactEntry.lastUsed.Store(now)
	s.entries[hostname] = exactEntry
	if parent, ok := parentDomain(hostname); ok {
		wildcardKey := "*." + parent
		if _, exists := s.entries[wildcardKey]; !exists {
			wcEntry := &stickyEntry{ip: ip}
			wcEntry.lastUsed.Store(now)
			s.entries[wildcardKey] = wcEntry
		}
	}
	s.mu.Unlock()

	errors.LogInfo(ctx, "sticky: resolved ", hostname, " -> ", ip)
	return ip, nil
}
