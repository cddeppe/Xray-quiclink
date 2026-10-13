package freedom

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

// StickyResolver keeps one address per hostname for a short while.
//
// The problem it exists for: a hostname commonly resolves to several
// addresses, and anything that sends more than one packet or opens more than
// one connection will otherwise pick a different address each time. For a QUIC
// flow that is fatal, because the packets of one connection scatter across
// several servers and the handshake never completes. Pinning a hostname to one
// address for the duration of a transfer avoids that.
//
// # Scope of an entry
//
// An entry is created only from a DNS answer for that exact hostname. It is
// never derived from a sibling hostname.
//
// Earlier revisions additionally cached a wildcard. Resolving www.example.com
// also stored "*.example.com" at the same address, and every other
// *.example.com hostname was then answered with that address without being
// looked up at all. That flattens a CDN's per-hostname edge selection onto a
// single server. Because each *.googlevideo.com hostname names a different
// edge, the practical effect is that all video traffic queues through one
// machine, which presents as stalls and heavy buffering.
//
// The hostname-to-address mapping handed to this resolver is the information
// the operator's DNS is trying to communicate, so it must not be collapsed.
//
// v26.13.6-link: removed the automatic wildcard entry, the wildcard lookup
// path, the refresh-time overwrite of a hostname's own entry that came with
// them, and the sibling-invalidation sweep that deleted entries which merely
// happened to share an address. Also fixed address-family detection.
type StickyResolver struct {
	entries map[string]*stickyEntry
	mu      sync.RWMutex
	ttl     time.Duration

	PreferIPv4 bool
	PreferIPv6 bool

	onIPChanged func(oldIP, newIP string)

	refreshing   map[string]struct{}
	refreshingMu sync.Mutex

	stopCh chan struct{}
}

type stickyEntry struct {
	ip       net.Address
	lastUsed atomic.Int64
}

func (e *stickyEntry) touch() {
	e.lastUsed.Store(time.Now().UnixNano())
}

func (e *stickyEntry) age() time.Duration {
	return time.Since(time.Unix(0, e.lastUsed.Load()))
}

func NewStickyResolver(ttl time.Duration) *StickyResolver {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	s := &StickyResolver{
		entries:    make(map[string]*stickyEntry),
		refreshing: make(map[string]struct{}),
		ttl:        ttl,
		stopCh:     make(chan struct{}),
	}
	go s.reaper()
	return s
}

// Close stops the reaper goroutine. Safe to call more than once.
func (s *StickyResolver) Close() {
	select {
	case <-s.stopCh:
	default:
		close(s.stopCh)
	}
}

// reaper evicts entries that have not been used for a long time. Without it the
// cache grows without bound as unique hostnames are seen; a single video
// playback contributes several.
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

// Resolve returns the address to use for hostname.
//
// A fresh entry is returned immediately. A stale entry is also returned
// immediately, with a refresh started in the background so the next call sees
// the current answer; that keeps one slow lookup off the request path. Prefer
// ResolveFresh where a stale address costs more than the wait.
func (s *StickyResolver) Resolve(ctx context.Context, hostname string) (net.Address, error) {
	s.mu.RLock()
	entry, ok := s.entries[hostname]
	if !ok {
		s.mu.RUnlock()
		return s.resolveAndCache(ctx, hostname)
	}
	if entry.age() < s.ttl {
		s.mu.RUnlock()
		entry.touch()
		return entry.ip, nil
	}
	staleIP := entry.ip
	s.mu.RUnlock()

	go s.refresh(hostname)
	errors.LogInfo(ctx, "sticky: stale-while-revalidate for ", hostname, " using stale ", staleIP)
	return staleIP, nil
}

// ResolveFresh is Resolve without stale-while-revalidate: an expired entry is
// not handed back, the caller waits for the lookup. Worth using wherever
doing the lookup is cheaper than failing once, such as the start of a QUIC
// handshake, where a dead address costs a whole handshake.
func (s *StickyResolver) ResolveFresh(ctx context.Context, hostname string) (net.Address, error) {
	s.mu.RLock()
	entry, ok := s.entries[hostname]
	if ok && entry.age() < s.ttl {
		s.mu.RUnlock()
		entry.touch()
		return entry.ip, nil
	}
	s.mu.RUnlock()

	ip, err := s.lookup(hostname)
	if err == nil {
		s.store(hostname, ip, ctx)
		return ip, nil
	}

	// The lookup failed. A stale address is a better answer than an outright
	// failure, so use it if there is one.
	s.mu.RLock()
	defer s.mu.RUnlock()
	if entry, ok := s.entries[hostname]; ok {
		errors.LogInfo(ctx, "sticky: lookup failed for ", hostname, ", using stale ", entry.ip, ": ", err)
		return entry.ip, nil
	}
	return nil, errors.New("sticky: failed to resolve ", hostname).Base(err)
}

// refresh re-resolves hostname and updates its entry. Concurrent refreshes of
// the same hostname are coalesced into one lookup, which matters because a
// stale entry can be hit by many requests at once.
func (s *StickyResolver) refresh(hostname string) {
	if !s.startRefresh(hostname) {
		return
	}
	defer s.finishRefresh(hostname)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ip, err := s.lookup(hostname)
	if err != nil {
		errors.LogInfo(ctx, "sticky: refresh failed for ", hostname, ": ", err)
		return
	}
	s.store(hostname, ip, ctx)
}

// lookup resolves hostname through xray's DNS client, so that dns.servers
// domain rules, finalQuery and timeoutMs are honoured. net.DefaultResolver
// reads /etc/resolv.conf and would bypass all of that, which matters when
// particular domains are meant to go to a particular resolver.
//
// It returns either an address or an error, never neither.
func (s *StickyResolver) lookup(hostname string) (net.Address, error) {
	ips, err := internet.LookupForIP(hostname, internet.DomainStrategy_USE_IP46, nil)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("no addresses returned")
	}
	addrs := make([]net.IPAddr, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, net.IPAddr{IP: ip})
	}
	addr := net.IPAddress(selectAddr(addrs, s.PreferIPv4, s.PreferIPv6))
	if addr == nil {
		return nil, errors.New("no usable address returned")
	}
	return addr, nil
}

// store writes the entry for exactly one hostname. Nothing is derived from it:
// see the note on the type.
func (s *StickyResolver) store(hostname string, ip net.Address, ctx context.Context) {
	s.mu.Lock()
	oldIP := ""
	if old, ok := s.entries[hostname]; ok {
		oldIP = old.ip.String()
	}
	entry := &stickyEntry{ip: ip}
	entry.touch()
	s.entries[hostname] = entry
	s.mu.Unlock()

	newIP := ip.String()
	if oldIP != "" && oldIP != newIP && s.onIPChanged != nil {
		s.onIPChanged(oldIP, newIP)
	}
	errors.LogInfo(ctx, "sticky: resolved ", hostname, " -> ", newIP)
}

func (s *StickyResolver) resolveAndCache(ctx context.Context, hostname string) (net.Address, error) {
	ip, err := s.lookup(hostname)
	if err != nil {
		return nil, errors.New("sticky: failed to resolve ", hostname).Base(err)
	}
	s.store(hostname, ip, ctx)
	return ip, nil
}

// startRefresh claims the refresh slot for hostname. It returns false when a
// refresh is already running, in which case the caller should not start one.
func (s *StickyResolver) startRefresh(hostname string) bool {
	s.refreshingMu.Lock()
	defer s.refreshingMu.Unlock()
	if _, ok := s.refreshing[hostname]; ok {
		return false
	}
	s.refreshing[hostname] = struct{}{}
	return true
}

func (s *StickyResolver) finishRefresh(hostname string) {
	s.refreshingMu.Lock()
	delete(s.refreshing, hostname)
	s.refreshingMu.Unlock()
}

// selectAddr picks an address from a DNS answer, applying the IPv4/IPv6
// preference if one is set.
//
// Family is decided with To4 rather than by comparing len(IP) against a length
// constant. An IPv4 address is frequently held in its 16-byte form -- anything
// produced by net.ParseIP is -- so a length test misclassifies it as IPv6 and
// the preference silently selects the wrong family, or nothing at all.
//
// When the preferred family is not present, the first address is used rather
// than returning nil. A nil result makes the caller discard the entry and log
// "invalid IP format: []", and the next request then resolves again, so the
// resolver never actually sticks.
func selectAddr(addrs []net.IPAddr, preferIPv4, preferIPv6 bool) net.IP {
	if len(addrs) == 0 {
		return nil
	}
	if preferIPv4 || preferIPv6 {
		for _, addr := range addrs {
			if preferIPv4 && addr.IP.To4() != nil {
				return addr.IP
			}
			if preferIPv6 && addr.IP.To4() == nil && addr.IP.To16() != nil {
				return addr.IP
			}
		}
	}
	return addrs[0].IP
}
