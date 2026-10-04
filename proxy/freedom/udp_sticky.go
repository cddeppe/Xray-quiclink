package freedom

import (
        "context"
        "strings"
        "sync"
        "sync/atomic"
        "time"

        "github.com/xtls/xray-core/common/errors"
        "github.com/xtls/xray-core/common/net"
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
        // v26.10.15-link: refresh coalescing. When a refresh is in progress
        // for a hostname, the channel is closed when the refresh completes.
        // Concurrent callers wait on the channel instead of firing their own
        // DNS query.
        refreshing   map[string]chan struct{}
        refreshingMu sync.Mutex
        // v26.10.15-link: stop channel for the reaper goroutine.
        stopCh chan struct{}
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
        if parent, ok := parentDomain(hostname); ok {
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

        ctx := context.Background()
        addrs, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
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
        s.entries[wildcardKey] = &stickyEntry{ip: ip}
        s.entries[wildcardKey].lastUsed.Store(now)
        s.entries[hostname] = &stickyEntry{ip: ip}
        s.entries[hostname].lastUsed.Store(now)
        s.mu.Unlock()

        errors.LogInfo(ctx, "sticky: background refresh completed for ", hostname, " -> ", ip)
}

// refreshExact does a background DNS resolution and updates the exact-match cache.
// v26.10.15-link: uses refresh coalescing.
func (s *StickyResolver) refreshExact(hostname string) {
        if !s.startRefresh(hostname) {
                return // another goroutine is already refreshing
        }
        defer s.finishRefresh(hostname)

        ctx := context.Background()
        addrs, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
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
        entry := &stickyEntry{ip: ip}
        entry.lastUsed.Store(time.Now().UnixNano())
        s.entries[hostname] = entry
        s.mu.Unlock()
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
        }
        return addrs[0].IP
}

// resolveAndCache does a fresh DNS resolution and caches the result.
func (s *StickyResolver) resolveAndCache(ctx context.Context, hostname string) (net.Address, error) {
        addrs, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
        if err != nil || len(addrs) == 0 {
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
