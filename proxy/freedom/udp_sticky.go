package freedom

import (
    "context"
    "strings"
    "sync"
    "time"

    "github.com/xtls/xray-core/common/errors"
    "github.com/xtls/xray-core/common/net"
)

// StickyResolver provides per-hostname DNS result stickiness for UDP outbound.
type StickyResolver struct {
    entries    map[string]*stickyEntry
    mu         sync.RWMutex
    ttl        time.Duration
    wildcardTTL time.Duration
    PreferIPv4 bool
    PreferIPv6 bool
}

type stickyEntry struct {
    ip       net.Address
    lastUsed time.Time
}

func NewStickyResolver(ttl time.Duration) *StickyResolver {
    return &StickyResolver{
        entries:    make(map[string]*stickyEntry),
        ttl:        ttl,
        wildcardTTL: 60 * time.Second,
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
        if time.Since(entry.lastUsed) < s.ttl {
            s.mu.RUnlock()
            entry.lastUsed = time.Now()
            return entry.ip, nil
        }
        staleIP := entry.ip
        s.mu.RUnlock()
        go s.refreshExact(hostname)
        errors.LogInfo(ctx, "sticky: stale-while-revalidate for ", hostname, " using stale ", staleIP)
        return staleIP, nil
    }

    // Check wildcard match (e.g., *.googlevideo.com)
    parts := strings.SplitN(hostname, ".", 2)
    if len(parts) == 2 {
        wildcardKey := "*." + parts[1]
        if entry, ok := s.entries[wildcardKey]; ok {
            if time.Since(entry.lastUsed) < s.wildcardTTL {
                // Wildcard is fresh — return it instantly
                s.mu.RUnlock()
                entry.lastUsed = time.Now()
                return entry.ip, nil
            }
            // Wildcard is expired — return stale IP immediately,
            // AND trigger background refresh (stale-while-revalidate)
            staleIP := entry.ip
            s.mu.RUnlock()

            // Background refresh: resolve in a goroutine
            go s.refreshWildcard(hostname, wildcardKey)

            errors.LogInfo(ctx, "sticky: stale-while-revalidate for ", hostname, " using stale ", staleIP)
            return staleIP, nil
        }
    }
    s.mu.RUnlock()

    // No cache hit — resolve fresh
    return s.resolveAndCache(ctx, hostname)
}

// refreshWildcard does a background DNS resolution and updates the cache.
// This runs in a goroutine so the current request isn't blocked.
func (s *StickyResolver) refreshWildcard(hostname, wildcardKey string) {
    ctx := context.Background()
    addrs, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
    if err != nil || len(addrs) == 0 {
        errors.LogInfo(ctx, "sticky: background refresh failed for ", hostname, ": ", err)
        return
    }

    ip := net.IPAddress(addrs[0].IP)
    if ip == nil {
        return
    }

    // Update the wildcard cache with the fresh IP
    s.mu.Lock()
    s.entries[wildcardKey] = &stickyEntry{ip: ip, lastUsed: time.Now()}
    // Also update the exact match
    s.entries[hostname] = &stickyEntry{ip: ip, lastUsed: time.Now()}
    s.mu.Unlock()

    errors.LogInfo(ctx, "sticky: background refresh completed for ", hostname, " -> ", ip)
}

// refreshExact does a background DNS resolution and updates the exact-match cache.
// This runs in a goroutine so the current request isn't blocked.
func (s *StickyResolver) refreshExact(hostname string) {
    ctx := context.Background()
    addrs, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
    if err != nil || len(addrs) == 0 {
        errors.LogInfo(ctx, "sticky: background refresh failed for ", hostname)
        return
    }

    // Apply preference
    var selectedAddr net.IP
    if s.PreferIPv4 || s.PreferIPv6 {
        for _, addr := range addrs {
            if s.PreferIPv4 && len(addr.IP) == net.IPv4len {
                selectedAddr = addr.IP
                break
            }
            if s.PreferIPv6 && len(addr.IP) == net.IPv6len {
                selectedAddr = addr.IP
                break
            }
        }
    }
    if selectedAddr == nil {
        selectedAddr = addrs[0].IP
    }
    ip := net.IPAddress(selectedAddr)
    if ip == nil {
        return
    }

    s.mu.Lock()
    s.entries[hostname] = &stickyEntry{ip: ip, lastUsed: time.Now()}
    s.mu.Unlock()
    errors.LogInfo(ctx, "sticky: background refresh completed for ", hostname, " -> ", ip)
}

// resolveAndCache does a fresh DNS resolution and caches the result.
func (s *StickyResolver) resolveAndCache(ctx context.Context, hostname string) (net.Address, error) {
    addrs, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
    if err != nil || len(addrs) == 0 {
        // Stale-serve fallback: look for any cached entry with same domain suffix
        s.mu.RLock()
        for host, entry := range s.entries {
            if strings.HasSuffix(hostname, strings.SplitN(host, ".", 2)[1]) {
                s.mu.RUnlock()
                errors.LogInfo(ctx, "sticky: stale-serve fallback for ", hostname, " using ", entry.ip)
                return entry.ip, nil
            }
        }
        s.mu.RUnlock()
        return nil, errors.New("sticky: failed to resolve and no stale cache for ", hostname)
    }

    // Apply IPv4/IPv6 preference if set. If PreferIPv4 is true, scan for
    // the first IPv4 address. If PreferIPv6 is true, scan for the first
    // IPv6 address. If neither is set, fall back to addrs[0].
    var selectedAddr net.IP
    if s.PreferIPv4 || s.PreferIPv6 {
        for _, addr := range addrs {
            if s.PreferIPv4 && len(addr.IP) == net.IPv4len {
                selectedAddr = addr.IP
                break
            }
            if s.PreferIPv6 && len(addr.IP) == net.IPv6len {
                selectedAddr = addr.IP
                break
            }
        }
    }
    if selectedAddr == nil {
        selectedAddr = addrs[0].IP
    }
    ip := net.IPAddress(selectedAddr)
    if ip == nil {
        return nil, errors.New("sticky: resolved IP is nil for ", hostname)
    }

    // Cache exact match and wildcard
    s.mu.Lock()
    s.entries[hostname] = &stickyEntry{ip: ip, lastUsed: time.Now()}
    parts := strings.SplitN(hostname, ".", 2)
    if len(parts) == 2 {
        wildcardKey := "*." + parts[1]
        if _, exists := s.entries[wildcardKey]; !exists {
            s.entries[wildcardKey] = &stickyEntry{ip: ip, lastUsed: time.Now()}
        }
    }
    s.mu.Unlock()

    errors.LogInfo(ctx, "sticky: resolved ", hostname, " -> ", ip)
    return ip, nil
}
