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
// Exact matches are permanent. Wildcard matches expire after 5 minutes.
// When a wildcard expires, we return the stale IP immediately AND
// trigger a background refresh (stale-while-revalidate).
func (s *StickyResolver) Resolve(ctx context.Context, hostname string) (net.Address, error) {
    // Check exact match first (permanent, no TTL)
    s.mu.RLock()
    if entry, ok := s.entries[hostname]; ok {
        s.mu.RUnlock()
        entry.lastUsed = time.Now()
        return entry.ip, nil
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

    ip := net.IPAddress(addrs[0].IP)
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
