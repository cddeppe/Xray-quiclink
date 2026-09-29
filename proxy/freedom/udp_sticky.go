package freedom

import (
    "context"
    "sync"
    "time"

    "github.com/xtls/xray-core/common/errors"
    "github.com/xtls/xray-core/common/net"
)

// StickyResolver provides per-hostname DNS result stickiness for UDP outbound.
//
// Problem it solves: when xray's freedom outbound handles many UDP flows to
// the same destination hostname (e.g., rr1---sn-xxx.googlevideo.com), it
// re-resolves the hostname per flow and picks a random IP from the result.
// If the destination has both IPv4 and IPv6 records, different flows in the
// same conversation may go out from different source IPs. Some destination
// servers (notably YouTube's CDN) embed the source IP they see in videoplayback
// URLs and reject subsequent requests if the source IP doesn't match —
// returning 400 Bad Request.
//
// The fix: cache the first resolved IP for each hostname and reuse it for
// subsequent flows within a TTL. This makes all flows to the same hostname
// use the same destination IP and (implicitly) the same source IP, so the
// destination server sees consistency.
//
// This is opt-in via the XRAY_UDP_STICKY=1 environment variable. When
// disabled, freedom uses the existing per-flow resolution path unchanged.
type StickyResolver struct {
    entries map[string]*stickyEntry
    mu      sync.RWMutex
    ttl     time.Duration
}

type stickyEntry struct {
    ip       net.Address
    lastUsed time.Time
}

// NewStickyResolver creates a new StickyResolver with the given TTL.
// Recommended TTL: 5 minutes — long enough to cover a typical video
// streaming session's related flows, short enough to handle CDN edge
// rotation eventually.
func NewStickyResolver(ttl time.Duration) *StickyResolver {
    return &StickyResolver{
        entries: make(map[string]*stickyEntry),
        ttl:     ttl,
    }
}

// Resolve returns a sticky IP for the given hostname. If a cached entry
// exists and is fresh (within TTL), returns it. Otherwise, resolves fresh
// via xray's default resolver, caches, and returns.
//
// The first resolution picks the first IP from the resolver's result
// (which may be IPv4 or IPv6 — whatever the resolver returns first).
// Subsequent resolutions of the same hostname return the same IP,
// regardless of what the resolver returns later.
func (s *StickyResolver) Resolve(ctx context.Context, hostname string) (net.Address, error) {
    // Check cache (read lock)
    s.mu.RLock()
    if entry, ok := s.entries[hostname]; ok {
        if time.Since(entry.lastUsed) < s.ttl {
            s.mu.RUnlock()
            // Update lastUsed (needs write lock, but it's just a timestamp
            // so we accept the race for simplicity)
            entry.lastUsed = time.Now()
            return entry.ip, nil
        }
    }
    s.mu.RUnlock()

    // Resolve fresh
    addrs, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
    if err != nil {
        return nil, errors.New("sticky: failed to resolve ", hostname).Base(err)
    }
    if len(addrs) == 0 {
        return nil, errors.New("sticky: no IPs returned for ", hostname)
    }

    // Pick the first IP (could prefer IPv4 here if needed — see comment below)
    ip := net.IPAddress(addrs[0].IP)
    if ip == nil {
        return nil, errors.New("sticky: resolved IP is nil for ", hostname)
    }

    // Cache (write lock)
    s.mu.Lock()
    s.entries[hostname] = &stickyEntry{
        ip:       ip,
        lastUsed: time.Now(),
    }
    s.mu.Unlock()

    errors.LogInfo(ctx, "sticky: resolved ", hostname, " -> ", ip)
    return ip, nil
}

// Note on IP family preference:
// Currently, this picks the first IP from the resolver's result. If you want
// to prefer IPv4 (or IPv6), modify the Resolve function to filter addrs by
// family before picking. For dual-stack destinations where either family
// works, "first result" is fine. For destinations where one family is more
// reliable, prefer that family explicitly.
