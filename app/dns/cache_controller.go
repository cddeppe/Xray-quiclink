package dns

import (
        "context"
        go_errors "errors"
        "net"
        "runtime"
        "strings"
        "sync"
        "time"

        "github.com/xtls/xray-core/common"
        "github.com/xtls/xray-core/common/errors"
        "github.com/xtls/xray-core/common/signal/pubsub"
        "github.com/xtls/xray-core/common/task"
        dns_feature "github.com/xtls/xray-core/features/dns"

        "golang.org/x/net/dns/dnsmessage"
        "golang.org/x/sync/singleflight"
)

const (
        minSizeForEmptyRebuild  = 512
        shrinkAbsoluteThreshold = 10240
        shrinkRatioThreshold    = 0.65
        migrationBatchSize      = 4096
)

type CacheController struct {
        name            string
        disableCache    bool
        serveStale      bool
        serveExpiredTTL int32
        // v26.10.40-link: prefetch config and refresher
        prefetchInterval   time.Duration
        prefetchThreshold  time.Duration
        prefetchNameserver CachedNameserver // back-reference for issuing refresh queries
        prefetchWorker     *task.Periodic

        ips      map[string]*record
        dirtyips map[string]*record

        sync.RWMutex
        pub           *pubsub.Service
        cacheCleanup  *task.Periodic
        highWatermark int
        requestGroup  singleflight.Group
}

func NewCacheController(name string, disableCache bool, serveStale bool, serveExpiredTTL uint32) *CacheController {
        c := &CacheController{
                name:            name,
                disableCache:    disableCache,
                serveStale:      serveStale,
                serveExpiredTTL: -int32(serveExpiredTTL),
                ips:             make(map[string]*record),
                pub:             pubsub.NewService(),
        }

        c.cacheCleanup = &task.Periodic{
                Interval: 300 * time.Second,
                Execute:  c.CacheCleanup,
        }
        return c
}

// v26.10.40-link: SetPrefetch configures background prefetch of near-expiry
// cache entries. Interval=0 disables prefetch. Threshold is how long before
// expiry to trigger a refresh (e.g. threshold=30s on an entry with TTL=60s
// will be refreshed at T+30s). The nameserver is the back-reference needed
// to issue the refresh query via the existing pull() path.
//
// Must be called once, after the CacheController is wired into a nameserver,
// before the nameserver starts serving queries. Safe to call multiple times
// (later call replaces earlier).
func (c *CacheController) SetPrefetch(interval, threshold time.Duration, ns CachedNameserver) {
        c.prefetchInterval = interval
        c.prefetchThreshold = threshold
        c.prefetchNameserver = ns
        if c.prefetchWorker != nil {
                _ = c.prefetchWorker.Close()
                c.prefetchWorker = nil
        }
        if interval <= 0 || threshold <= 0 || ns == nil {
                return
        }
        c.prefetchWorker = &task.Periodic{
                Interval: interval,
                Execute:  c.Prefetch,
        }
}

// Prefetch scans the cache for near-expiry entries and issues background
// refresh queries. Called periodically by prefetchWorker. Returns nil to
// keep the periodic task running; an error would stop it (we never want
// that, so always return nil).
func (c *CacheController) Prefetch() error {
        if c.prefetchNameserver == nil {
                return nil
        }
        candidates := c.collectPrefetchCandidates()
        if len(candidates) == 0 {
                return nil
        }
        errors.LogInfo(context.Background(), c.name, " prefetch: refreshing ", len(candidates), " near-expiry entries")
        // Issue refresh queries in parallel so we don't block the prefetch
        // worker goroutine for 1s × N entries.
        var wg sync.WaitGroup
        for _, fqdn := range candidates {
                wg.Add(1)
                go func(fqdn string) {
                        defer wg.Done()
                        // pull() uses an 8s timeout and respects singleflight
                        // (concurrent prefetch + foreground queries are coalesced).
                        // IPv4+IPv6 both enabled — same as the foreground path.
                        pull(context.Background(), c.prefetchNameserver, fqdn, dns_feature.IPOption{
                                IPv4Enable: true,
                                IPv6Enable: true,
                        })
                }(fqdn)
        }
        wg.Wait()
        return nil
}

// collectPrefetchCandidates returns the FQDNs of cache entries whose A or
// AAAA record expires within prefetchThreshold, OR whose A/AAAA records
// have been cleaned (set to nil by CacheCleanup) but the entry still
// exists in the map. This ensures the prefetch goroutine refreshes
// expired entries before they're fully deleted, keeping the cache warm
// even during idle periods.
//
// v26.10.49-link: previously, entries whose A/AAAA had been set to nil
// by CacheCleanup were skipped (rec.A != nil check failed). This meant
// that after sitting idle for >serveExpiredTTL seconds, all *.googlevideo.com
// entries were cleaned and the wildcard fallback (v26.10.48) had nothing
// to return. Now the prefetch also refreshes these "zombie" entries.
func (c *CacheController) collectPrefetchCandidates() []string {
        c.RLock()
        defer c.RUnlock()
        if len(c.ips) == 0 {
                return nil
        }
        threshold := time.Now().Add(c.prefetchThreshold)
        out := make([]string, 0, 16)
        for domain, rec := range c.ips {
                if rec == nil {
                        continue
                }
                // v26.10.49-link: also collect entries whose A/AAAA was
                // cleaned by CacheCleanup (set to nil) but the entry still
                // exists. These need refresh before they're fully deleted.
                if rec.A == nil && rec.AAAA == nil {
                        out = append(out, domain)
                        continue
                }
                if rec.A != nil && rec.A.Expire.Before(threshold) {
                        out = append(out, domain)
                        continue
                }
                if rec.AAAA != nil && rec.AAAA.Expire.Before(threshold) {
                        out = append(out, domain)
                }
        }
        return out
}

// CacheCleanup clears expired items from cache
func (c *CacheController) CacheCleanup() error {
        expiredKeys, err := c.collectExpiredKeys()
        if err != nil {
                return err
        }
        if len(expiredKeys) == 0 {
                return nil
        }
        c.writeAndShrink(expiredKeys)
        return nil
}

func (c *CacheController) collectExpiredKeys() ([]string, error) {
        c.RLock()
        defer c.RUnlock()

        if len(c.ips) == 0 {
                return nil, errors.New("nothing to do. stopping...")
        }

        // skip collection if a migration is in progress
        if c.dirtyips != nil {
                return nil, nil
        }

        now := time.Now()
        if c.serveStale && c.serveExpiredTTL != 0 {
                now = now.Add(time.Duration(c.serveExpiredTTL) * time.Second)
        }

        expiredKeys := make([]string, 0, len(c.ips)/4) // pre-allocate

        for domain, rec := range c.ips {
                if (rec.A != nil && rec.A.Expire.Before(now)) ||
                        (rec.AAAA != nil && rec.AAAA.Expire.Before(now)) {
                        expiredKeys = append(expiredKeys, domain)
                }
        }

        return expiredKeys, nil
}

func (c *CacheController) writeAndShrink(expiredKeys []string) {
        c.Lock()
        defer c.Unlock()

        // double check to prevent upper call multiple cleanup tasks
        if c.dirtyips != nil {
                return
        }

        lenBefore := len(c.ips)
        if lenBefore > c.highWatermark {
                c.highWatermark = lenBefore
        }

        now := time.Now()
        if c.serveStale && c.serveExpiredTTL != 0 {
                now = now.Add(time.Duration(c.serveExpiredTTL) * time.Second)
        }

        for _, domain := range expiredKeys {
                rec := c.ips[domain]
                if rec == nil {
                        continue
                }
                if rec.A != nil && rec.A.Expire.Before(now) {
                        rec.A = nil
                }
                if rec.AAAA != nil && rec.AAAA.Expire.Before(now) {
                        rec.AAAA = nil
                }
                if rec.A == nil && rec.AAAA == nil {
                        delete(c.ips, domain)
                }
        }

        lenAfter := len(c.ips)

        if lenAfter == 0 {
                if c.highWatermark >= minSizeForEmptyRebuild {
                        errors.LogDebug(
                                context.Background(), c.name,
                                " rebuilding empty cache map to reclaim memory.",
                                " size_before_cleanup=", lenBefore,
                                " peak_size_before_rebuild=", c.highWatermark,
                        )

                        c.ips = make(map[string]*record)
                        c.highWatermark = 0
                }
                return
        }

        if reductionFromPeak := c.highWatermark - lenAfter; reductionFromPeak > shrinkAbsoluteThreshold &&
                float64(reductionFromPeak) > float64(c.highWatermark)*shrinkRatioThreshold {
                errors.LogDebug(
                        context.Background(), c.name,
                        " shrinking cache map to reclaim memory.",
                        " new_size=", lenAfter,
                        " peak_size_before_shrink=", c.highWatermark,
                        " reduction_since_peak=", reductionFromPeak,
                )

                c.dirtyips = c.ips
                c.ips = make(map[string]*record, int(float64(lenAfter)*1.1))
                c.highWatermark = lenAfter
                go c.migrate()
        }
}

type migrationEntry struct {
        key   string
        value *record
}

func (c *CacheController) migrate() {
        defer func() {
                if r := recover(); r != nil {
                        errors.LogError(context.Background(), c.name, " panic during cache migration: ", r)
                        c.Lock()
                        c.dirtyips = nil
                        // c.ips = make(map[string]*record)
                        // c.highWatermark = 0
                        c.Unlock()
                }
        }()

        c.RLock()
        dirtyips := c.dirtyips
        c.RUnlock()

        // double check to prevent upper call multiple cleanup tasks
        if dirtyips == nil {
                return
        }

        errors.LogDebug(context.Background(), c.name, " starting background cache migration for ", len(dirtyips), " items")

        batch := make([]migrationEntry, 0, migrationBatchSize)
        for domain, recD := range dirtyips {
                batch = append(batch, migrationEntry{domain, recD})

                if len(batch) >= migrationBatchSize {
                        c.flush(batch)
                        batch = batch[:0]
                        runtime.Gosched()
                }
        }
        if len(batch) > 0 {
                c.flush(batch)
        }

        c.Lock()
        c.dirtyips = nil
        c.Unlock()

        errors.LogDebug(context.Background(), c.name, " cache migration completed")
}

func (c *CacheController) flush(batch []migrationEntry) {
        c.Lock()
        defer c.Unlock()

        for _, dirty := range batch {
                if cur := c.ips[dirty.key]; cur != nil {
                        merge := &record{}
                        if cur.A == nil {
                                merge.A = dirty.value.A
                        } else {
                                merge.A = cur.A
                        }
                        if cur.AAAA == nil {
                                merge.AAAA = dirty.value.AAAA
                        } else {
                                merge.AAAA = cur.AAAA
                        }
                        c.ips[dirty.key] = merge
                } else {
                        c.ips[dirty.key] = dirty.value
                }
        }
}

func (c *CacheController) updateRecord(req *dnsRequest, rep *IPRecord) {
        rtt := time.Since(req.start)

        switch req.reqType {
        case dnsmessage.TypeA:
                c.pub.Publish(req.domain+"4", rep)
        case dnsmessage.TypeAAAA:
                c.pub.Publish(req.domain+"6", rep)
        }

        if c.disableCache {
                errors.LogInfo(context.Background(), c.name, " got answer: ", req.domain, " ", req.reqType, " -> ", rep.IP, ", rtt: ", rtt)
                return
        }

        c.Lock()
        lockWait := time.Since(req.start) - rtt

        newRec := &record{}
        oldRec := c.ips[req.domain]
        var dirtyRec *record
        if c.dirtyips != nil {
                dirtyRec = c.dirtyips[req.domain]
        }

        var pubRecord *IPRecord
        var pubSuffix string

        switch req.reqType {
        case dnsmessage.TypeA:
                newRec.A = rep
                if oldRec != nil && oldRec.AAAA != nil {
                        newRec.AAAA = oldRec.AAAA
                        pubRecord = oldRec.AAAA
                } else if dirtyRec != nil && dirtyRec.AAAA != nil {
                        pubRecord = dirtyRec.AAAA
                }
                pubSuffix = "6"
        case dnsmessage.TypeAAAA:
                newRec.AAAA = rep
                if oldRec != nil && oldRec.A != nil {
                        newRec.A = oldRec.A
                        pubRecord = oldRec.A
                } else if dirtyRec != nil && dirtyRec.A != nil {
                        pubRecord = dirtyRec.A
                }
                pubSuffix = "4"
        }

        c.ips[req.domain] = newRec
        c.Unlock()

        if pubRecord != nil {
                _, ttl, err := pubRecord.getIPs()
                if ttl > 0 && !go_errors.Is(err, errRecordNotFound) {
                        c.pub.Publish(req.domain+pubSuffix, pubRecord)
                }
        }

        errors.LogInfo(context.Background(), c.name, " got answer: ", req.domain, " ", req.reqType, " -> ", rep.IP, ", rtt: ", rtt, ", lock: ", lockWait)

        if !c.serveStale || c.serveExpiredTTL != 0 {
                common.Must(c.cacheCleanup.Start())
        }
        // v26.10.40-link: also kick off the prefetch worker if configured.
        // common.Must(cacheCleanup.Start) is idempotent (task.Periodic.Start
        // is a no-op if already running), and so is prefetchWorker.Start.
        if c.prefetchWorker != nil {
                common.Must(c.prefetchWorker.Start())
        }
}

func (c *CacheController) findRecords(domain string) *record {
        c.RLock()
        defer c.RUnlock()

        rec := c.ips[domain]
        if rec == nil && c.dirtyips != nil {
                rec = c.dirtyips[domain]
        }
        return rec
}

func (c *CacheController) registerSubscribers(domain string, option dns_feature.IPOption) (sub4 *pubsub.Subscriber, sub6 *pubsub.Subscriber) {
        // ipv4 and ipv6 belong to different subscription groups
        if option.IPv4Enable {
                sub4 = c.pub.Subscribe(domain + "4")
        }
        if option.IPv6Enable {
                sub6 = c.pub.Subscribe(domain + "6")
        }
        return
}

func closeSubscribers(sub4 *pubsub.Subscriber, sub6 *pubsub.Subscriber) {
        if sub4 != nil {
                sub4.Close()
        }
        if sub6 != nil {
                sub6.Close()
        }
}

// v26.10.48-link: findWildcardFallback scans the cache for any entry
// whose domain shares the same parent (wildcard) as the given domain.
// Returns the IP from the first matching entry, or nil if none found.
//
// This is used as a DNS fallback when DNS resolution fails for a new
// hostname (e.g., YouTube rotates to a new CDN edge and upstream DNS
// returns SERVFAIL). Instead of buffering the video for 30-45 seconds
// until DNS recovers, xray returns a cached IP from a sibling hostname
// (same CDN, different edge) so the video can play immediately.
//
// Example: DNS fails for rr5---sn-2oh0j5-54.googlevideo.com →
// cache has rr1---sn-ajnv4c-5a.googlevideo.com → 173.194.163.81
// → return 173.194.163.81 as the DNS answer.
//
// This is safe because:
// 1. The destination domain stays as-is in freedom.go (no modification)
// 2. The dialer dials the returned IP (same as any DNS resolution)
// 3. TLS SNI flows through the browser (xray doesn't terminate TLS)
// 4. The IP might be a different CDN edge, but YouTube's CDN serves
//    all videos from all edges — a different edge just means a
//    different server serving the same content
// 5. The stale-serve TTL (serveExpiredTTL) controls how long the
//    fallback IP is used before a fresh DNS query is attempted
func (c *CacheController) findWildcardFallback(domain string) []net.IP {
        // Extract the parent domain (everything after the first dot)
        // e.g., "rr5---sn-2oh0j5-54.googlevideo.com." → "googlevideo.com."
        // We want to find any cached entry that ends with the same
        // parent domain.
        dotIdx := strings.Index(domain, ".")
        if dotIdx < 0 || dotIdx >= len(domain)-1 {
                return nil
        }
        parent := domain[dotIdx+1:] // "googlevideo.com."

        c.RLock()
        defer c.RUnlock()

        // Scan cache for entries that share the same parent domain.
        // Return the first one that has a valid A record.
        for cachedDomain, rec := range c.ips {
                if cachedDomain == domain {
                        continue // skip self
                }
                // Check if the cached domain ends with the same parent
                // e.g., "rr1---sn-ajnv4c-5a.googlevideo.com." ends with "googlevideo.com."
                if !strings.HasSuffix(cachedDomain, parent) {
                        continue
                }
                // Found a sibling entry — return its IP
                if rec.A != nil {
                        ips, _, err := rec.A.getIPs()
                        if err == nil && len(ips) > 0 {
                                return ips
                        }
                }
        }
        // Also check dirtyips (during migration)
        if c.dirtyips != nil {
                for cachedDomain, rec := range c.dirtyips {
                        if cachedDomain == domain {
                                continue
                        }
                        if !strings.HasSuffix(cachedDomain, parent) {
                                continue
                        }
                        if rec.A != nil {
                                ips, _, err := rec.A.getIPs()
                                if err == nil && len(ips) > 0 {
                                        return ips
                                }
                        }
                }
        }
        return nil
}
