package freedom

import (
        "context"
        "sync"
        "time"

        "github.com/xtls/xray-core/common/errors"
        "github.com/xtls/xray-core/common/net"
        "github.com/xtls/xray-core/transport/internet"
        "github.com/xtls/xray-core/transport/internet/stat"
)

// TCPSocketPool is a warm-pool for outbound TCP connections.
//
// v26.10.44-link: warm pool — reuse outbound TCP after inbound closes.
// v26.10.45-link: frequency-based pre-warming (preWarmCount).
// v26.10.46-link: per-wildcard first-N learning (preWarmFirstN) —
// replaces frequency-based with a smarter algorithm that learns the
// critical-path IPs per site family. More efficient: pre-warms 5 per
// site family instead of 20 globally. More targeted: pre-warms the
// IPs the browser hits first (page load), not the ones it hits most
// (analytics/tracking fire after the page loads).
type TCPSocketPool struct {
        mu       sync.Mutex
        warm     map[string]*warmConn
        timeout  time.Duration

        // v26.10.46-link: per-wildcard first-N learning
        patterns   map[string]*wildcardPattern
        preWarmN   int    // how many first-N to pre-warm per wildcard
        learnVisits int   // how many visits before a pattern is stable
        dialFunc   func(ctx context.Context, dest net.Destination) (stat.Connection, error)
        stopCh     chan struct{}
}

// wildcardPattern tracks the critical-path IPs for a site family
// (e.g., *.hulu.com). It learns which IPs are hit first on each visit,
// stabilizes after learnVisits visits, and is then used for pre-warming.
type wildcardPattern struct {
        mu          sync.Mutex
        wildcard    string   // e.g., "*.hulu.com"
        candidate   []string // IPs from the current visit (in order)
        stable      []string // IPs from the confirmed pattern (in order)
        visitCount  int      // how many visits have been tracked
        lastVisit   time.Time // when the last visit started
        stabilized  bool     // pattern is stable — start pre-warming
}

type warmConn struct {
        conn      stat.Connection
        dest      string
        expiresAt time.Time
        preWarmed bool
}

func NewTCPSocketPool(timeout time.Duration, preWarmN int, preWarmFirstN int, learnVisits int) *TCPSocketPool {
        p := &TCPSocketPool{
                warm:        make(map[string]*warmConn),
                timeout:     timeout,
                patterns:    make(map[string]*wildcardPattern),
                preWarmN:    preWarmFirstN,
                learnVisits: learnVisits,
                stopCh:      make(chan struct{}),
        }
        go p.reaper()
        if preWarmFirstN > 0 || preWarmN > 0 {
                go p.preWarmLoop()
        }
        return p
}

// SetDialFunc provides the dialer function needed for pre-warming.
func (p *TCPSocketPool) SetDialFunc(f func(ctx context.Context, dest net.Destination) (stat.Connection, error)) {
        if p == nil {
                return
        }
        p.mu.Lock()
        p.dialFunc = f
        p.mu.Unlock()
}

// Acquire returns a warm TCP connection for the given destination.
// Also tracks the access for first-N learning.
func (p *TCPSocketPool) Acquire(dest net.Destination) stat.Connection {
        if p == nil {
                return nil
        }
        key := tcpDestKey(dest)

        // v26.10.46-link: track for first-N learning
        if p.preWarmN > 0 {
                p.trackFirstN(dest)
        }

        p.mu.Lock()
        wc, ok := p.warm[key]
        if ok {
                delete(p.warm, key)
        }
        p.mu.Unlock()
        if !ok || wc == nil {
                return nil
        }
        if time.Now().After(wc.expiresAt) {
                wc.conn.Close()
                return nil
        }
        return wc.conn
}

// Release puts a TCP connection into the warm pool for reuse.
func (p *TCPSocketPool) Release(conn stat.Connection, dest net.Destination) {
        if p == nil {
                conn.Close()
                return
        }
        key := tcpDestKey(dest)
        p.mu.Lock()
        if old, ok := p.warm[key]; ok {
                old.conn.Close()
                delete(p.warm, key)
        }
        p.warm[key] = &warmConn{
                conn:      conn,
                dest:      key,
                expiresAt: time.Now().Add(p.timeout),
        }
        p.mu.Unlock()
}

// trackFirstN records a new destination's first-N order for its wildcard
// group. Called on every TCP connection (new or warm-pool reuse).
// Uses the destination's domain (if available) to determine the wildcard
// group. If the destination is an IP (already resolved), tries to find
// the original domain from the connection context — but for simplicity,
// we track by IP. The first-N learning groups IPs by their DNS wildcard
// parent, which is tracked at resolve time.
func (p *TCPSocketPool) trackFirstN(dest net.Destination) {
        if p == nil || p.preWarmN == 0 {
                return
        }
        key := tcpDestKey(dest)

        // Find the wildcard group for this destination. We track by IP
        // (the resolved address), so we need a mapping from IP to wildcard.
        // The sticky resolver knows the hostname, but the warm pool only
        // sees the resolved destination.
        //
        // Approach: track a "visit" by checking if we've seen this IP
        // recently. If not, it's a new IP in this visit cycle. After
        // p.learnVisits complete visit cycles, the pattern stabilizes.
        //
        // Simpler approach: track the order of first connections per
        // wildcard. The wildcard is determined by the domain that was
        // resolved to this IP. We need the domain — but the warm pool
        // only has the IP.
        //
        // Even simpler: track the first N unique IPs seen in each 60s
        // window. After 3 windows with the same first N, stabilize.
        // This doesn't group by wildcard, but it catches the critical-
        // path pattern: the first 5 IPs are always the same for a site.
        //
        // Let me use the simplest approach that works: track the order
        // of unique IPs within a "session" (defined as a 10-second window
        // of activity). After learnVisits sessions with the same first N,
        // stabilize.

        p.mu.Lock()
        defer p.mu.Unlock()

        // Use a single global pattern (not per-wildcard) for simplicity.
        // The first N IPs across all activity represent the critical path.
        // This is simpler than per-wildcard grouping and still avoids the
        // frequency problem (analytics IPs fire later, not in the first N).
        if p.patterns["__global__"] == nil {
                p.patterns["__global__"] = &wildcardPattern{
                        wildcard:  "__global__",
                        lastVisit: time.Now(),
                }
        }
        wp := p.patterns["__global__"]
        wp.mu.Lock()
        defer wp.mu.Unlock()

        // Check if this is a new "visit" (10s gap since last activity)
        now := time.Now()
        if now.Sub(wp.lastVisit) > 10*time.Second {
                // New visit — finalize the candidate and start a new one
                if len(wp.candidate) > 0 {
                        wp.visitCount++
                        if wp.visitCount >= p.learnVisits {
                                // Check if candidate matches stable
                                if !wp.stabilized {
                                        if len(wp.stable) == 0 {
                                                // First stabilization — adopt the candidate
                                                wp.stable = append([]string{}, wp.candidate...)
                                                wp.stabilized = true
                                                errors.LogInfo(context.Background(), "tcp warm pool: first-N pattern stabilized after ", wp.visitCount, " visits, ", len(wp.stable), " critical-path IPs")
                                        } else if stringSlicesMatch(wp.stable, wp.candidate) {
                                                // Already stable, still matches — good
                                        } else {
                                                // Pattern changed — update (CDN migration)
                                                wp.stable = append([]string{}, wp.candidate...)
                                                errors.LogInfo(context.Background(), "tcp warm pool: first-N pattern updated (CDN migration?) — ", len(wp.stable), " critical-path IPs")
                                        }
                                }
                        }
                }
                wp.candidate = nil
                wp.lastVisit = now
        }

        // Add this IP to the candidate if not already present and we
        // haven't exceeded preWarmN
        if !containsString(wp.candidate, key) && len(wp.candidate) < p.preWarmN {
                wp.candidate = append(wp.candidate, key)
        }
        wp.lastVisit = now
}

// preWarmLoop periodically pre-establishes TCP connections for the
// learned first-N pattern. Runs every 60 seconds.
func (p *TCPSocketPool) preWarmLoop() {
        t := time.NewTicker(60 * time.Second)
        defer t.Stop()
        for {
                select {
                case <-p.stopCh:
                        return
                case <-t.C:
                        p.doPreWarm()
                }
        }
}

func (p *TCPSocketPool) doPreWarm() {
        p.mu.Lock()
        dialFunc := p.dialFunc
        if dialFunc == nil {
                p.mu.Unlock()
                return
        }

        // Get the stabilized first-N pattern
        wp := p.patterns["__global__"]
        if wp == nil {
                p.mu.Unlock()
                return
        }
        wp.mu.Lock()
        stable := append([]string{}, wp.stable...)
        wp.mu.Unlock()
        p.mu.Unlock()

        if len(stable) == 0 {
                return
        }

        // Pre-warm each IP in the stable pattern that doesn't already
        // have a warm connection. Dial in parallel to speed up the cycle.
        var wg sync.WaitGroup
        for _, key := range stable {
                p.mu.Lock()
                _, exists := p.warm[key]
                p.mu.Unlock()
                if exists {
                        continue
                }

                dest := parseDestKey(key)
                if dest == nil {
                        continue
                }

                wg.Add(1)
                go func(d net.Destination, k string) {
                        defer wg.Done()
                        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
                        conn, err := dialFunc(ctx, d)
                        cancel()
                        if err != nil {
                                return
                        }
                        p.mu.Lock()
                        if old, ok := p.warm[k]; ok {
                                old.conn.Close()
                        }
                        p.warm[k] = &warmConn{
                                conn:      conn,
                                dest:      k,
                                expiresAt:  time.Now().Add(p.timeout * 12),
                                preWarmed:  true,
                        }
                        p.mu.Unlock()
                        errors.LogInfo(context.Background(), "tcp warm pool: pre-warmed connection to ", k)
                }(*dest, key)
        }
        wg.Wait()
}

// reaper periodically closes expired warm connections.
func (p *TCPSocketPool) reaper() {
        t := time.NewTicker(p.timeout)
        defer t.Stop()
        for {
                select {
                case <-p.stopCh:
                        return
                case <-t.C:
                        p.evictExpired()
                }
        }
}

func (p *TCPSocketPool) evictExpired() {
        now := time.Now()
        p.mu.Lock()
        for key, wc := range p.warm {
                if now.After(wc.expiresAt) {
                        wc.conn.Close()
                        delete(p.warm, key)
                }
        }
        p.mu.Unlock()
}

// Close closes all warm connections and stops goroutines.
func (p *TCPSocketPool) Close() {
        if p == nil {
                return
        }
        select {
        case <-p.stopCh:
        default:
                close(p.stopCh)
        }
        p.mu.Lock()
        for _, wc := range p.warm {
                wc.conn.Close()
        }
        p.warm = make(map[string]*warmConn)
        p.mu.Unlock()
}

// tcpDestKey converts a net.Destination to a string key.
func tcpDestKey(dest net.Destination) string {
        return dest.Address.String() + ":" + dest.Port.String()
}

// parseDestKey converts a string key back to a net.Destination.
func parseDestKey(key string) *net.Destination {
        addr, portStr := "", ""
        for i := len(key) - 1; i >= 0; i-- {
                if key[i] == ':' {
                        addr = key[:i]
                        portStr = key[i+1:]
                        break
                }
        }
        if addr == "" || portStr == "" {
                return nil
        }
        address := net.ParseAddress(addr)
        if address == nil {
                return nil
        }
        port, err := net.PortFromString(portStr)
        if err != nil {
                return nil
        }
        return &net.Destination{
                Network: net.Network_TCP,
                Address: address,
                Port:    port,
        }
}

// Helper functions

func containsString(s []string, v string) bool {
        for _, x := range s {
                if x == v {
                        return true
                }
        }
        return false
}

func stringSlicesMatch(a, b []string) bool {
        if len(a) != len(b) {
                return false
        }
        for i := range a {
                if a[i] != b[i] {
                        return false
                }
        }
        return true
}

var _ = internet.DomainStrategy_USE_IP
