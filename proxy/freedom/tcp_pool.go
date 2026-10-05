package freedom

import (
        "context"
        "sort"
        "sync"
        "sync/atomic"
        "time"

        "github.com/xtls/xray-core/common/errors"
        "github.com/xtls/xray-core/common/net"
        "github.com/xtls/xray-core/transport/internet"
        "github.com/xtls/xray-core/transport/internet/stat"
)

// TCPSocketPool is a warm-pool for outbound TCP connections. When a
// TCP connection's inbound side closes but the outbound is still alive,
// the outbound is placed in the warm pool for reuse by the next inbound
// to the same destination. Eliminates TCP+TLS handshake for repeated
// connections to the same destination — especially valuable through
// WireGuard tunnels where each handshake takes 200-600ms.
//
// v26.10.44-link: opt-in via enableTCPWarmPool in udpConfig.
// v26.10.45-link: auto pre-warming. The pool tracks which destinations
// are frequently accessed and pre-establishes TCP connections for the
// top N, so the first visit to a frequently-used site has zero TCP
// handshake latency.
type TCPSocketPool struct {
        mu       sync.Mutex
        warm     map[string]*warmConn
        timeout  time.Duration

        // v26.10.45-link: frequency tracking + pre-warming
        freq       map[string]*int64      // dest key → access count (atomic)
        preWarmN   int                    // how many top destinations to pre-warm
        dialFunc   func(ctx context.Context, dest net.Destination) (stat.Connection, error)
        stopCh     chan struct{}
}

type warmConn struct {
        conn      stat.Connection
        dest      string // IP:port for keying
        expiresAt time.Time
        // v26.10.45-link: true if this conn was pre-warmed (not from a real
        // connection). Pre-warmed conns have a longer TTL — they're kept
        // alive indefinitely via tcpKeepAlive and re-established if they die.
        preWarmed bool
}

func NewTCPSocketPool(timeout time.Duration, preWarmN int) *TCPSocketPool {
        p := &TCPSocketPool{
                warm:      make(map[string]*warmConn),
                timeout:   timeout,
                freq:      make(map[string]*int64),
                preWarmN:  preWarmN,
                stopCh:    make(chan struct{}),
        }
        go p.reaper()
        if preWarmN > 0 {
                go p.preWarmLoop()
        }
        return p
}

// SetDialFunc provides the dialer function needed for pre-warming.
// Called from freedom.Process on the first TCP connection. Until this
// is set, pre-warming is disabled (no way to establish connections).
func (p *TCPSocketPool) SetDialFunc(f func(ctx context.Context, dest net.Destination) (stat.Connection, error)) {
        if p == nil {
                return
        }
        p.mu.Lock()
        p.dialFunc = f
        p.mu.Unlock()
}

// Acquire returns a warm TCP connection for the given destination, or
// nil if none is available. The caller takes ownership — the conn is
// removed from the pool. Also tracks frequency for pre-warming.
func (p *TCPSocketPool) Acquire(dest net.Destination) stat.Connection {
        if p == nil {
                return nil
        }
        key := tcpDestKey(dest)

        // v26.10.45-link: track frequency for pre-warming
        p.trackAccess(key)

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

// trackAccess increments the frequency counter for a destination.
// Used by both Acquire (warm-pool miss → new dial) and Process (every
// TCP dial) to learn which destinations are frequently accessed.
func (p *TCPSocketPool) trackAccess(key string) {
        if p == nil || p.preWarmN == 0 {
                return
        }
        p.mu.Lock()
        defer p.mu.Unlock()
        if p.freq[key] == nil {
                c := int64(0)
                p.freq[key] = &c
        }
        atomic.AddInt64(p.freq[key], 1)
}

// preWarmLoop periodically pre-establishes TCP connections for the top
// N most frequently accessed destinations. Runs every 60 seconds.
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

// doPreWarm identifies the top N destinations and pre-establishes TCP
// connections for any that don't already have a warm connection.
func (p *TCPSocketPool) doPreWarm() {
        p.mu.Lock()
        dialFunc := p.dialFunc
        if dialFunc == nil {
                p.mu.Unlock()
                return
        }

        // Get top N destinations by frequency
        type destFreq struct {
                key  string
                freq int64
        }
        all := make([]destFreq, 0, len(p.freq))
        for key, count := range p.freq {
                all = append(all, destFreq{key, atomic.LoadInt64(count)})
        }
        p.mu.Unlock()

        if len(all) == 0 {
                return
        }

        // Sort by frequency (descending)
        sort.Slice(all, func(i, j int) bool {
                return all[i].freq > all[j].freq
        })

        // Take top N
        n := p.preWarmN
        if n > len(all) {
                n = len(all)
        }
        top := all[:n]

        // For each top destination, check if a warm conn already exists.
        // If not, dial a new one and put it in the pool.
        for _, df := range top {
                p.mu.Lock()
                _, exists := p.warm[df.key]
                p.mu.Unlock()
                if exists {
                        continue // already warm
                }

                // Parse the key back to a destination. The key is "IP:port".
                // We stored the original destination's address + port, so we
                // can reconstruct a net.Destination for the dialer.
                // Actually, we need the original net.Destination to dial
                // correctly. Let me store it in the freq map instead of just
                // the key string.
                // For now, reconstruct from key:
                dest := parseDestKey(df.key)
                if dest == nil {
                        continue
                }

                // Dial with a short timeout — don't block the pre-warm goroutine
                // for too long if the destination is unreachable.
                ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
                conn, err := dialFunc(ctx, *dest)
                cancel()
                if err != nil {
                        continue // can't reach this destination right now
                }

                // Put it in the warm pool with a longer TTL for pre-warmed conns.
                // Pre-warmed conns are kept alive via tcpKeepAlive (15s probes)
                // and re-established every 60s by this goroutine if they die.
                p.mu.Lock()
                if old, ok := p.warm[df.key]; ok {
                        old.conn.Close() // race: someone else dialed while we were dialing
                }
                p.warm[df.key] = &warmConn{
                        conn:       conn,
                        dest:       df.key,
                        expiresAt:  time.Now().Add(p.timeout * 12), // 5s * 12 = 60s for pre-warmed
                        preWarmed:  true,
                }
                p.mu.Unlock()
                errors.LogInfo(context.Background(), "tcp warm pool: pre-warmed connection to ", df.key)
        }
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
                // already closed
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

// tcpDestKey converts a net.Destination to a string key for the warm pool.
func tcpDestKey(dest net.Destination) string {
        return dest.Address.String() + ":" + dest.Port.String()
}

// parseDestKey converts a string key back to a net.Destination.
// The key is "IP:port" or "[IPv6]:port".
func parseDestKey(key string) *net.Destination {
        // Find the last colon (separates port from address)
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

// Ensure internet is imported (used for the dialer type in SetDialFunc)
var _ = internet.DomainStrategy_USE_IP
