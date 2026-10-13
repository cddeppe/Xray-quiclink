package freedom

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// TCPSocketPool keeps pre-dialled ("warm") outbound TCP connections for
// destinations that are likely to be requested by the next session, so that
// the next session can skip the TCP handshake and start writing immediately.
//
// # The invariant that makes this safe
//
// A warm connection may only be handed to a caller if NOTHING has ever been
// written to it. A TCP connection is owned by the session that created it: as
// soon as a client has sent a ClientHello (or an HTTP request, or a proxy
// session) over it, the peer's state belongs to that client and to nobody
// else. Writing a second client's first bytes into such a connection splices
// two sessions together. At best the peer resets the connection; at worst the
// bytes are delivered into the first client's session.
//
// Hence:
//
//   - doPreWarm dials connections and parks them pristine.
//   - Acquire liveness-probes a pristine connection and removes it, so a
//     given connection is only ever handed out once.
//   - Release never parks a connection. A connection that has carried a
//     session is closed. It exists so that callers have one explicit place to
//     say "this socket is finished".
//
// # Why Release works this way (v26.13.5-link)
//
// Previously Release stored the session-carrying socket back into the pool,
// keyed only by destination address, and Acquire handed it to the next request
// for that address. The sticky resolver maps many hostnames onto a single IP,
// so that key collides constantly: the second and later requests to an address
// inherited a socket whose peer had already completed a TLS session with a
// different hostname. Acquire returned non-nil, so Process skipped its dial
// and had no way to fall back, and the request simply failed.
//
// The observed symptom was that the first request after a pre-warm succeeded
// and most subsequent requests to the same address failed, which presented as
// "browsing does not work at all". Removing the reuse path is the fix; the
// pre-warm path (the part that actually skips the handshake) is kept.
type TCPSocketPool struct {
	mu      sync.Mutex
	warm    map[string]*warmConn
	timeout time.Duration

	// First-N learning: which destinations are worth pre-dialling.
	// See trackFirstN.
	patterns    map[string]*wildcardPattern
	preWarmN    int // how many first-N destinations to learn and pre-warm
	learnVisits int // how many visits before a pattern is considered stable

	dialFunc func(ctx context.Context, dest xnet.Destination) (stat.Connection, error)
	stopCh   chan struct{}

	// v26.11.2-link: callback to notify the sticky resolver when a
	// warm TCP connection is found dead or expired. The resolver
	// proactively refreshes DNS for the destination's hostname so the
	// next dial gets a fresh IP without waiting for the TTL.
	// The callback receives the destination key (ip:port string).
	onSocketStale func(destKey string)
}

// visitGap is the idle period that ends one "visit" and begins the next.
// First-N candidates are collected per visit.
const visitGap = 10 * time.Second

// wildcardPattern tracks the destinations that are hit early in a visit, which
// are the ones worth pre-dialling. Analytics and tracking hosts fire after the
// page has rendered, so they do not appear in the first N.
type wildcardPattern struct {
	mu         sync.Mutex
	wildcard   string
	candidate  []string
	stable     []string
	visitCount int
	lastVisit  time.Time
	stabilized bool

	// totalDomains counts connections before deduplication, so the
	// stabilisation log can show how many connections mapped onto the
	// learned set of unique destinations.
	totalDomains int
}

type warmConn struct {
	conn      stat.Connection
	dest      string
	expiresAt time.Time
	// pristine is true only for a connection this pool dialled itself and
	// that nothing has been written to. It is the gate in Acquire; a
	// connection without it is never handed out.
	pristine bool
}

// NewTCPSocketPool creates a pool. preWarmN is a fallback for preWarmFirstN:
// if preWarmFirstN is not positive, preWarmN is used instead.
func NewTCPSocketPool(timeout time.Duration, preWarmN int, preWarmFirstN int, learnVisits int) *TCPSocketPool {
	if preWarmFirstN <= 0 {
		preWarmFirstN = preWarmN
	}
	if learnVisits <= 0 {
		learnVisits = 1
	}
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	p := &TCPSocketPool{
		warm:        make(map[string]*warmConn),
		timeout:     timeout,
		patterns:    make(map[string]*wildcardPattern),
		preWarmN:    preWarmFirstN,
		learnVisits: learnVisits,
		stopCh:      make(chan struct{}),
	}
	go p.reaper()
	if p.preWarmN > 0 {
		go p.preWarmLoop()
	}
	return p
}

// SetDialFunc provides the dialer used by pre-warming.
func (p *TCPSocketPool) SetDialFunc(f func(ctx context.Context, dest xnet.Destination) (stat.Connection, error)) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.dialFunc = f
	p.mu.Unlock()
}

// isConnAlive reports whether a pooled TCP connection is still usable.
//
// It sets a read deadline in the past and reads one byte:
//
//   - n > 0: the peer sent data nobody has read. Not a pristine connection,
//     so it must not be handed out. The byte read here is discarded along
//     with the connection, which is why this is only ever called on a
//     connection the caller is about to throw away.
//   - io.EOF: the peer half-closed. Dead for our purposes.
//   - a timeout: the socket was idle with nothing to read, which is exactly
//     what a healthy warm connection looks like.
//   - anything else: the socket is dead.
//
// The deadline is always reset before returning so the next reader is not
// poisoned.
//
// Note this can only detect a failure that has already been delivered to the
// socket (FIN or RST). A connection killed by a NAT timeout whose FIN has not
// arrived yet looks healthy here, so a pre-warmed connection should still be
// treated as speculative by the caller: if the first write fails, dial again.
func isConnAlive(conn net.Conn) bool {
	if conn == nil {
		return false
	}
	// Unwrap stat.CounterConnection if present: the socket underneath is
	// what we want to poke.
	if sc, ok := conn.(*stat.CounterConnection); ok && sc != nil && sc.Connection != nil {
		conn = sc.Connection
	}
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		// Not a plain TCP socket (wrapped, TLS, websocket). We cannot probe
		// it cheaply without consuming stream data, so report it as alive
		// and let the first write surface any problem.
		return true
	}
	if err := tcpConn.SetReadDeadline(time.Now()); err != nil {
		// Setting a deadline on a closed descriptor fails: conn is dead.
		return false
	}
	defer func() {
		_ = tcpConn.SetReadDeadline(time.Time{})
	}()

	oneByte := make([]byte, 1)
	n, err := tcpConn.Read(oneByte)
	if n > 0 {
		return false
	}
	if err == nil {
		// A blocking read with an expired deadline should not return
		// (0, nil); treat it as healthy.
		return true
	}
	if err == io.EOF {
		return false
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	return false
}

// Acquire returns a warm, still-pristine connection for the given
// destination, or nil if the pool has nothing usable. A nil return means the
// caller must dial.
//
// v26.11.2-link: dead-conn detection. When a warm connection is found
// but is closed (RemoteAddr is nil or the conn is already closed), we
// notify the onSocketStale callback so the sticky resolver can
// proactively refresh DNS for the stale IP. This catches CDN edge
// rotation on the TCP side — without this, the resolver keeps
// returning the old IP for up to TTL seconds and the phone retries
// into a black hole.
func (p *TCPSocketPool) Acquire(dest xnet.Destination) stat.Connection {
	if p == nil {
		return nil
	}
	key := tcpDestKey(dest)

	// Learn from every acquisition, hit or miss.
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

	// The invariant: only a connection nothing has ever been written to may
	// be handed out. Anything else is closed rather than reused. This is what
	// stops a new session from writing its ClientHello into a peer's
	// established TLS session.
	if !wc.pristine {
		wc.conn.Close()
		if p.onSocketStale != nil {
			go p.onSocketStale(key)
		}
		return nil
	}
	if time.Now().After(wc.expiresAt) {
		// v26.11.2-link: warm conn expired — notify stale callback.
		// The IP may have rotated while the conn sat in the pool.
		wc.conn.Close()
		if p.onSocketStale != nil {
			go p.onSocketStale(key)
		}
		return nil
	}
	// v26.11.2-link: detect dead connections. A warm conn whose
	// RemoteAddr is nil has been closed by the remote (RST/FIN) or
	// by the kernel. Don't return it to the caller — it would fail
	// immediately. Notify the stale callback so the resolver refreshes.
	if wc.conn.RemoteAddr() == nil {
		wc.conn.Close()
		if p.onSocketStale != nil {
			go p.onSocketStale(key)
		}
		return nil
	}
	if !isConnAlive(wc.conn) {
		wc.conn.Close()
		if p.onSocketStale != nil {
			go p.onSocketStale(key)
		}
		return nil
	}
	return wc.conn
}

// Release is called when a connection obtained from this pool is no longer
// needed. It deliberately does NOT park the connection for reuse: a connection
// that has carried a session belongs to that session and cannot be given to
// another one. It is closed here so callers cannot leak it by accident.
func (p *TCPSocketPool) Release(conn stat.Connection, dest xnet.Destination) {
	if conn == nil {
		return
	}
	conn.Close()
}

// trackFirstN records the order in which destinations are first seen within a
// visit. The first N of a visit are the critical path for a page load; hosts
// contacted later (analytics, tracking) are not, which is why the first N is a
// better pre-warm set than the most frequently seen destinations.
//
// A visit ends after visitGap of inactivity. When a visit ends, its candidate
// set is compared against the learned set: the first time it becomes the
// learned set, and afterwards it replaces it when it changes (a CDN edge
// rotation).
func (p *TCPSocketPool) trackFirstN(dest xnet.Destination) {
	if p == nil || p.preWarmN <= 0 {
		return
	}
	key := tcpDestKey(dest)

	p.mu.Lock()
	defer p.mu.Unlock()

	// A single global pattern is used rather than one per wildcard: the
	// pool only sees resolved addresses, so it has no hostname to group by.
	if p.patterns["__global__"] == nil {
		p.patterns["__global__"] = &wildcardPattern{
			wildcard:  "__global__",
			lastVisit: time.Now(),
		}
	}
	wp := p.patterns["__global__"]
	wp.mu.Lock()
	defer wp.mu.Unlock()

	now := time.Now()
	if now.Sub(wp.lastVisit) > visitGap {
		// This acquisition starts a new visit: close out the previous one.
		if len(wp.candidate) > 0 {
			wp.visitCount++
			if wp.visitCount >= p.learnVisits {
				switch {
				case len(wp.stable) == 0:
					wp.stable = append([]string(nil), wp.candidate...)
					wp.stabilized = true
					shared := wp.totalDomains - len(wp.stable)
					if shared < 0 {
						shared = 0
					}
					errors.LogInfo(context.Background(), "tcp warm pool: first-N pattern learned after ", wp.visitCount, " visits, ", len(wp.stable), " destinations (from ", wp.totalDomains, " acquisitions, ", shared, " repeats)")
				case stringSlicesMatch(wp.stable, wp.candidate):
					// Unchanged: nothing to do.
				default:
					// The critical path moved (CDN edge rotation). Adopt the
					// new set so pre-warming follows the live edges instead of
					// dialling addresses that no longer serve.
					wp.stable = append([]string(nil), wp.candidate...)
					errors.LogInfo(context.Background(), "tcp warm pool: first-N pattern updated, ", len(wp.stable), " destinations (from ", wp.totalDomains, " acquisitions)")
				}
			}
		}
		wp.candidate = nil
		wp.lastVisit = now
	}

	if !containsString(wp.candidate, key) && len(wp.candidate) < p.preWarmN {
		wp.candidate = append(wp.candidate, key)
	}
	wp.totalDomains++
	wp.lastVisit = now
}

// preWarmLoop periodically pre-dials the learned destinations.
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
	wp := p.patterns["__global__"]
	if wp == nil {
		p.mu.Unlock()
		return
	}
	wp.mu.Lock()
	stable := append([]string(nil), wp.stable...)
	wp.mu.Unlock()
	p.mu.Unlock()

	if len(stable) == 0 {
		return
	}

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
		go func(d xnet.Destination, k string) {
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
				expiresAt: time.Now().Add(p.timeout),
				pristine:  true,
			}
			p.mu.Unlock()
		}(*dest, key)
	}
	wg.Wait()
}

// reaper periodically closes warm connections that outlived their timeout.
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

// Close closes all warm connections and stops the pool's goroutines.
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

// tcpDestKey converts a destination to a pool key. The network type is part of
// the key so that a TCP and a UDP destination to the same host and port cannot
// collide (the pool is TCP-only today, but the key should not depend on that).
//
// Format: "<network>:<address>:<port>", for example "tcp:1.2.3.4:443",
// "tcp:[::1]:443" or "tcp:example.com:443".
func tcpDestKey(dest xnet.Destination) string {
	return dest.Network.String() + ":" + dest.Address.String() + ":" + dest.Port.String()
}

// parseDestKey converts a pool key back to a destination. Inverse of
// tcpDestKey: the first colon separates the network token, and the last colon
// in the remainder separates the port, which works for bracketed IPv6 because
// the brackets absorb the internal colons.
func parseDestKey(key string) *xnet.Destination {
	firstColon := strings.Index(key, ":")
	if firstColon <= 0 {
		return nil
	}
	networkStr := key[:firstColon]
	rest := key[firstColon+1:]

	lastColon := strings.LastIndex(rest, ":")
	if lastColon <= 0 {
		return nil
	}
	addr := rest[:lastColon]
	portStr := rest[lastColon+1:]
	if addr == "" || portStr == "" {
		return nil
	}
	address := xnet.ParseAddress(addr)
	if address == nil {
		return nil
	}
	port, err := xnet.PortFromString(portStr)
	if err != nil {
		return nil
	}
	network := xnet.Network_TCP
	if n, ok := xnet.Network_value[networkStr]; ok {
		network = xnet.Network(n)
	}
	return &xnet.Destination{
		Network: network,
		Address: address,
		Port:    port,
	}
}

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
