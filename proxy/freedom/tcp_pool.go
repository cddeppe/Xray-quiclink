package freedom

import (
	"context"
	"sync"
	"syscall"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// TCPSocketPool is a warm-pool for outbound TCP connections.
//
// v26.11.132: rewritten with liveness checks, multi-conn per dest,
// and corrected reaper/pre-warm TTLs.
type TCPSocketPool struct {
	mu       sync.Mutex
	warm     map[string][]*warmConn // deque per dest key
	maxIdle  int                   // max conns per dest key (default 4)
	timeout  time.Duration

	// v26.10.46-link: per-wildcard first-N learning
	patterns    map[string]*wildcardPattern
	preWarmN    int  // how many first-N to pre-warm per wildcard
	learnVisits int  // how many visits before a pattern is stable
	dialFunc    func(ctx context.Context, dest net.Destination) (stat.Connection, error)
	stopCh      chan struct{}
}

// wildcardPattern tracks the critical-path IPs for a site family.
type wildcardPattern struct {
	mu          sync.Mutex
	wildcard    string
	candidate   []string
	stable      []string
	visitCount  int
	lastVisit   time.Time
	stabilized  bool
	totalDomains  int
	uniqueIPs     map[string]bool
}

type warmConn struct {
	conn      stat.Connection
	dest      string
	expiresAt time.Time
	preWarmed bool
}

func NewTCPSocketPool(timeout time.Duration, preWarmN int, preWarmFirstN int, learnVisits int) *TCPSocketPool {
	maxIdle := 4 // default: allow 4 conns per destination
	p := &TCPSocketPool{
		warm:        make(map[string][]*warmConn),
		maxIdle:     maxIdle,
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
// v26.11.132: uses atomic check to avoid lock contention on every Process call.
func (p *TCPSocketPool) SetDialFunc(f func(ctx context.Context, dest net.Destination) (stat.Connection, error)) {
	if p == nil {
		return
	}
	p.mu.Lock()
	if p.dialFunc == nil {
		p.dialFunc = f
	}
	p.mu.Unlock()
}

// Acquire returns a warm TCP connection for the given destination.
// v26.11.132: adds liveness check via getsockopt(SO_ERROR) to detect
// connections that the remote has closed (HTTP/2 GOAWAY, idle timeout).
func (p *TCPSocketPool) Acquire(dest net.Destination) stat.Connection {
	if p == nil {
		return nil
	}
	key := tcpDestKey(dest)

	// v26.10.46-link: track for first-N learning
	if p.preWarmN > 0 {
		p.trackFirstN(dest)
	}

	for {
		p.mu.Lock()
		queue := p.warm[key]
		if len(queue) == 0 {
			p.mu.Unlock()
			return nil
		}
		// Pop from head (FIFO — oldest warm conn first)
		wc := queue[0]
		queue[0] = nil
		p.warm[key] = queue[1:]
		if len(p.warm[key]) == 0 {
			delete(p.warm, key)
		}
		p.mu.Unlock()

		// Check expiry
		if time.Now().After(wc.expiresAt) {
			wc.conn.Close()
			continue // try next conn in queue
		}

		// v26.11.132: Liveness check — detect if remote closed the conn.
		// Uses getsockopt(SOL_SOCKET, SO_ERROR) via syscall.
		if !isConnAlive(wc.conn) {
			wc.conn.Close()
			continue // try next conn in queue
		}

		return wc.conn
	}
}

// Release puts a TCP connection into the warm pool for reuse.
// v26.11.132: appends to deque instead of overwriting.
func (p *TCPSocketPool) Release(conn stat.Connection, dest net.Destination) {
	if p == nil {
		conn.Close()
		return
	}
	key := tcpDestKey(dest)
	p.mu.Lock()
	queue := p.warm[key]
	// Cap at maxIdle — if full, close the oldest
	if len(queue) >= p.maxIdle {
		if len(queue) > 0 {
			queue[0].conn.Close()
			queue[0] = nil
			queue = queue[1:]
		}
	}
	queue = append(queue, &warmConn{
		conn:      conn,
		dest:      key,
		expiresAt: time.Now().Add(p.timeout),
	})
	p.warm[key] = queue
	p.mu.Unlock()
}

// isConnAlive checks if a TCP connection is still alive using getsockopt.
// Returns false if the remote has closed the connection or an error occurred.
func isConnAlive(conn stat.Connection) bool {
	// Try to get the underlying *net.TCPConn
	type syscallConn interface {
		SyscallConn() (syscall.RawConn, error)
	}

	// Unwrap stat.CounterConnection if present
	rawConn := conn
	if sc, ok := rawConn.(interface{ Connection() stat.Connection }); ok {
		rawConn = sc.Connection()
	}

	sc, ok := rawConn.(syscallConn)
	if !ok {
		// Can't check — assume alive (better than dropping a good conn)
		return true
	}

	rawFd, err := sc.SyscallConn()
	if err != nil {
		return true // can't check — assume alive
	}

	alive := false
	err = rawFd.Control(func(fd uintptr) {
		// getsockopt(SOL_SOCKET, SO_ERROR)
		val, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_ERROR)
		if err == nil && val == 0 {
			alive = true
		}
	})
	if err != nil {
		return true // can't check — assume alive
	}
	return alive
}

// trackFirstN records a new destination's first-N order for its wildcard
// group. Called on every TCP connection (new or warm-pool reuse).
func (p *TCPSocketPool) trackFirstN(dest net.Destination) {
	if p == nil || p.preWarmN == 0 {
		return
	}
	key := tcpDestKey(dest)

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.patterns["__global__"] == nil {
		p.patterns["__global__"] = &wildcardPattern{
			wildcard:  "__global__",
			lastVisit: time.Now(),
			uniqueIPs: make(map[string]bool),
		}
	}
	wp := p.patterns["__global__"]
	wp.mu.Lock()
	defer wp.mu.Unlock()

	now := time.Now()
	if now.Sub(wp.lastVisit) > 10*time.Second {
		if len(wp.candidate) > 0 {
			wp.visitCount++
			if wp.visitCount >= p.learnVisits {
				if !wp.stabilized {
					if len(wp.stable) == 0 {
						wp.stable = append([]string{}, wp.candidate...)
						wp.stabilized = true
						dupCount := wp.totalDomains - len(wp.stable)
						if dupCount < 0 {
							dupCount = 0
						}
						errors.LogInfo(context.Background(), "tcp warm pool: first-N pattern stabilized after ", wp.visitCount, " visits, ", len(wp.stable), " critical-path IPs (from ", wp.totalDomains, " domains — ", dupCount, " shared IPs)")
					} else if stringSlicesMatch(wp.stable, wp.candidate) {
						// Already stable, still matches — good
					} else {
						wp.stable = append([]string{}, wp.candidate...)
						errors.LogInfo(context.Background(), "tcp warm pool: first-N pattern updated (CDN migration?) — ", len(wp.stable), " critical-path IPs")
					}
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
	wp.uniqueIPs[key] = true
	wp.lastVisit = now
}

// preWarmLoop periodically pre-establishes TCP connections.
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
	stable := append([]string{}, wp.stable...)
	wp.mu.Unlock()
	p.mu.Unlock()

	if len(stable) == 0 {
		return
	}

	var wg sync.WaitGroup
	for _, key := range stable {
		p.mu.Lock()
		queue := p.warm[key]
		p.mu.Unlock()
		// v26.11.132: skip if we already have maxIdle conns for this dest
		if len(queue) >= p.maxIdle {
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
			// v26.11.132: use p.timeout (not *12) for pre-warmed conns too
			p.warm[k] = append(p.warm[k], &warmConn{
				conn:      conn,
				dest:      k,
				expiresAt: time.Now().Add(p.timeout),
				preWarmed: true,
			})
			p.mu.Unlock()
			errors.LogInfo(context.Background(), "tcp warm pool: pre-warmed connection to ", k)
		}(*dest, key)
	}
	wg.Wait()
}

// reaper periodically closes expired warm connections.
// v26.11.132: runs every timeout/4 (min 5s) instead of every timeout.
func (p *TCPSocketPool) reaper() {
	interval := p.timeout / 4
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	t := time.NewTicker(interval)
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
	for key, queue := range p.warm {
		kept := queue[:0]
		for _, wc := range queue {
			if now.After(wc.expiresAt) {
				wc.conn.Close()
			} else {
				kept = append(kept, wc)
			}
		}
		if len(kept) == 0 {
			delete(p.warm, key)
		} else {
			p.warm[key] = kept
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
	for _, queue := range p.warm {
		for _, wc := range queue {
			wc.conn.Close()
		}
	}
	p.warm = make(map[string][]*warmConn)
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
