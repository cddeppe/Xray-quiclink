package freedom

import (
        "context"
        "errors"
        "io"
        stdnet "net"
        "strconv"
        "strings"
        "sync"
        "sync/atomic"
        "syscall"
        "time"

        "github.com/xtls/xray-core/common/buf"
        xrayerrors "github.com/xtls/xray-core/common/errors"
        xraynet "github.com/xtls/xray-core/common/net"
        "github.com/xtls/xray-core/common/protocol/quic"
        "github.com/xtls/xray-core/features/stats"
        "github.com/xtls/xray-core/transport/internet"
)

// UDPSocketPool pools UDP sockets by destination IP:port so that many
// inbound QUIC sessions going to the same destination share one outbound
// UDP socket. Reply packets are demuxed by parsing the QUIC DCID.
type UDPSocketPool struct {
        mu               sync.Mutex
        sockets          map[string]*pooledSocket
        reaper           *time.Ticker
        stalenessTimeout time.Duration
        idleTimeout      time.Duration
        unusedTimeout    time.Duration
        // v26.10.17-link: sockopt config for interface binding (SO_BINDTODEVICE)
        // and fwmark (SO_MARK). Without these, pool sockets bypass the
        // WireGuard policy routing and QUIC traffic leaks outside the
        // tunnel. Set via NewUDPSocketPool from the freedom Handler.Init.
        sockopt *internet.SocketConfig
}

type pooledSocket struct {
        mu            sync.RWMutex // v26.10.16-link: RWMutex so readLoop can RLock the demux read
        conn          stdnet.PacketConn
        dest          *stdnet.UDPAddr
        refCount      int
        // v26.10.43-link (audit P5): atomic timestamps to avoid
        // mutex contention on the readLoop hot path.
        lastUsed      atomic.Int64 // UnixNano
        lastReplyTime atomic.Int64  // UnixNano
        demux         map[dcidKey]chan<- readResult // v26.10.16-link: struct key, zero-alloc
        // v26.11.99-link: lastActiveCh for delivering server Initial replies
        // when Chrome uses 0-length SCID. Server's Initial reply has DCID=∅,
        // which can't be demuxed. We deliver to the most recently active conn,
        // then register the server's SCID from the reply so future packets
        // (Handshake, 1-RTT) hit demux normally via the DCID (= server's SCID).
        lastActiveCh  chan<- readResult
        closed        chan struct{}
        closeOnce     sync.Once
        dead          bool
        // v26.10.15-link: dropped reply packets counter for observability.
        droppedReplies atomic.Int64
}

// v26.10.16-link: dcidKey is a zero-allocation map key for QUIC DCID
// lookups in the pooled socket's demux map. Replaces hex.EncodeToString(dcid)
// which allocated a 16-char string per reply packet. The struct is 24
// bytes (20 CID + 4 len), comparable, and hashable.
type dcidKey struct {
        cid [quic.MaxCIDLen]byte
        len int
}

// v26.10.42-link (audit P3): pool packet buffers to avoid make([]byte, n) +
// copy per QUIC reply packet. At 25 kpps this eliminates ~10-30 MB/s of
// garbage on the UDP demux hot path.
var packetPool = sync.Pool{
        New: func() any {
                b := make([]byte, 65535)
                return &b
        },
}

func getPacket() []byte  { return *packetPool.Get().(*[]byte) }
func putPacket(b []byte) { packetPool.Put(&b) }

func makeDCIDKey(dcid []byte) dcidKey {
        var k dcidKey
        k.len = len(dcid)
        copy(k.cid[:], dcid)
        return k
}

// cidKey is the string form for the scids map and the pooledConn.RegisterCID
// path. Kept as string because SCID registration happens once per connection
// (not per packet), so the alloc cost is negligible.
type readResult struct {
        data []byte
        addr stdnet.Addr
}

type pooledConn struct {
        socket *pooledSocket
        inbox  chan readResult
        done   chan struct{}
        mu     sync.Mutex
        // v26.10.15-link: closed is atomic so WriteTo (the hot path)
        // can check it without acquiring mu. mu is still needed to
        // protect scids map mutations during Close.
        closed atomic.Bool
        // v26.10.16-link: scidsDCID stores the SCIDs we've registered
        // in the socket's demux map. Keyed on dcidKey (struct, zero-alloc)
        // so Close() can index demux directly without converting from
        // hex string. Replaces the old scids map[string]bool.
        scidsDCID map[dcidKey]bool
}

func NewUDPSocketPool(staleness, idle, unused time.Duration, sockopt *internet.SocketConfig) *UDPSocketPool {
        p := &UDPSocketPool{
                sockets:          make(map[string]*pooledSocket),
                stalenessTimeout: staleness,
                idleTimeout:      idle,
                unusedTimeout:    unused,
                sockopt:          sockopt,
        }
        p.startReaper()
        return p
}

// listenUDPWithSockopt creates a UDP socket and applies the pool's
// sockopt config (interface binding, fwmark, UDP_GRO). This is the
// v26.10.17-link fix for WireGuard: without SO_BINDTODEVICE, pool
// sockets bypass the WG policy routing and QUIC traffic leaks.
func (p *UDPSocketPool) listenUDPWithSockopt() (stdnet.PacketConn, error) {
        pc, err := stdnet.ListenUDP("udp", nil)
        if err != nil {
                return nil, err
        }
        // v26.10.19-link: only enter the SyscallConn/Control path when we
        // actually have something to apply. If the sockopt has no interface
        // and no mark (e.g., the "direct" outbound for YouTube), skip the
        // entire Control path and return the bare socket — identical to
        // v26.10.16 behavior. This avoids a regression where SyscallConn()
        // + Control() had a side effect that broke the pool's read path.
        if p.sockopt == nil {
                return pc, nil
        }
        if p.sockopt.Interface == "" && p.sockopt.Mark == 0 {
                return pc, nil
        }
        // We have an interface or mark to apply. Get the raw fd via
        // SyscallConn.Control and apply SO_BINDTODEVICE + SO_MARK.
        rawConn, err := pc.SyscallConn()
        if err != nil {
                return pc, nil
        }
        err = rawConn.Control(func(fd uintptr) {
                optErr := applyPoolSocketOptions(int(fd), p.sockopt)
                if optErr != nil {
                        xrayerrors.LogWarning(context.Background(), "udp_pool: failed to apply sockopt on pool socket: ", optErr)
                }
        })
        if err != nil {
                return pc, nil
        }
        return pc, nil
}

func (p *UDPSocketPool) startReaper() {
        p.reaper = time.NewTicker(2 * time.Minute)
        go func() {
                for range p.reaper.C {
                        p.evictStale()
                }
        }()
}

// Close stops the reaper goroutine. Safe to call multiple times.
// v26.10.34-link (M4 fix): without this, every SIGHUP reload leaks one
// reaper goroutine + one time.Ticker per freedom outbound.
func (p *UDPSocketPool) Close() {
        if p.reaper != nil {
                p.reaper.Stop()
        }
}

func (p *UDPSocketPool) evictStale() {
        p.mu.Lock()
        defer p.mu.Unlock()
        for key, sock := range p.sockets {
                sock.mu.Lock()
                isDead := sock.dead
                // v26.10.43-link (audit P5): atomic reads for timestamps
                isIdle := time.Since(time.Unix(0, sock.lastReplyTime.Load())) > p.idleTimeout && sock.refCount > 0
                isUnused := time.Since(time.Unix(0, sock.lastUsed.Load())) > p.unusedTimeout && sock.refCount == 0
                sock.mu.Unlock()

                if isDead || isIdle || isUnused {
                        // v26.10.34-link (H1 fix): use MarkStale (not MarkDead) so
                        // sockets with active sessions (refCount > 0) keep their
                        // conn alive. MarkDead would close s.conn and kill all
                        // sessions sharing it — the exact regression v26.10.28
                        // fixed for the Acquire path but missed in the reaper.
                        sock.MarkStale()
                        delete(p.sockets, key)
                        xrayerrors.LogInfo(context.Background(), "udp_pool: evicted stale socket for ", key)
                }
        }
}

// InvalidateByIP marks all pool sockets to the given IP as stale.
// Called by the sticky resolver when it refreshes DNS and gets a new
// IP — the old IP's pool sockets should be evicted so new connections
// use the fresh IP.
//
// v26.10.27-link: closes the gap between sticky resolver TTL (60s)
// and pool staleness (300s). Previously, when the resolver got a new
// IP, existing pool sockets to the old IP stayed alive for up to 5
// minutes, sending QUIC retransmits into a black hole.
func (p *UDPSocketPool) InvalidateByIP(ip string) {
        p.mu.Lock()
        for key, sock := range p.sockets {
                if strings.HasPrefix(key, ip+":") || strings.HasPrefix(key, "["+ip+"]:") {
                        // v26.10.42-link (audit C1): use MarkStale instead of
                        // manually setting dead=true. Prevents the FD+goroutine
                        // leak when refCount reaches 0 after invalidation.
                        sock.MarkStale()
                        delete(p.sockets, key)
                        xrayerrors.LogInfo(context.Background(), "udp_pool: invalidated socket for ", key, " (IP changed)")
                }
        }
        p.mu.Unlock()
}

func destKey(dest *stdnet.UDPAddr) string {
        return dest.String()
}

func (p *UDPSocketPool) Acquire(dest *stdnet.UDPAddr) (*pooledConn, error) {
        key := destKey(dest)

        p.mu.Lock()
        sock, ok := p.sockets[key]
        if ok && (sock.IsClosed() || sock.IsDead()) {
                delete(p.sockets, key)
                ok = false
        }
        if ok {
                // STALENESS CHECK: If the socket hasn't received a reply in 60 seconds,
                // assume the CDN edge rotated and is silently dropping packets.
                // Mark it dead and force the creation of a fresh socket for this request.
                sock.mu.Lock()
                // v26.10.43-link (audit P5): atomic read
                isStale := time.Since(time.Unix(0, sock.lastReplyTime.Load())) > p.stalenessTimeout
                sock.mu.Unlock()
                if isStale {
                        // v26.10.42-link (audit C1): use MarkStale instead of
                        // manually setting dead=true. MarkStale closes s.conn
                        // when refCount==0, preventing the FD+goroutine leak
                        // that occurred when refCount hit 0 after this point
                        // (release() checks s.dead but the conn was never
                        // closed because we bypassed MarkStale's close logic).
                        sock.MarkStale()
                        delete(p.sockets, key)
                        ok = false
                } else {
                        // v26.10.26-link: only increment refCount if the socket
                        // is alive. Previously this ran even after MarkDead+delete,
                        // orphaning the dead socket with refCount > 0.
                        // v26.10.43-link (audit P5): init atomic timestamps
                        nowNano := time.Now().UnixNano()
                        sock.lastUsed.Store(nowNano)
                        sock.lastReplyTime.Store(nowNano) // v26.10.26: init to now, not zero
                        sock.mu.Lock()
                        sock.refCount++
                        sock.lastUsed.Store(nowNano)
                        sock.mu.Unlock()
                }
        }
        p.mu.Unlock()

        if !ok {
                // v26.10.17-link: create the socket with interface binding,
                // fwmark, and UDP_GRO so QUIC traffic through the pool follows
                // the WireGuard policy routing instead of leaking via the
                // default route.
                pc, err := p.listenUDPWithSockopt()
                if err != nil {
                        return nil, err
                }

                sock = &pooledSocket{
                        conn:          pc,
                        dest:          dest,
                        demux:         make(map[dcidKey]chan<- readResult),
                        closed:        make(chan struct{}),
                        lastUsed:      atomic.Int64{},
                        lastReplyTime: atomic.Int64{},
                }

                p.mu.Lock()
                if existing, ok := p.sockets[key]; ok && !existing.IsClosed() && !existing.IsDead() {
                        pc.Close()
                        sock = existing
                        // v26.10.43-link (audit P5): init atomic timestamps
                        nowNano := time.Now().UnixNano()
                        sock.lastUsed.Store(nowNano)
                        sock.lastReplyTime.Store(nowNano) // v26.10.26: init to now, not zero
                        sock.mu.Lock()
                        sock.refCount++
                        sock.mu.Unlock()
                } else {
                        p.sockets[key] = sock
                        // v26.10.43-link (audit P5): init atomic timestamps
                        nowNano := time.Now().UnixNano()
                        sock.lastUsed.Store(nowNano)
                        sock.lastReplyTime.Store(nowNano) // v26.10.26: init to now, not zero
                        sock.mu.Lock()
                        sock.refCount++
                        sock.mu.Unlock()
                        go sock.readLoop()
                }
                p.mu.Unlock()
        }

        inbox := make(chan readResult, 256) // v26.10.20-link: was 32, increased to 256 to absorb YouTube reply bursts
        conn := &pooledConn{
                socket:    sock,
                inbox:     inbox,
                done:      make(chan struct{}),
                scidsDCID: make(map[dcidKey]bool),
        }
        return conn, nil
}

func (s *pooledSocket) readLoop() {
        // v26.10.15-link: 65535 bytes to handle UDP GRO/GSO coalesced
        // datagrams (Linux can deliver up to 64KB in a single recvmsg
        // when GRO is enabled). The old 1500-byte buffer silently
        // truncated coalesced QUIC packets, causing the DCID parser to
        // see malformed packets and demux replies to sessions that
        // couldn't read them. Memory cost: 64KB per pooled socket
        // (dozens of sockets total = ~1MB).
        b := make([]byte, 65535)
        for {
                select {
                case <-s.closed:
                        return
                default:
                }

                n, addr, err := s.conn.ReadFrom(b)
                if err != nil {
                        if s.IsClosed() {
                                return
                        }
                        // v26.10.26-link: don't kill the shared socket on
                        // transient read errors (ICMP port-unreachable from CDN
                        // edge rotation, EAGAIN, ENOBUFS, etc). The write path
                        // already has isTransientWriteError; the read path didn't.
                        // A single ICMP unreachable would kill all 50+ sessions
                        // sharing this socket.
                        if isTransientReadError(err) {
                                xrayerrors.LogInfo(context.Background(), "udp_pool: transient read error, continuing: ", err)
                                continue
                        }
                        xrayerrors.LogInfo(context.Background(), "udp_pool: read error, marking socket dead: ", err)
                        s.MarkDead()
                        return
                }

                // v26.10.42-link (audit P3): use pooled buffer instead of
                // make+copy per packet.
                packet := getPacket()
                copy(packet, b[:n])

                dcid, _, err := quic.ParseDCID(packet[:n])
                if err != nil {
                        putPacket(packet)
                        continue
                }
                // v26.10.16-link: zero-alloc dcidKey struct instead of
                // hex.EncodeToString(dcid) which allocated a 16-char string
                // per reply packet.
                dk := makeDCIDKey(dcid)

                // v26.10.16-link: use RLock for the demux read path (was
                // Lock, blocking all RegisterCID calls which need write
                // locks). The demux map is only mutated by RegisterCID
                // and Close (which use Lock), so RLock is correct here.
                s.mu.RLock()
                ch, ok := s.demux[dk]
                s.mu.RUnlock()

                // Update timestamps under Lock. This is a short critical
                // section but still serializes with RegisterCID. A future
                // optimization could make these atomic.Int64 fields, but
                // that requires updating evictStale to read them atomically
                // too — defer to avoid risk.
                // v26.10.43-link (audit P5): atomic stores, no mutex needed
                nowNano := time.Now().UnixNano()
                s.lastUsed.Store(nowNano)
                s.lastReplyTime.Store(nowNano)

                if !ok {
                        // v26.11.99-link: Deliver server's Initial reply when Chrome uses 0-SCID.
                        // Server's Initial has DCID=∅ (Chrome's SCID). demux can't route it.
                        // Deliver to lastActiveCh (the most recently active conn), then
                        // register the server's SCID from the reply so future packets
                        // (Handshake, 1-RTT with DCID=server's SCID) hit demux normally.
                        if len(dcid) == 0 && n > 0 && packet[0]&0x80 != 0 {
                                // Long header with 0-length DCID = server's reply to 0-SCID client
                                s.mu.RLock()
                                ch = s.lastActiveCh
                                s.mu.RUnlock()
                                if ch != nil {
                                        ok = true
                                        // Register the server's SCID from this reply so future
                                        // packets with DCID=serverSCID hit demux directly.
                                        if scid, _, serr := quic.ParseSCID(packet[:n]); serr == nil && len(scid) > 0 {
                                                scidKey := makeDCIDKey(scid)
                                                s.mu.Lock()
                                                if _, exists := s.demux[scidKey]; !exists {
                                                        s.demux[scidKey] = ch
                                                }
                                                s.mu.Unlock()
                                        }
                                }
                        }
                        if !ok {
                                putPacket(packet)
                                continue
                        }
                }

                // v26.10.21-link: non-blocking send with large channel (256).
                //
                // The blocking send (v26.10.20) was WRONG for the shared-socket
                // model: one slow/stale session's full channel would block the
                // entire readLoop, starving ALL other sessions sharing the same
                // socket. This made YouTube stalls WORSE when swiping quickly
                // between videos (many sessions, one stale session blocks all).
                //
                // The correct approach for a shared readLoop:
                // 1. Large channel (256) so drops are rare during bursts
                // 2. Non-blocking send so one slow session doesn't starve others
                // 3. Track drops for observability
                select {
                case ch <- readResult{data: packet, addr: addr}:
                default:
                        s.droppedReplies.Add(1)
                        // v26.10.42-link (audit P3): return the pooled buffer
                        // when the inbox is full and we drop the packet.
                        putPacket(packet)
                }
        }
}

func (s *pooledSocket) IsClosed() bool {
        select {
        case <-s.closed:
                return true
        default:
                return false
        }
}

func (s *pooledSocket) IsDead() bool {
        s.mu.Lock()
        defer s.mu.Unlock()
        return s.dead
}

// MarkDead marks the socket as dead and closes it immediately.
// Used for persistent errors (EBADF, read failure on closed socket).
func (s *pooledSocket) MarkDead() {
        s.mu.Lock()
        defer s.mu.Unlock()
        if s.dead {
                return
        }
        s.dead = true
        s.closeOnce.Do(func() {
                close(s.closed)
                _ = s.conn.Close()
        })
}

// MarkStale marks the socket as dead but does NOT close s.conn if
// there are active sessions (refCount > 0). Used by the staleness
// check in Acquire — new sessions get a fresh socket, but existing
// sessions keep their connection alive.
//
// v26.10.27-link: previously, staleness called MarkDead which closed
// s.conn, killing ALL existing sessions sharing the socket. A new
// Shorts swipe would kill the currently-playing video's QUIC connection.
func (s *pooledSocket) MarkStale() {
        s.mu.Lock()
        defer s.mu.Unlock()
        if s.dead {
                return
        }
        s.dead = true
        if s.refCount == 0 {
                // No active sessions — safe to close now.
                s.closeOnce.Do(func() {
                        close(s.closed)
                        _ = s.conn.Close()
                })
        }
        // If refCount > 0, existing sessions keep the socket alive.
        // The readLoop will exit when s.closed is closed (which happens
        // when the last session calls release() and refCount hits 0,
        // or when the reaper evicts it).
}

func (s *pooledSocket) release() {
        s.mu.Lock()
        if s.refCount > 0 {
                s.refCount--
        }
        s.lastUsed.Store(time.Now().UnixNano())
        // v26.10.28-link: if refCount reaches 0 and the socket was
        // removed from the pool map (staleness or InvalidateByIP),
        // close it now. The socket is not in the map so no new
        // sessions will find it — safe to close.
        if s.refCount == 0 && s.dead {
                s.closeOnce.Do(func() {
                        close(s.closed)
                        _ = s.conn.Close()
                })
        }
        s.mu.Unlock()
}

func (c *pooledConn) RegisterCID(cid []byte) {
        if len(cid) == 0 {
                return
        }
        // v26.10.16-link: use zero-alloc dcidKey for both the scids set
        // and the demux map. Eliminates hex.EncodeToString per SCID
        // registration (was 1 string alloc; now zero).
        dk := makeDCIDKey(cid)

        // v26.10.15-link: atomic closed check avoids acquiring mu
        // when the conn is already closed.
        if c.closed.Load() {
                return
        }
        c.mu.Lock()
        already := c.scidsDCID[dk]
        if !already {
                c.scidsDCID[dk] = true
        }
        c.mu.Unlock()

        if !already {
                // H4 fix: re-check closed under lock before mutating demux.
                // Between the first closed check and here, another goroutine
                // could call Close() which clears scidsDCID from demux.
                c.mu.Lock()
                if c.closed.Load() {
                        c.mu.Unlock()
                        return
                }
                c.socket.mu.Lock()
                c.socket.demux[dk] = c.inbox
                c.socket.mu.Unlock()
                c.mu.Unlock()
        }
}

func (c *pooledConn) WriteTo(b []byte, addr stdnet.Addr) (int, error) {
        // v26.10.15-link: use atomic.Bool for closed check (25x faster
        // than mutex acquire+release on the hot path).
        if c.closed.Load() {
                return 0, io.EOF
        }

        // v26.10.15-link: only parse SCID for long headers (Initial,
        // 0-RTT, Handshake). Short headers (1-RTT, bit 7 = 0) don't
        // carry SCID length info, and we've already registered the SCID
        // during the handshake. This skips the parse + hex encode +
        // mutex acquire for 99% of packets in a long-lived QUIC
        // connection (which are 1-RTT).
        if len(b) > 0 && b[0]&0x80 != 0 {
                if scid, _, err := parseQUICSCID(b); err == nil && len(scid) > 0 {
                        c.RegisterCID(scid)
                }
                // Also register the DCID. The client's Initial has DCID =
                // initial_dcid and SCID = client_scid. The pool registers
                // client_scid (above) so the server's Initial reply (DCID =
                // client_scid) is demuxed correctly. BUT the server's Retry
                // packet has DCID = initial_dcid (the client's DCID from the
                // Initial, NOT the SCID). Without registering initial_dcid,
                // Retry packets are silently dropped by readLoop's demux
                // lookup, and the QUIC handshake never completes — the
                // browser times out QUIC and falls back to H2/TCP.
                if dcid, _, err := quic.ParseDCID(b); err == nil && len(dcid) > 0 {
                        c.RegisterCID(dcid)
                }
        }

        // v26.10.34-link (M1 fix): honor the caller-provided addr if it's a
        // *net.UDPAddr; otherwise fall back to the socket's fixed dest. The
        // pool model assumes one socket per dest, but QUIC connection
        // migration can send packets to a different server IP.
        dest := c.socket.dest
        if udp, ok := addr.(*stdnet.UDPAddr); ok {
                dest = udp
        }
        n, err := c.socket.conn.WriteTo(b, dest)
        if err != nil {
                if !isTransientWriteError(err) {
                        c.socket.MarkDead()
                }
        } else {
                // v26.11.99-link: Update lastActiveCh so the server's Initial reply
                // (which has DCID=∅ for 0-SCID Chrome) can be delivered.
                c.socket.mu.Lock()
                c.socket.lastActiveCh = c.inbox
                c.socket.mu.Unlock()
        }
        return n, err
}

func (c *pooledConn) ReadFrom(p []byte) (int, stdnet.Addr, error) {
        select {
        case rr, ok := <-c.inbox:
                if !ok {
                        return 0, nil, io.EOF
                }
                n := copy(p, rr.data)
                // v26.10.42-link (audit P3): return the pooled buffer
                // after copying the data out.
                putPacket(rr.data)
                return n, rr.addr, nil
        case <-c.done:
                return 0, nil, io.EOF
        }
}

func (c *pooledConn) IsClosed() bool {
        return c.closed.Load()
}

func (c *pooledConn) Close() error {
        // v26.10.15-link: atomic CAS to avoid double-close. The
        // CAS ensures only one caller proceeds to close(c.done)
        // and the scids cleanup.
        if !c.closed.CompareAndSwap(false, true) {
                return nil
        }
        close(c.done)

        c.mu.Lock()
        // v26.10.34-link (C1 fix): acquire socket.mu before mutating s.demux.
        // Without this, readLoop (RLock) and RegisterCID (Lock) race with the
        // delete here — Go's race detector flags it, and production can panic
        // with "concurrent map read and map write".
        c.socket.mu.Lock()
        for dk := range c.scidsDCID {
                if existing, ok := c.socket.demux[dk]; ok && existing == c.inbox {
                        delete(c.socket.demux, dk)
                }
        }
        c.socket.mu.Unlock()
        c.mu.Unlock()

        c.socket.release()
        return nil
}

func (c *pooledConn) LocalAddr() stdnet.Addr {
        return c.socket.conn.LocalAddr()
}

func (c *pooledConn) RemoteAddr() stdnet.Addr {
        return c.socket.dest
}

func (c *pooledConn) SetDeadline(time.Time) error      { return nil }
func (c *pooledConn) SetReadDeadline(time.Time) error  { return nil }
func (c *pooledConn) SetWriteDeadline(time.Time) error { return nil }

func parseQUICSCID(b []byte) ([]byte, bool, error) {
        // Thin wrapper around quic.ParseSCID so that the freedom package does not
        // duplicate long-header parsing logic. Keeping the local name preserves
        // the call-site shape (one less import-qualified call) and lets us swap
        // the implementation in a single place if the QUIC spec ever grows a new
        // long-header variant that requires version-specific SCID handling.
        return quic.ParseSCID(b)
}

// isTransientWriteError returns true for WriteTo errors that are
// recoverable and should NOT cause the socket to be marked dead.
// These include:
//   - EAGAIN/EWOULDBLOCK: send buffer full, kernel will retry
//   - ENOMEM/ENOBUFS: kernel memory pressure, transient
//   - EHOSTUNREACH/ENETUNREACH: routing blip, usually recovers
//   - ECONNREFUSED: ICMP port unreachable, transient for UDP
//
// Only persistent errors (EBADF, EINVAL, EFAULT) should mark the
// socket dead — they indicate the socket itself is broken.
//
// v26.10.15-link: without this check, a single transient EAGAIN
// would kill the socket and all 50+ QUIC sessions sharing it.
// applyPoolSocketOptions applies interface binding, fwmark, and UDP_GRO
// to a pool socket's file descriptor. Linux-only; on other platforms
// the syscall constants don't exist and this function isn't called.
//
// v26.10.17-link: critical fix for WireGuard. Without SO_BINDTODEVICE,
// pool sockets bypass the WG policy routing and QUIC traffic leaks
// outside the tunnel. Without SO_MARK, packets don't get the fwmark
// that wg-quick uses for policy routing.
func applyPoolSocketOptions(fd int, sockopt *internet.SocketConfig) error {
        // v26.10.17-link: SO_BINDTODEVICE + SO_MARK for WireGuard.
        if sockopt.Interface != "" {
                if err := syscall.BindToDevice(fd, sockopt.Interface); err != nil {
                        return xrayerrors.New("failed to set SO_BINDTODEVICE on pool socket: ", err)
                }
        }
        if sockopt.Mark != 0 {
                if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, int(sockopt.Mark)); err != nil {
                        return xrayerrors.New("failed to set SO_MARK on pool socket: ", err)
                }
        }
        // v26.10.27-link: honor customSockopt (SO_RCVBUF, SO_SNDBUF, etc).
        // Previously the pool path skipped these — only the non-pool TCP/UDP
        // path applied them. Users who set customSockopt for buffer sizes
        // were silently ignored on pool sockets.
        for _, custom := range sockopt.CustomSockopt {
                if custom.System != "" && custom.System != "linux" {
                        continue
                }
                // H1 fix: was strings.HasPrefix("udp", custom.Network) — backwards.
                if custom.Network != "" && !strings.Contains(custom.Network, "udp") {
                        continue
                }
                level, _ := strconv.Atoi(custom.Level)
                if level == 0 {
                        level = syscall.SOL_SOCKET // L7 fix: was 0x6 (IPPROTO_TCP), wrong for UDP
                }
                opt, _ := strconv.Atoi(custom.Opt)
                if opt == 0 {
                        continue
                }
                if custom.Type == "int" {
                        value, _ := strconv.Atoi(custom.Value)
                        if err := syscall.SetsockoptInt(fd, level, opt, value); err != nil {
                                xrayerrors.LogWarning(context.Background(), "udp_pool: failed to set customSockopt: ", err)
                        }
                }
        }
        return nil
}

func isTransientWriteError(err error) bool {
        if err == nil {
                return false
        }
        // Use errors.As to unwrap net.OpError and similar wrappers
        var errno syscall.Errno
        if errors.As(err, &errno) {
                switch errno {
                case syscall.EAGAIN,
                        syscall.ENOMEM, syscall.ENOBUFS,
                        syscall.EHOSTUNREACH, syscall.ENETUNREACH,
                        syscall.ECONNREFUSED:
                        return true
                }
        }
        return false
}

// isTransientReadError mirrors isTransientWriteError for the read path.
// v26.10.26-link: without this, a single ICMP port-unreachable from CDN
// edge rotation would MarkDead the shared socket and kill all 50+ sessions.
func isTransientReadError(err error) bool {
        if err == nil {
                return false
        }
        var errno syscall.Errno
        if errors.As(err, &errno) {
                switch errno {
                case syscall.EAGAIN,
                        syscall.ENOMEM, syscall.ENOBUFS,
                        syscall.EHOSTUNREACH, syscall.ENETUNREACH,
                        syscall.ECONNREFUSED:
                        return true
                }
        }
        return false
}

// ============================================================
// Integration with freedom.go: pooled buf.Reader/Writer
// ============================================================

type PooledPacketReader struct {
        conn *pooledConn
}

func NewPooledPacketReader(conn *pooledConn) *PooledPacketReader {
        return &PooledPacketReader{conn: conn}
}

func (r *PooledPacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
        // v26.10.42-link (audit C2): use a 64KB buffer to match the readLoop's
        // 64KB read buffer. The previous buf.New() (8KB cap) silently truncated
        // GRO-coalesced QUIC packets and coalesced Initial+Handshake+0-RTT
        // bundles that exceed 8KB, causing the QUIC parser to see malformed
        // packets and demux replies to sessions that couldn't read them.
        b := buf.NewWithSize(65535)
        b.Resize(0, 65535)

        n, addr, err := r.conn.ReadFrom(b.Bytes())
        if err != nil {
                b.Release()
                return nil, err
        }
        b.Resize(0, int32(n))

        if udpAddr, ok := addr.(*stdnet.UDPAddr); ok {
                b.UDP = &xraynet.Destination{
                        Address: xraynet.IPAddress(udpAddr.IP),
                        Port:    xraynet.Port(udpAddr.Port),
                        Network: xraynet.Network_UDP,
                }
        }
        return buf.MultiBuffer{b}, nil
}

type PooledPacketWriter struct {
        conn      *pooledConn
        statWrite stats.Counter
}

func NewPooledPacketWriter(conn *pooledConn, statWrite stats.Counter) *PooledPacketWriter {
        return &PooledPacketWriter{conn: conn, statWrite: statWrite}
}

func (w *PooledPacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
        for {
                mb2, b := buf.SplitFirst(mb)
                mb = mb2
                if b == nil {
                        break
                }

                // v26.10.74-link: always use socket.dest (the pool's fixed
                // destination IP that freedom already resolved and dialed).
                //
                // The previous code called `b.UDP.Address.IP()` to construct
                // the destAddr. This was unsafe because the dispatcher's QUIC
                // sniffing override (default.go:378,390) and the handler's
                // EndpointOverrideReader (override.go:13-23) rewrite b.UDP.Address
                // from the original IP to the sniffed SNI domain (a domainAddress).
                // Calling IP() on a domainAddress panics
                // (common/net/address.go:171-173: `panic("Calling IP() on a DomainAddress.")`),
                // killing the goroutine without recover() and causing Chrome
                // to fall back to HTTP/2.
                //
                // Always using socket.dest is both safer (no panic) and more
                // correct: the pool's entire DCID-demux model assumes one
                // destination per socket. All packets sent through this writer
                // should go to socket.dest — the address the pooled socket
                // was acquired for at freedom.go:619 (h.socketPool.Acquire).
                destAddr := w.conn.socket.dest

                n, err := w.conn.WriteTo(b.Bytes(), destAddr)
                b.Release()
                if err != nil {
                        buf.ReleaseMulti(mb)
                        return err
                }
                if w.statWrite != nil {
                        w.statWrite.Add(int64(n))
                }
        }
        return nil
}

func isQUICLongHeader(b []byte) bool {
        if len(b) < 1 {
                return false
        }
        return b[0]&0x80 != 0 && b[0]&0x40 != 0
}
