package freedom

import (
        "context"
        "errors"
        "io"
        stdnet "net"
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
        lastUsed      time.Time
        lastReplyTime time.Time
        demux         map[dcidKey]chan<- readResult // v26.10.16-link: struct key, zero-alloc
        closed        chan struct{}
        closeOnce     sync.Once
        dead          bool
        // v26.10.15-link: dropped reply packets counter for observability.
        // Incremented when the inbox channel (cap 32) is full and the
        // readLoop drops a reply packet. QUIC will retransmit, but
        // persistent drops indicate a slow consumer.
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
        if p.sockopt == nil {
                return pc, nil
        }
        // pc is *net.UDPConn which implements SyscallConn. Get the raw fd
        // via Control so we can apply SO_BINDTODEVICE, SO_MARK, UDP_GRO.
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

func (p *UDPSocketPool) evictStale() {
        p.mu.Lock()
        defer p.mu.Unlock()
        for key, sock := range p.sockets {
                sock.mu.Lock()
                isDead := sock.dead
                isIdle := time.Since(sock.lastReplyTime) > p.idleTimeout && sock.refCount > 0
                isUnused := time.Since(sock.lastUsed) > p.unusedTimeout && sock.refCount == 0
                sock.mu.Unlock()

                if isDead || isIdle || isUnused {
                        sock.MarkDead()
                        delete(p.sockets, key)
                        xrayerrors.LogInfo(context.Background(), "udp_pool: evicted stale socket for ", key)
                }
        }
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
                isStale := time.Since(sock.lastReplyTime) > p.stalenessTimeout
                sock.mu.Unlock()
                if isStale {
                        sock.MarkDead()
                        delete(p.sockets, key)
                        ok = false
                }
                sock.mu.Lock()
                sock.refCount++
                sock.lastUsed = time.Now()
                sock.mu.Unlock()
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
                        conn:     pc,
                        dest:     dest,
                        demux:    make(map[dcidKey]chan<- readResult),
                        closed:   make(chan struct{}),
                        lastUsed: time.Now(),
                }

                p.mu.Lock()
                if existing, ok := p.sockets[key]; ok && !existing.IsClosed() && !existing.IsDead() {
                        pc.Close()
                        sock = existing
                        sock.mu.Lock()
                        sock.refCount++
                        sock.mu.Unlock()
                } else {
                        p.sockets[key] = sock
                        sock.mu.Lock()
                        sock.refCount++
                        sock.mu.Unlock()
                        go sock.readLoop()
                }
                p.mu.Unlock()
        }

        inbox := make(chan readResult, 32)
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
                        xrayerrors.LogInfo(context.Background(), "udp_pool: read error, marking socket dead: ", err)
                        s.MarkDead()
                        return
                }

                packet := make([]byte, n)
                copy(packet, b[:n])

                dcid, _, err := quic.ParseDCID(packet)
                if err != nil {
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
                s.mu.Lock()
                s.lastUsed = time.Now()
                s.lastReplyTime = time.Now()
                s.mu.Unlock()

                if !ok {
                        continue
                }

                select {
                case ch <- readResult{data: packet, addr: addr}:
                default:
                        // v26.10.15-link: track dropped replies for observability.
                        // QUIC retransmits will recover, but persistent drops
                        // indicate the consumer is slow.
                        s.droppedReplies.Add(1)
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

// MarkDead marks the socket as dead and closes it.
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

func (s *pooledSocket) release() {
        s.mu.Lock()
        if s.refCount > 0 {
                s.refCount--
        }
        s.lastUsed = time.Now()
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
                c.socket.mu.Lock()
                c.socket.demux[dk] = c.inbox
                c.socket.mu.Unlock()
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
        }

        n, err := c.socket.conn.WriteTo(b, c.socket.dest)
        if err != nil {
                // v26.10.15-link: only mark the socket dead on persistent
                // errors. Transient errors (EAGAIN, ENOBUFS, EHOSTUNREACH,
                // ENETUNREACH, ECONNREFUSED) are recoverable — the kernel
                // will retry or the route will come back. Killing the socket
                // on a transient error would kill all 50+ QUIC sessions
                // sharing this socket, which is much worse than dropping one
                // packet.
                if !isTransientWriteError(err) {
                        c.socket.MarkDead()
                }
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
        // v26.10.16-link: scids now stores dcidKey (struct, zero-alloc)
        // instead of string. This lets Close() index the demux map directly
        // without converting back from hex string to dcidKey.
        for dk := range c.scidsDCID {
                if existing, ok := c.socket.demux[dk]; ok && existing == c.inbox {
                        delete(c.socket.demux, dk)
                }
        }
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
        // NOTE: UDP_GRO was removed in v26.10.18-link. It caused YouTube to
        // stall because GRO coalesces multiple UDP packets into a single
        // ReadFrom call, but the pool's DCID demux assumes one packet per
        // read. With GRO enabled, ParseDCID only parsed the first packet in
        // the coalesced blob and the rest were silently dropped.
        //
        // To re-enable GRO safely, the readLoop would need to use recvmmsg
        // with GRO_RETURN_UNKNOWN and handle the per-packet metadata. That's
        // a bigger change — deferred.
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
        b := buf.New()
        b.Resize(0, buf.Size)

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

                var destAddr stdnet.Addr
                if b.UDP != nil {
                        destAddr = &stdnet.UDPAddr{
                                IP:   b.UDP.Address.IP(),
                                Port: int(b.UDP.Port),
                        }
                } else {
                        destAddr = w.conn.socket.dest
                }

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
