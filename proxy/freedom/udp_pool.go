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
        demuxSource   map[dcidKey]*stdnet.UDPAddr
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

// v26.10.42-link (audit P3): pool packet buffers to avoid make([]byte, n) +
// copy per QUIC reply packet. At 25 kpps this eliminates ~10-30 MB/s of
// garbage on the UDP demux hot path.
var packetPool = sync.Pool{
        New: func() any {
                b := make([]byte, 65535)
                return &b
        },
}

func getPacket() []byte  {
        b := *packetPool.Get().(*[]byte)
        return b[:cap(b)] // v26.11.81 fix: reset len to full capacity
}
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
        // v26.11.52-link (Solution B): source is the inbound client's
        // source IP:port, captured at Acquire time in freedom.go so the
        // pool can bind outbound packets to the originating client. nil
        // for non-QUIC / per-session paths.
        source *stdnet.UDPAddr
        // v26.10.16-link: scidsDCID stores the SCIDs we've registered
        // in the socket's demux map. Keyed on dcidKey (struct, zero-alloc)
        // so Close() can index demux directly without converting from
        // hex string. Replaces the old scids map[string]bool.
        scidsDCID map[dcidKey]bool
        // v26.11.0.18: timestamps for stall detection.
        // lastWriteTime is updated on every WriteTo call (Chrome→Google direction).
        // lastReplyTime is updated when a packet is delivered to the inbox (Google→Chrome).
        // If Chrome is actively sending but Google hasn't replied within stallTimeout,
        // the connection is considered stalled and we send ICMP to force Chrome fallback.
        // Atomic to avoid mutex contention on the hot path.
        lastWriteTime atomic.Int64 // UnixNano
        lastReplyTime atomic.Int64 // UnixNano
        // v26.11.0.18: ensure ICMP is only sent once per stall (avoid spamming Chrome
        // with multiple ICMPs if ReadFrom is called multiple times during shutdown).
        icmpSent atomic.Bool
        // v26.11.0.18: the inbound LOCAL port Chrome is sending to (typically 443).
        // Captured in freedom.go from inbound.Local.Port and used by
        // sendICMPPortUnreachable to build a valid ICMP packet whose embedded
        // UDP dst port matches Chrome's connected peer port — without this, the
        // kernel won't match the ICMP back to Chrome's socket and Chrome won't
        // see ECONNREFUSED. Defaults to 443 if not set.
        localPort int
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
                        demuxSource:   make(map[dcidKey]*stdnet.UDPAddr),
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
                src := s.demuxSource[dk]
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
                        // FIX: SCID-based fallback for 0-length SCID clients
                        // (Chrome/Edge). The server's reply DCID = client's SCID
                        // = ∅ (0 bytes), so demux[∅] misses (RegisterCID skips
                        // 0-length). But per RFC 9000 §7.3, the server's reply
                        // SCID = client's Initial DCID, which WAS registered in
                        // WriteTo. Parse the SCID and try demux[scid] as a
                        // fallback before dropping.
                        if n > 0 && packet[0]&0x80 != 0 {
                                if scid, _, perr := quic.ParseSCID(packet[:n]); perr == nil && len(scid) > 0 {
                                        scidKey := makeDCIDKey(scid)
                                        s.mu.RLock()
                                        ch, ok = s.demux[scidKey]
                                        src = s.demuxSource[scidKey]
                                        s.mu.RUnlock()
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
                sentOk := false
                packetToSend := packet[:n] // v26.11.81 fix: slice to actual length
                // v26.11.0.12: recover from panic — the inbox channel may be
                // closed (pooledConn.Close() no longer deletes from demux,
                // so stale entries point to closed channels). When we recover,
                // DELETE the stale entry so future replies with the same DCID
                // don't trigger another panic. Panics are expensive in Go
                // (~1us each), and accumulated stale entries would cause the
                // readLoop to slow down, delaying replies to active connections.
                panicked := false
                func() {
                        defer func() {
                                if r := recover(); r != nil {
                                        panicked = true
                                        s.droppedReplies.Add(1)
                                        putPacket(packet)
                                }
                        }()
                        select {
                        case ch <- readResult{data: packetToSend, addr: addr}:
                                sentOk = true
                        default:
                                s.droppedReplies.Add(1)
                                putPacket(packet)
                        }
                }()
                // v26.11.0.12: clean up stale demux entry on panic
                if panicked {
                        s.mu.Lock()
                        delete(s.demux, dk)
                        delete(s.demuxSource, dk)
                        s.mu.Unlock()
                }

                if sentOk && n > 0 && packet[0]&0x80 != 0 && src != nil {
                        pktType := (packet[0] >> 4) & 0x03
                        if pktType == 0x00 {
                                if scid, _, perr := quic.ParseSCID(packet[:n]); perr == nil && len(scid) > 0 {
                                        scidCopy := append([]byte(nil), scid...)
                                        quic.NotifyServerSCID(scidCopy, src)
                                }
                        }
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
                if c.source != nil {
                        c.socket.demuxSource[dk] = c.source
                }
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
                // FIX: also register the outgoing DCID. Per RFC 9000 §7.3,
                // the server's reply SCID = client's Initial DCID. For
                // 0-length SCID clients (Chrome/Edge), RegisterCID(scid)
                // is skipped (len==0), so demux has no entry for the
                // connection and the server's reply (DCID=∅) is silently
                // dropped. By registering the DCID, the readLoop's
                // SCID-based fallback can route the reply by looking up
                // demux[serverSCID] = demux[clientDCID].
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
        // v26.11.0.18: CRITICAL FIX — retry transient write errors internally
        // and swallow them if all retries fail. A single transient error
        // (EAGAIN, ENOBUFS, EHOSTUNREACH, ECONNREFUSED from CDN edge rotation)
        // must NOT kill the QUIC connection — QUIC handles packet loss via
        // retransmission. Previously, returning the error to the caller
        // (PooledPacketWriter.WriteMultiBuffer → buf.Copy → requestDone)
        // caused:
        //   1. buf.Copy in requestDone returns error
        //   2. task.Run cancels → Process returns → pooledConn.Close()
        //   3. QUIC connection dies, Chrome retries, may give up → TCP fallback
        // This was identified as a root cause of UDP stalls in v26.11.255
        // (for per-conn sockets); the same fix applies to pooled sockets.
        // Hot path overhead: zero on success (no extra syscall).
        for retry := 0; retry < 3; retry++ {
                n, err := c.socket.conn.WriteTo(b, dest)
                if err == nil {
                        c.lastWriteTime.Store(time.Now().UnixNano())
                        return n, nil
                }
                if !isTransientWriteError(err) {
                        // Persistent error — socket is broken. Mark dead and return
                        // the error so the caller can clean up.
                        c.socket.MarkDead()
                        c.lastWriteTime.Store(time.Now().UnixNano())
                        return n, err
                }
                // Transient error — retry after brief backoff (1ms, 2ms).
                // Only sleep between retries, not after the last attempt.
                if retry < 2 {
                        time.Sleep(time.Millisecond * time.Duration(1<<retry))
                }
        }
        // All retries exhausted — swallow the error to prevent Process from
        // dying. QUIC will retransmit if the packet was lost. Returning nil
        // here is intentional: one transient write failure should NOT kill
        // a long-lived QUIC connection.
        c.lastWriteTime.Store(time.Now().UnixNano())
        return len(b), nil
}

func (c *pooledConn) ReadFrom(p []byte) (int, stdnet.Addr, error) {
        // v26.11.0.18: Stall detection + ICMP trigger.
        //
        // When Chrome is actively sending packets (lastWriteTime is recent) but
        // Google hasn't replied within stallTimeout, the connection is stalled.
        // This happens when:
        //   - Google's CDN edge rotated (Google stopped serving this conn)
        //   - The destination IP is silently dropping packets
        //   - Some other path issue between xray and Google
        //
        // Previous fixes (v0.11 + v0.12) keep the demux entry and clean up stale
        // entries on panic, but Chrome's QUIC stack still has to wait for its
        // own ~25-30s timeout to fall back to TCP. This makes video stall for
        // 25-30s every time the CDN edge rotates or the conn dies.
        //
        // Fix: detect the stall after stallTimeout (5s) and send an ICMP port
        // unreachable to Chrome's source IP:port. This makes Chrome's UDP socket
        // receive ECONNREFUSED, causing Chrome's QUIC stack to immediately
        // declare the path broken and fall back to TCP (~1s).
        //
        // Key insight from v0.13-v0.17: ICMP must be triggered from STALL
        // DETECTION (which fires when the conn is genuinely stalled), NOT from
        // Close() (which never fires for active QUIC connections because Process
        // blocks on input/inbox forever).
        const stallTimeout = 5 * time.Second

        for {
                // Check if we're stalled RIGHT NOW (before blocking on inbox).
                // This catches the case where we've been stalled for a while.
                if c.isStalled(stallTimeout) {
                        c.handleStall()
                        return 0, nil, io.EOF
                }

                // Calculate the remaining time until stall timeout.
                // Use the more recent of lastReplyTime and lastWriteTime as the reference.
                now := time.Now()
                lastReplyNano := c.lastReplyTime.Load()
                lastWriteNano := c.lastWriteTime.Load()

                var refTime time.Time
                switch {
                case lastWriteNano == 0:
                        // No write yet — wait for the full timeout. Don't penalize the
                        // connection before Chrome has sent anything.
                        refTime = now
                case lastReplyNano > lastWriteNano:
                        // Google replied more recently than Chrome wrote. Use reply time.
                        refTime = time.Unix(0, lastReplyNano)
                default:
                        // Chrome wrote more recently than Google replied (or no reply yet).
                        // Use write time so the timer starts when Chrome last sent.
                        refTime = time.Unix(0, lastWriteNano)
                }

                remaining := stallTimeout - now.Sub(refTime)
                if remaining < 0 {
                        remaining = 0
                }

                timer := time.NewTimer(remaining)

                select {
                case rr, ok := <-c.inbox:
                        timer.Stop()
                        if !ok {
                                return 0, nil, io.EOF
                        }
                        n := copy(p, rr.data)
                        // v26.10.42-link (audit P3): return the pooled buffer
                        // after copying the data out.
                        putPacket(rr.data)
                        // v26.11.0.18: update reply timestamp for stall detection.
                        c.lastReplyTime.Store(time.Now().UnixNano())
                        return n, rr.addr, nil
                case <-c.done:
                        timer.Stop()
                        return 0, nil, io.EOF
                case <-timer.C:
                        // v26.11.0.18: stall timeout — no reply from Google.
                        // Check if Chrome is still actively sending. If Chrome
                        // stopped sending (idle/paused), don't kill the connection.
                        if c.isStalled(stallTimeout) {
                                c.handleStall()
                                return 0, nil, io.EOF
                        }
                        // Chrome is idle (not sending) — loop and wait again.
                        // Don't recurse — use a loop to avoid stack growth if Chrome
                        // oscillates between active and idle.
                }
        }
}

// isStalled returns true if Chrome is actively sending (lastWriteTime is recent)
// AND Google has NOT replied since the last write within stallTimeout.
//
// v26.11.0.18: This is the precise stall condition — Chrome sent a packet that
// Google never acknowledged. The previous implementation had a bug: it checked
// `now - lastReply > stallTimeout` even when Chrome had just written (e.g.,
// Chrome writes at T+6s after 6s idle; at T+7s the old logic declared stall
// because lastReply was 6.9s old, even though Google might have been about to
// reply to the brand-new write). That caused premature ICMP sends and killed
// healthy connections that were just resuming after a pause.
//
// Correct logic: only declare stall if Google has NOT replied SINCE the last
// write (lastReply < lastWrite) AND enough time has passed since that write.
// If lastReply >= lastWrite, Google acknowledged the last write — healthy.
//
// If Chrome hasn't written in 2x stallTimeout, the connection is just idle
// (user paused the video or is reading comments) — not stalled. We must NOT
// kill idle connections or we'd interrupt legitimate pauses.
func (c *pooledConn) isStalled(stallTimeout time.Duration) bool {
        now := time.Now()
        lastWriteNano := c.lastWriteTime.Load()
        lastReplyNano := c.lastReplyTime.Load()

        // No writes at all, or Chrome hasn't written in 2x stallTimeout → idle.
        if lastWriteNano == 0 || now.Sub(time.Unix(0, lastWriteNano)) > 2*stallTimeout {
                return false
        }

        // Chrome has written recently. If Google replied AT OR AFTER the last
        // write, the connection is healthy — the last packet was acked.
        if lastReplyNano > 0 && lastReplyNano >= lastWriteNano {
                return false
        }

        // Google has NOT replied to the last write. Wait stallTimeout from the
        // write before declaring stall (gives Google time to process + reply).
        return now.Sub(time.Unix(0, lastWriteNano)) > stallTimeout
}

// handleStall is called when a QUIC stall is detected. It sends an ICMP
// port unreachable to Chrome's source IP:port, which makes Chrome's UDP
// socket receive ECONNREFUSED. Chrome's QUIC stack then declares the path
// broken and falls back to TCP immediately (within ~1s) instead of waiting
// for its own 25-30s timeout.
//
// v26.11.0.18: This is the key fix. Previous attempts (v0.13-v0.17) tried
// to send ICMP from Close(), but Close() never fires for active QUIC
// connections (Process blocks on input/inbox forever). This version triggers
// ICMP from stall detection in ReadFrom, which DOES fire when the connection
// is genuinely stalled.
//
// After sending ICMP, we return EOF from ReadFrom. This causes:
//   1. responseDone's buf.Copy returns EOF
//   2. task.Run returns → Process returns → defer pooledConn.Close() fires
//   3. With v0.11 fix, demux entries are kept (stale) → readLoop drops
//      subsequent Google packets via panic recovery (v0.12 fix)
//   4. Chrome receives ICMP → ECONNREFUSED → declares path broken
//   5. Chrome falls back to TCP within ~1s
//   6. When Chrome retries QUIC (next video), xray handles it normally
func (c *pooledConn) handleStall() {
        // v26.11.0.18: ensure ICMP is only sent once per connection stall.
        // Multiple ReadFrom calls might detect the stall concurrently.
        if !c.icmpSent.CompareAndSwap(false, true) {
                // Already sent — just return EOF.
                return
        }
        lastWrite := time.Unix(0, c.lastWriteTime.Load())
        lastReply := time.Unix(0, c.lastReplyTime.Load())
        xrayerrors.LogInfo(context.Background(),
                "udp_pool: QUIC stall detected — sending ICMP port unreachable to force Chrome fallback; source=",
                c.source, " lastWrite=", lastWrite, " lastReply=", lastReply)
        c.sendICMPPortUnreachable()
}

// sendICMPPortUnreachable sends an ICMP Type 3 Code 3 (Destination
// Unreachable - Port Unreachable) packet to Chrome's source IP:port.
// This makes Chrome's UDP socket receive ECONNREFUSED, causing Chrome's
// QUIC stack to immediately declare the path broken and fall back to TCP.
//
// v26.11.0.18: The ICMP packet format follows RFC 792:
//   - ICMP header (8 bytes): Type=3, Code=3, Checksum, Unused
//   - Original IP header (20 bytes): Chrome's IP → VPS IP (looks like a packet Chrome sent)
//   - Original UDP header (8 bytes): Chrome's src port → VPS port (443)
//
// The kernel at Chrome's side matches the embedded IP+UDP headers to Chrome's
// connected UDP socket (LOCAL=Chrome:port, PEER=VPS:443) and sets ECONNREFUSED
// on it. Chrome's QUIC stack sees the error and declares the path broken.
//
// CRITICAL (v26.11.0.18 fix): the embedded IP dst and UDP dst port MUST match
// Chrome's socket PEER (VPS_IP, 443). Linux's __udp4_lib_lookup for connected
// UDP sockets requires inet_daddr == embedded IP dst AND inet_dport == embedded
// UDP dst port, otherwise the lookup fails silently and Chrome never sees the
// ECONNREFUSED. Previous versions used 0.0.0.0 for the IP dst (placeholder)
// and the pool socket's random local port for the UDP dst port — both WRONG.
//
// We get the VPS IP from the raw ICMP socket's LocalAddr after Dial: the
// kernel picks the source IP based on routing to Chrome's IP, which is the
// same VPS IP that Chrome is sending to (assuming symmetric routing).
//
// Requires CAP_NET_RAW (xray runs as root via systemd, so this is available).
// Silently fails if raw socket access is unavailable — Chrome will fall back
// to TCP via its own ~25s timeout in that case.
func (c *pooledConn) sendICMPPortUnreachable() {
        if c.source == nil {
                xrayerrors.LogInfo(context.Background(), "udp_pool: ICMP skip — c.source is nil")
                return
        }

        // Only send for IPv4 Chrome sources (ICMPv4 is simpler; ICMPv6 needs
        // different format and router solicitation, skip for now).
        srcIP := c.source.IP.To4()
        if srcIP == nil {
                xrayerrors.LogInfo(context.Background(), "udp_pool: ICMP skip — source is IPv6: ", c.source.IP)
                return
        }

        // The inbound LOCAL port Chrome is sending to (typically 443).
        // This MUST match Chrome's connected PEER port or the kernel won't
        // match the ICMP back to Chrome's socket.
        dstPort := uint16(c.localPort)
        if dstPort == 0 {
                dstPort = 443 // sensible default for QUIC/HTTP3
        }
        srcPort := uint16(c.source.Port)

        // Open the raw ICMP socket FIRST. The kernel picks the source IP
        // based on routing to Chrome's IP — this is the VPS IP that Chrome
        // is sending to. We need this for the embedded IP dst.
        conn, err := stdnet.Dial("ip4:icmp", srcIP.String())
        if err != nil {
                xrayerrors.LogInfo(context.Background(), "udp_pool: ICMP send failed (no raw socket access): ", err)
                return
        }
        defer conn.Close()

        // Extract the kernel-chosen source IP (= VPS IP Chrome sends to).
        var vpsIP stdnet.IP
        switch la := conn.LocalAddr().(type) {
        case *stdnet.IPAddr:
                vpsIP = la.IP.To4()
        case *stdnet.UDPAddr:
                vpsIP = la.IP.To4()
        }
        if vpsIP == nil {
                // Could not determine VPS IP — without it, the kernel won't
                // match the ICMP to Chrome's connected socket. Log and bail.
                xrayerrors.LogInfo(context.Background(), "udp_pool: ICMP skip — can't determine VPS local IP from raw socket")
                return
        }

        // Build ICMP Type 3 Code 3 packet.
        // Format per RFC 792:
        //   ICMP header (8 bytes): Type, Code, Checksum, Unused
        //   Original IP header (20 bytes): Chrome_IP → VPS_IP
        //   Original UDP header (8 bytes): Chrome_port → 443
        //
        // Total: 36 bytes. The kernel uses the embedded IP+UDP header to match
        // the ICMP back to Chrome's UDP socket.
        icmp := make([]byte, 36)
        // ICMP header
        icmp[0] = 3 // Type: Destination Unreachable
        icmp[1] = 3 // Code: Port Unreachable
        // icmp[2:4] = checksum (calculated below)
        // icmp[4:8] = unused (4 bytes, all zero)

        // Original IP header (20 bytes) — fabricated to look like a packet
        // from Chrome's IP:port to VPS's IP:port (i.e., the packet that
        // "triggered" this ICMP). Linux matches this against Chrome's
        // connected UDP socket.
        icmp[8] = 0x45 // Version (4) + IHL (5 = 20 bytes)
        icmp[9] = 0    // DSCP + ECN
        // Total length (2 bytes) = 28 (20 IP + 8 UDP)
        icmp[10] = 0
        icmp[11] = 28
        // Identification (2 bytes) = 0
        icmp[12] = 0
        icmp[13] = 0
        // Flags + Fragment offset (2 bytes) = 0
        icmp[14] = 0
        icmp[15] = 0
        icmp[16] = 64 // TTL
        icmp[17] = 17 // Protocol: UDP
        // Header checksum (2 bytes) = 0 (kernel doesn't validate the embedded checksum)
        icmp[18] = 0
        icmp[19] = 0
        // Source IP (4 bytes) = Chrome's IP (matches Chrome's socket LOCAL IP)
        copy(icmp[20:24], srcIP.To4())
        // Destination IP (4 bytes) = VPS's IP (matches Chrome's socket PEER IP).
        // v26.11.0.18 FIX: was 0.0.0.0 — that broke kernel socket matching for
        // connected UDP sockets. Now uses the actual VPS IP from the raw socket.
        copy(icmp[24:28], vpsIP)

        // Original UDP header (8 bytes)
        icmp[28] = byte(srcPort >> 8)
        icmp[29] = byte(srcPort)
        icmp[30] = byte(dstPort >> 8)
        icmp[31] = byte(dstPort)
        // UDP length (2 bytes) = 8 (just the header)
        icmp[32] = 0
        icmp[33] = 8
        // UDP checksum (2 bytes) = 0 (UDP checksum is optional for IPv4)
        icmp[34] = 0
        icmp[35] = 0

        // Calculate ICMP checksum (over the entire 36-byte packet)
        var sum uint32
        for i := 0; i < len(icmp); i += 2 {
                sum += uint32(icmp[i])<<8 | uint32(icmp[i+1])
        }
        for sum>>16 > 0 {
                sum = (sum & 0xFFFF) + (sum >> 16)
        }
        checksum := ^uint16(sum)
        icmp[2] = byte(checksum >> 8)
        icmp[3] = byte(checksum)

        // Send via raw ICMP socket. The kernel adds the outer IP header.
        _, err = conn.Write(icmp)
        if err != nil {
                xrayerrors.LogInfo(context.Background(), "udp_pool: ICMP write failed: ", err)
                return
        }
        xrayerrors.LogInfo(context.Background(),
                "udp_pool: sent ICMP port unreachable to ", srcIP, ":", c.source.Port,
                " (vps ", vpsIP, ":", dstPort, ")")
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

        // v26.11.0.11: DON'T delete DCIDs from the socket's demux map.
        // Previously, Close() removed the DCID entries (lines 676-680).
        // This caused the fast-swipe stall:
        // - Video A's Process returns → Close() → demux[A] deleted
        // - Google sends more packets with DCID A (retransmissions, ACKs)
        // - readLoop sees demux miss → drops them
        // - Chrome's QUIC stack never gets ACKs → declares path dead
        // - Chrome falls back to TCP after ~25s
        //
        // Fix: leave the DCID in the demux map as a stale entry. The inbox
        // channel is closed (close(c.done) above), so readLoop's non-blocking
        // send will panic — but we recover from the panic (in the send path)
        // and silently drop the packet. When a new connection registers the
        // same DCID (Chrome reuses DCIDs, or a new Initial overwrites it),
        // the stale entry is replaced with the new inbox.
        //
        // Memory impact: one stale demux entry per closed connection.
        // The pool's reaper (300s unused timeout) cleans up the socket
        // entirely, including all demux entries. So at most ~300s of
        // stale entries, which is negligible (a few hundred entries).
        //
        // We still need to release the socket's refCount so the reaper
        // can close it when it's truly unused.
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
