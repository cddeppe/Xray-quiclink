package freedom

import (
        "context"
        "errors"
        "fmt"
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
        mu            sync.RWMutex
        conn          stdnet.PacketConn
        dest          *stdnet.UDPAddr
        refCount      int
        lastUsed      atomic.Int64
        lastReplyTime atomic.Int64
        demux         map[dcidKey]chan<- readResult
        demuxSource   map[dcidKey]*stdnet.UDPAddr
        closed        chan struct{}
        closeOnce     sync.Once
        dead          bool
        droppedReplies atomic.Int64
        // v26.11.158: Track all pooledConns so readLoop can check
        // if a pooledConn is closed before sending to its inbox.
        conns []*pooledConn
        // v26.11.216: shortHeaderCIDLen learned from the first connection's
        // Initial SCID length. For Chrome (0-length SCID), this is 0.
        shortHeaderCIDLen atomic.Int32
        // v26.11.217: lastActiveInbox is the inbox of the connection that
        // most recently sent a packet via WriteTo. When a reply arrives with
        // DCID=∅ (Chrome 0-length SCID), we deliver to this inbox instead
        // of using demux[∅] (which would collide across connections).
        lastActiveInbox chan<- readResult
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
        // v26.11.212: onActivity is called when data flows through this conn
        // (both WriteTo and ReadFrom). Set by freedom.Process to update the
        // inbound udpConn's lastActivityTime, preventing clean() from retiring
        // active connections. Without this, clean() sees no activity updates
        // (because BufferedPacketReader and PooledPacketWriter bypass
        // udpConn.Write/Read) and retires connections after sessionIdleTimeout.
        onActivity func()
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
        // v26.11.207: Don't evict the shared socket. With port-only keying,
        // there's only ONE socket for all QUIC traffic. Evicting it kills
        // the source port stability. The socket is wildcard-bound and
        // receives from any IP — it should never be evicted.
        //
        // Only evict if the socket is dead AND refCount == 0 (truly abandoned).
        p.mu.Lock()
        defer p.mu.Unlock()
        for key, sock := range p.sockets {
                sock.mu.Lock()
                isDead := sock.dead && sock.refCount == 0
                sock.mu.Unlock()

                if isDead {
                        sock.MarkStale()
                        delete(p.sockets, key)
                        xrayerrors.LogInfo(context.Background(), "udp_pool: evicted dead socket for ", key)
                }
        }
}

// InvalidateByIP marks all pool sockets to the given IP as stale.
// v26.11.204: Since we now key by port only (not IP), this is a no-op.
// The shared socket handles all IPs — invalidating by IP would kill
// connections to other Google IPs sharing the same socket.
func (p *UDPSocketPool) InvalidateByIP(ip string) {
        // v26.11.204: No-op — pool is keyed by port, not IP.
        // The shared socket handles all Google IPs. DNS rotation doesn't
        // require socket invalidation because the socket is wildcard-bound
        // and receives replies from any source IP.
}

func destKey(dest *stdnet.UDPAddr) string {
        // v26.11.204: Key by PORT ONLY, not by full dest IP:port.
        // This makes ALL QUIC traffic to port 443 share ONE pool socket
        // with ONE source port. Google sees the same source port regardless
        // of which CDN edge IP it is — no path validation, no stall on
        // video switching.
        //
        // The DCID-based demux handles routing replies to the correct
        // connection. The readLoop receives from ALL source IPs on the
        // wildcard-bound socket, parses the DCID, and routes to the correct
        // inbox. This is safe because QUIC DCIDs are globally unique.
        //
        // Previously this was dest.String() which created a separate socket
        // per Google IP. Chrome switches videos → different googlevideo.com
        // subdomain → different IP → different socket → different source
        // port → Google sees connection migration → path validation → stall.
        return fmt.Sprintf(":%d", dest.Port)
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
                // v26.11.206: REMOVED staleness check. With port-only keying, the
                // pool socket is shared across ALL Google IPs. If one connection
                // is idle, the staleness check would mark the shared socket stale,
                // killing ALL connections. The socket is wildcard-bound and receives
                // from any source IP — staleness is irrelevant.
                nowNano := time.Now().UnixNano()
                sock.lastUsed.Store(nowNano)
                sock.mu.Lock()
                sock.refCount++
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
                        conn:          pc,
                        dest:          dest,
                        demux:         make(map[dcidKey]chan<- readResult),
                        demuxSource:   make(map[dcidKey]*stdnet.UDPAddr),
                        closed:        make(chan struct{}),
                        lastUsed:      atomic.Int64{},
                        lastReplyTime: atomic.Int64{},
                }
                xrayerrors.LogInfo(context.Background(), "udp_pool: NEW socket created for key=", key, " localAddr=", pc.LocalAddr())

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
        // v26.11.158: Track this pooledConn so readLoop can check IsClosed
        sock.mu.Lock()
        sock.conns = append(sock.conns, conn)
        sock.mu.Unlock()
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

                // v26.11.216: Use shortHeaderCIDLen for short headers instead
                // of the default 8. Chrome uses 0-length SCID, so the server's
                // 1-RTT replies have DCID=∅ (0 bytes). ParseDCID defaults to 8,
                // reading garbage. With shortHeaderCIDLen=0, we read 0 bytes
                // → demux[∅] → matches the 0-length SCID registration.
                var dcid []byte
                if n > 0 && packet[0]&0x80 != 0 {
                        // Long header — DCID length is in the packet
                        dcid, _, err = quic.ParseDCID(packet[:n])
                } else {
                        // Short header — use learned CID length
                        cidLen := int(s.shortHeaderCIDLen.Load())
                        if cidLen < 0 {
                                // Not learned yet — fall back to default
                                cidLen = quic.DefaultShortHeaderCIDLen
                        }
                        // v26.11.216: cidLen can be 0 (Chrome uses 0-length SCID).
                        // Don't fall back to 8 when cidLen=0 — that reads garbage.
                        dcid, _, err = quic.ParseShortHeaderDCIDWithLen(packet[:n], cidLen)
                }
                if err != nil {
                        putPacket(packet)
                        continue
                }
                // v26.10.16-link: zero-alloc dcidKey struct instead of
                // hex.EncodeToString(dcid) which allocated a 16-char string
                // per reply packet.
                dk := makeDCIDKey(dcid)

                // v26.11.215: Debug log for demux lookup
                xrayerrors.LogInfo(context.Background(), "DIAG: readLoop reply dcidLen=", len(dcid),
                        " firstByte=0x", fmt.Sprintf("%02x", packet[0]),
                        " demuxSize=", len(s.demux))

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
                        // v26.11.290: Try 20-byte CID length for short headers.
                        // Google's server SCID is 20 bytes; Chrome uses it as the
                        // 1-RTT DCID. The shortHeaderCIDLen (0 for Chrome) gives
                        // DCID=∅ which falls to lastActiveInbox. But if that missed,
                        // try parsing with length 20 (Google's SCID) — this routes
                        // correctly when the server SCID was registered.
                        if n > 0 && packet[0]&0x80 == 0 && len(packet) > 20 {
                                if altDcid, _, altErr := quic.ParseShortHeaderDCIDWithLen(packet[:n], 20); altErr == nil && len(altDcid) > 0 {
                                        altDk := makeDCIDKey(altDcid)
                                        s.mu.RLock()
                                        if altCh, altOk := s.demux[altDk]; altOk {
                                                ch = altCh
                                                src = s.demuxSource[altDk]
                                                ok = true
                                        }
                                        s.mu.RUnlock()
                                }
                        }
                }
                if !ok {
                        // v26.11.217: If DCID is empty (0-length), use lastActiveInbox
                        // instead of demux[∅]. This avoids collisions when multiple
                        // connections share the pool socket (all Chrome connections
                        // have 0-length SCID → all replies have DCID=∅).
                        if len(dcid) == 0 {
                                s.mu.RLock()
                                li := s.lastActiveInbox
                                s.mu.RUnlock()
                                if li != nil {
                                        ch = li
                                        ok = true
                                }
                        }
                }
                if !ok {
                        // SCID fallback for long headers: server's reply SCID =
                        // client's Initial DCID, which was registered in WriteTo.
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

                // v26.11.290: For long-header replies, register the server's SCID
                // in the demux map. Future 1-RTT packets from Chrome will carry
                // DCID = server SCID, so this enables correct routing via the
                // 20-byte lookup above. Only fires for long headers (low frequency).
                if n > 0 && packet[0]&0x80 != 0 && ch != nil {
                        if scid, _, perr := quic.ParseSCID(packet[:n]); perr == nil && len(scid) > 0 {
                                scidKey := makeDCIDKey(scid)
                                s.mu.Lock()
                                if _, exists := s.demux[scidKey]; !exists {
                                        s.demux[scidKey] = ch
                                        s.demuxSource[scidKey] = src
                                }
                                s.mu.Unlock()
                        }
                }

                // v26.10.21-link: non-blocking send with large channel (256).
                // v26.11.159: Removed IsClosed check — it acquired RLock and
                // iterated ALL conns per packet, blocking RegisterCID (which
                // needs Lock). This delayed CID rotation registration, causing
                // Google's replies with the new DCID to be dropped.
                // The non-blocking send already handles dead conns: if the
                // inbox is full (nobody reading), the packet is dropped (QUIC
                // retransmits). No lock needed.
                sentOk := false
                packetToSend := packet[:n]
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
        // v26.11.216: Register 0-length CIDs too. Chrome uses 0-length SCID.
        // The server's reply has DCID = client's SCID = ∅. We need demux[∅]
        // to route the reply. This is safe because with port-only keying,
        // there's typically one connection per pool socket at handshake time.
        // When a new Initial arrives (different DCID), it overwrites demux[∅].
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
                if scid, _, err := parseQUICSCID(b); err == nil {
                        // v26.11.217: Don't register 0-length SCIDs in demux —
                        // they collide across connections. Instead, set lastActiveInbox
                        // so the readLoop can route DCID=∅ replies to the most recently
                        // active connection.
                        if len(scid) > 0 {
                                c.RegisterCID(scid)
                        }
                        c.socket.shortHeaderCIDLen.Store(int32(len(scid)))
                        // v26.11.217: Update lastActiveInbox on every WriteTo call
                        c.socket.mu.Lock()
                        c.socket.lastActiveInbox = c.inbox
                        c.socket.mu.Unlock()
                }
                // FIX: also register the outgoing DCID. Per RFC 9000 §7.3,
                // the server's reply SCID = client's Initial DCID. For
                // 0-length SCID clients (Chrome/Edge), RegisterCID(scid)
                // is skipped (len==0), so demux has no entry for the
                // connection and the server's reply (DCID=∅) is silently
                // dropped. By registering the DCID, the readLoop's
                // SCID-based fallback can route the reply by looking up
                // demux[serverSCID] = demux[clientDCID].
                if dcid, _, err := quic.ParseDCID(b); err == nil {
                        xrayerrors.LogInfo(context.Background(), "DIAG: WriteTo register DCID len=", len(dcid),
                                " scidLen=", func() int { if s, _, _ := parseQUICSCID(b); s != nil { return len(s) }; return 0 }(),
                                " firstByte=0x", fmt.Sprintf("%02x", b[0]))
                        if len(dcid) > 0 {
                                c.RegisterCID(dcid)
                        }
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
        // v26.11.212: update activity timer
        if c.onActivity != nil {
                c.onActivity()
        }
        return n, err
}

func (c *pooledConn) ReadFrom(p []byte) (int, stdnet.Addr, error) {
        // v26.11.208: Add 30-second timeout. If no reply in 30s, return EOF.
        // This makes BufferedPacketReader's readLoop exit, which makes
        // responseDone return, which makes Process return. Without this,
        // abandoned QUIC connections (Shorts swiping) keep their readLoop
        // alive forever — goroutine leak that stalls new connections.
        timer := time.NewTimer(30 * time.Second)
        defer timer.Stop()
        select {
        case rr, ok := <-c.inbox:
                if !ok {
                        return 0, nil, io.EOF
                }
                n := copy(p, rr.data)
                putPacket(rr.data)
                // v26.11.212: update activity timer
                if c.onActivity != nil {
                        c.onActivity()
                }
                return n, rr.addr, nil
        case <-c.done:
                return 0, nil, io.EOF
        case <-timer.C:
                return 0, nil, io.EOF
        }
}

func (c *pooledConn) IsClosed() bool {
        return c.closed.Load()
}

func (c *pooledConn) Close() error {
        if !c.closed.CompareAndSwap(false, true) {
                return nil
        }
        close(c.done)

        // v26.11.198: DON'T delete DCIDs from the socket's demux map on Close.
        // When Process returns (video switch), pooledConn.Close() fires. If we
        // delete the DCID, Google's in-flight replies for that DCID (retransmissions,
        // ACKs) are silently dropped by readLoop (demux miss). Chrome's QUIC stack
        // never receives ACKs → declares path dead → falls back to TCP after ~25s.
        //
        // Fix: leave the DCID in the demux map as a stale entry. The inbox channel
        // is closed (close(c.done) above), so readLoop's send will panic — but we
        // recover from the panic and silently drop the packet. When a new connection
        // registers the same DCID, the stale entry is overwritten.
        //
        // We still need to release the socket's refCount so the reaper can close
        // it when it's truly unused.
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
        // v26.11.214: Support both QUIC v1 (0xc0) and v2 (0x80) long headers.
        // QUIC v1: bit 7=1 (long header), bit 6=1 (fixed bit)
        // QUIC v2: bit 7=1 (long header), bit 6=0 (fixed bit inverted per RFC 9369)
        // Both have bit 7=1 for long header.
        return b[0]&0x80 != 0
}

// ============================================================
// v26.11.201: BufferedPacketReader — decouples pool inbox from Process
// ============================================================
//
// This is the missing piece from the v196 binary. Without it, when Process
// returns (video switch, CID rotation, timer fires), responseDone stops
// reading from PooledPacketReader → nobody drains pooledConn.inbox → inbox
// fills up (256 cap) → readLoop drops replies (non-blocking send) → Chrome
// never gets ACKs → stall at ~10 seconds.
//
// BufferedPacketReader wraps PooledPacketReader with a readLoop goroutine
// that continuously drains the underlying reader into an internal buffer.
// When Process returns and responseDone stops, the readLoop keeps running —
// Google's replies keep being consumed and buffered. When the goroutine
// restarts and a new Process starts, the new responseDone reads from the
// buffer, getting all the accumulated replies — no stall.
//
// The buffer is a buf.MultiBuffer channel with large capacity (256) to
// absorb bursts of replies during the Process gap.

type BufferedPacketReader struct {
        base    buf.Reader      // underlying PooledPacketReader
        buffer  chan buf.MultiBuffer
        done    chan struct{}
        closed  atomic.Bool
}

func NewBufferedPacketReader(base buf.Reader) *BufferedPacketReader {
        r := &BufferedPacketReader{
                base:   base,
                buffer: make(chan buf.MultiBuffer, 256),
                done:   make(chan struct{}),
        }
        go r.readLoop()
        return r
}

func (r *BufferedPacketReader) readLoop() {
        for {
                select {
                case <-r.done:
                        return
                default:
                }
                mb, err := r.base.ReadMultiBuffer()
                if err != nil {
                        // v26.11.211: Don't push nil mb to buffer on error.
                        // Just exit — the error will be returned by ReadMultiBuffer
                        // on the next call (buffer is empty, r.done is closed).
                        if mb != nil {
                                buf.ReleaseMulti(mb)
                        }
                        return
                }
                if mb == nil || len(mb) == 0 {
                        continue
                }
                select {
                case r.buffer <- mb:
                case <-r.done:
                        buf.ReleaseMulti(mb)
                        return
                default:
                        // Buffer full — drop oldest to make room
                        select {
                        case old := <-r.buffer:
                                buf.ReleaseMulti(old)
                        default:
                        }
                        select {
                        case r.buffer <- mb:
                        case <-r.done:
                                buf.ReleaseMulti(mb)
                                return
                        }
                }
        }
}

func (r *BufferedPacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
        select {
        case mb, ok := <-r.buffer:
                if !ok || len(mb) == 0 {
                        return nil, io.EOF
                }
                return mb, nil
        case <-r.done:
                return nil, io.EOF
        }
}

func (r *BufferedPacketReader) Close() error {
        if !r.closed.CompareAndSwap(false, true) {
                return nil
        }
        close(r.done)
        // Drain and release any buffered packets
        for {
                select {
                case mb := <-r.buffer:
                        if mb != nil {
                                buf.ReleaseMulti(mb)
                        }
                default:
                        return nil
                }
        }
}
