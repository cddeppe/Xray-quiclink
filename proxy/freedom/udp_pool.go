package freedom

import (
        "context"
        "fmt"
        "encoding/binary"
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

// registerQUICPoolCIDs pre-registers the packet's SCID/DCID before sending it
// on the pooled socket. This avoids the race where the server's reply arrives
// before the demux map is populated, leading to a demux miss and the reply
// being silently dropped.
func registerQUICPoolCIDs(c *pooledConn, packet []byte) {
        if c == nil || len(packet) == 0 || packet[0]&0x80 == 0 {
                return
        }
        if scid, _, err := parseQUICSCID(packet); err == nil {
                c.RegisterCID(scid)
        }
        if dcid, _, err := quic.ParseDCID(packet); err == nil {
                c.RegisterCID(dcid)
        }
}

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
        // v26.11.1-link: callback to notify the sticky resolver when a
        // socket is marked stale (CDN edge rotation detected). The resolver
        // proactively refreshes DNS for the stale IP's hostname, so the
        // next request gets the fresh IP without waiting for the TTL.
        onSocketStale func(ip string)

        // v26.11.35-link: source → client SCID cache.
        //
        // When the browser sends a QUIC Initial (long header), the client's
        // SCID (= A) is registered in the current socket's demux. But when
        // DNS rotation sends subsequent short-header packets to a DIFFERENT
        // destination IP, those packets go to a DIFFERENT socket. The server
        // replies from that IP with DCID = A (client's SCID), but the new
        // socket's demux doesn't have A → demux miss → drop → h2 fallback.
        //
        // This cache stores (source IP:port → client's SCID A) when we see
        // a long header. When a short header arrives from the same source,
        // we look up A and register it on the current socket's demux —
        // regardless of which IP the short header is being sent to.
        //
        // TTL: 5 minutes (longer than any QUIC handshake). Lazy expiration
        // on lookup. The cache is keyed by source string ("IP:port").
        sourceSCIDCache    map[string][]byte
        sourceSCIDCacheMu sync.RWMutex
}

type pooledSocket struct {
        mu       sync.RWMutex // v26.10.16-link: RWMutex so readLoop can RLock the demux read
        conn     stdnet.PacketConn
        dest     *stdnet.UDPAddr
        refCount int
        // v26.11.35-link: back-reference to the owning pool, so WriteTo
        // can access the pool's source → SCID cache via c.socket.pool.
        pool *UDPSocketPool
        // v26.11.37-link: shortHeaderCIDLen is the DCID length used by
        // short-header (1-RTT) packets on this socket. Learned from the
        // client's Initial SCID length. The readLoop uses this to parse
        // short-header DCIDs correctly — the global DefaultShortHeaderCIDLen
        // (8) is wrong for clients that use shorter SCIDs (e.g. 3 bytes).
        // This is atomic for lock-free reads in the readLoop hot path.
        shortHeaderCIDLen atomic.Int32
        // v26.10.43-link (audit P5): atomic timestamps to avoid
        // mutex contention on the readLoop hot path.
        lastUsed      atomic.Int64                  // UnixNano
        lastReplyTime atomic.Int64                  // UnixNano
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
        n    int // v26.11.23: actual bytes (data may be a 65535-byte pooled buffer)
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
        // v26.11.35-link: source is the browser's source IP:port.
        // Used to look up the source → SCID cache so we can register
        // the cached client SCID (A) on this socket's demux when
        // processing short-header packets.
        source *stdnet.UDPAddr
}

func NewUDPSocketPool(staleness, idle, unused time.Duration, sockopt *internet.SocketConfig) *UDPSocketPool {
        p := &UDPSocketPool{
                sockets:          make(map[string]*pooledSocket),
                stalenessTimeout: staleness,
                idleTimeout:      idle,
                unusedTimeout:    unused,
                sockopt:          sockopt,
                sourceSCIDCache:  make(map[string][]byte),
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

func (p *UDPSocketPool) Acquire(dest *stdnet.UDPAddr, source *stdnet.UDPAddr) (*pooledConn, error) {
        key := destKey(dest)

        p.mu.Lock()
        sock, ok := p.sockets[key]
        if ok && (sock.IsClosed() || sock.IsDead()) {
                delete(p.sockets, key)
                ok = false
        }
        if ok {
                // STALENESS CHECK: If the socket hasn't received a reply in
                // stalenessTimeout seconds, assume the CDN edge rotated and
                // is silently dropping packets. Mark it dead and force the
                // creation of a fresh socket for this request.
                //
                // v26.11.1-link: reduced default stalenessTimeout from 300s
                // to 30s (see freedom.go). 300s was too long — when a CDN edge
                // rotates, the phone retries for up to 5 minutes before the pool considers
                // the socket stale. 30s catches dead edges much faster, reducing stall
                // duration from ~42s to ~15s.
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
                        // v26.11.1-link: notify sticky resolver that this IP
                        // is stale, so it proactively refreshes DNS instead
                        // of waiting for the TTL to expire. This closes the
                        // gap between "socket detected stale" and "resolver
                        // gets new IP" — without this, the resolver still
                        // returns the old (stale) IP for up to TTL seconds.
                        if p.onSocketStale != nil {
                                p.onSocketStale(dest.IP.String())
                        }
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
                        pool:          p, // v26.11.35-link: back-ref for source → SCID cache
                        demux:         make(map[dcidKey]chan<- readResult),
                        closed:        make(chan struct{}),
                        lastUsed:      atomic.Int64{},
                        lastReplyTime: atomic.Int64{},
                }
                // v26.11.38-link: default to -1 (unset). When we see the
                // client's Initial SCID, we'll learn the actual length
                // (0 for Chrome/Edge, 3 for some clients, 8 for Firefox).
                // -1 means "not learned yet" — the readLoop falls back to
                // DefaultShortHeaderCIDLen (8) until the Initial arrives.
                sock.shortHeaderCIDLen.Store(-1)

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

        inbox := make(chan readResult, 256)
        conn := &pooledConn{
                socket:    sock,
                inbox:     inbox,
                done:      make(chan struct{}),
                scidsDCID: make(map[dcidKey]bool),
                source:    source,
        }
        xrayerrors.LogWarning(context.Background(), "DIAG: Acquire dest=", dest.String(), " source=", func() string { if source != nil { return source.String() }; return "(nil)" }(), " socket=", fmt.Sprintf("%p", sock), " conn=", fmt.Sprintf("%p", conn))
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

                // v26.11.19-link: send ICMP "Fragmentation Needed" to the
                // server when the response exceeds the path MTU. QUIC
                // servers coalesce Initial+Handshake+0-RTT into one UDP
                // datagram up to 65535 bytes via GSO. We can't forward this
                // to the browser (path MTU is 1500, max UDP payload is
                // 65507). IP fragmentation is unreliable. ICMP Type 3
                // Code 4 hints the server to reduce its packet size.
                //
                // v26.11.28-link: keep the ICMP send (harmless if server
                // ignores it; the SplitCoalesced path in worker.go is the
                // real fix). Silent — the per-packet warning was too noisy.
                if n > 1250 {
                        sendICMPFragmentationNeeded(s.dest, 1250)
                }

                // v26.11.37-link: parse DCID. For short headers (1-RTT),
                // use the socket's learned shortHeaderCIDLen (from the
                // client's Initial SCID) instead of the global default (8).
                // The server's short-header DCID = client's SCID, so the
                // length must match. If the client uses a 3-byte SCID, the
                // server uses a 3-byte DCID — parsing it as 8 bytes produces
                // a wrong key (3 bytes of DCID + 5 bytes of packet number).
                var dcid []byte
                if packet[0]&0x80 != 0 {
                        // Long header — DCID length is encoded in the packet
                        dcid, _, err = quic.ParseDCID(packet[:n])
                } else {
                        // Short header — use the socket's learned CID length
                        cidLen := int(s.shortHeaderCIDLen.Load())
                        if cidLen < 0 {
                                // v26.11.38-link: not learned yet (Initial not
                                // processed). Fall back to default 8.
                                cidLen = quic.DefaultShortHeaderCIDLen
                        }
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
                        // v26.10.29-link: silent drop on demux miss.
                        //
                        // v26.10.27 tried broadcast-on-miss (sending to ALL
                        // sessions on the socket) but this caused cascading
                        // stalls — flooding wrong sessions' inbox channels
                        // with non-matching packets, filling the 256-cap
                        // channels with garbage so the real reply was dropped.
                        //
                        // The silent drop is correct: NEW_CONNECTION_ID
                        // rotation is handled by the inbound worker's
                        // tryQUICMigration (source IP:port → connection mapping).
                        // The pool's demux is only for the reply path. If a
                        // reply arrives with an unknown DCID, it's either a
                        // NEW_CONNECTION_ID reply (rare) or a stray packet
                        // from a different connection sharing the CDN edge.
                        // Dropping is safer than broadcasting.
                        //
                        // v26.11.5-diag: log demux misses at warning level
                        // so we can see when the response is being dropped.
                        // If this fires for every QUIC handshake, the DCID
                        // registration is broken.
                        putPacket(packet)
                        continue
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
                xrayerrors.LogWarning(context.Background(), "DIAG: readLoop demux HIT dcid=", fmt.Sprintf("%x", dcid), " len=", len(dcid), " from=", addr.String())
                sentOk := false
                inboxClosed := false
                func() {
                        defer func() {
                                if r := recover(); r != nil {
                                        // Inbox is closed — mark for cleanup.
                                        inboxClosed = true
                                        _ = r
                                }
                        }()
                        select {
                        case ch <- readResult{data: packet, n: n, addr: addr}:
                                sentOk = true
                        default:
                                s.droppedReplies.Add(1)
                        }
                }()
                if !sentOk {
                        putPacket(packet)
                        // v26.11.41-link: if the inbox was closed, DELETE the
                        // stale demux entry. Without this, the stale entry
                        // stays forever and ALL future replies with this DCID
                        // are dropped (sent to the closed inbox → panic → drop).
                        // With YouTube opening 5+ concurrent QUIC connections
                        // from the same port, stale entries accumulate and
                        // freeze all video playback.
                        // Deleting the entry lets the next Initial from the
                        // browser re-register the DCID on a new live inbox.
                        if inboxClosed {
                                s.mu.Lock()
                                if existing, ok := s.demux[dk]; ok && existing == ch {
                                        delete(s.demux, dk)
                                }
                                s.mu.Unlock()
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
        // v26.11.7-link: register 0-length CIDs too. Chrome/Edge send a
        // 0-length SCID in their QUIC Initial. The server's Initial response
        // uses the client's SCID as its DCID — which is also 0-length. If we
        // skip 0-length CIDs (the old `if len(cid) == 0 { return }`), the
        // server's response is never registered in the demux map, and the
        // readLoop silently drops it. The QUIC handshake fails and the
        // browser falls back to TCP.
        //
        // makeDCIDKey with len=0 creates a key with len=0 and an empty cid
        // array. This is a valid map key — it just represents "any 0-length
        // DCID". Since all 0-length SCID connections share the same key,
        // they'll all map to the same inbox. This is correct for 0-length
        // SCID — there's only one "connection" per 0-length SCID because
        // the server can't distinguish between different 0-length SCID
        // connections (they all look the same on the wire).
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
                c.mu.Lock()
                if c.closed.Load() {
                        c.mu.Unlock()
                        return
                }
                c.socket.mu.Lock()
                c.socket.demux[dk] = c.inbox
                c.socket.mu.Unlock()
                c.mu.Unlock()
        } else {
        }
}
func (c *pooledConn) WriteTo(b []byte, addr stdnet.Addr) (int, error) {
        // v26.10.15-link: use atomic.Bool for closed check (25x faster
        // than mutex acquire+release on the hot path).
        if c.closed.Load() {
                return 0, io.EOF
        }

        // v26.11.30-link: pre-register QUIC SCID/DCID before writing to the socket.
        // If we wait until after WriteTo, the server can reply before the demux map is
        // populated and the reply is silently dropped as a demux miss. This was the
        // actual H3 failure mode for quic.nginx.org / cloudflare-quic.com.
        registerQUICPoolCIDs(c, b)

        // v26.10.15-link: only parse SCID for long headers (Initial,
        // 0-RTT, Handshake). Short headers (1-RTT, bit 7 = 0) don't
        // carry SCID length info, and we've already registered the SCID
        // during the handshake. This skips the parse + hex encode +
        // mutex acquire for 99% of packets in a long-lived QUIC
        // connection (which are 1-RTT).
        //
        // v26.11.7-link: register 0-length SCIDs too. Chrome/Edge send
        // a 0-length SCID. The server's Initial response uses the
        // client's SCID as its DCID — also 0-length. If we skip
        // len(scid) > 0, the 0-length SCID is never registered, and
        // the server's 0-length DCID response can't be demuxed.
        if len(b) > 0 && b[0]&0x80 != 0 {
                xrayerrors.LogWarning(context.Background(), "DIAG: WriteTo LONG conn=", fmt.Sprintf("%p", c), " socket=", fmt.Sprintf("%p", c.socket), " firstByte=", fmt.Sprintf("0x%02x", b[0]))
                if scid, _, err := parseQUICSCID(b); err == nil {
                        xrayerrors.LogWarning(context.Background(), "DIAG: WriteTo LONG SCID=", fmt.Sprintf("%x", scid), " len=", len(scid))
                        c.RegisterCID(scid)
                        // v26.11.37-link: learn the short-header DCID length
                        // from the client's SCID. The server's short-header
                        // DCID = client's SCID, so the length must match.
                        // v26.11.38-link: also set for 0-length SCIDs (Chrome/Edge)
                        // — the readLoop needs to parse 0 bytes, not the default 8.
                        old := c.socket.shortHeaderCIDLen.Swap(int32(len(scid)))
                        xrayerrors.LogWarning(context.Background(), "DIAG: shortHeaderCIDLen SET socket=", fmt.Sprintf("%p", c.socket), " old=", old, " new=", len(scid))
                        // v26.11.35-link: cache (source → client SCID A) so that
                        // subsequent short-header packets from the same source can
                        // re-register A on whatever socket they go to (the DNS
                        // may rotate to a different IP → different socket).
                        // v26.11.38-link: also cache 0-length SCIDs (Chrome/Edge).
                        if c.source != nil {
                                c.socket.pool.sourceSCIDCacheMu.Lock()
                                c.socket.pool.sourceSCIDCache[c.source.String()] = scid
                                cl := len(c.socket.pool.sourceSCIDCache)
                                c.socket.pool.sourceSCIDCacheMu.Unlock()
                                xrayerrors.LogWarning(context.Background(), "DIAG: sourceSCIDCache SET [", c.source.String(), "] = ", fmt.Sprintf("%x", scid), " size=", cl)
                        }
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
                // v26.11.7-link: also register 0-length DCIDs (same fix as SCID)
                if dcid, _, err := quic.ParseDCID(b); err == nil {
                        c.RegisterCID(dcid)
                }
        } else if len(b) > 0 && b[0]&0x40 != 0 {
                // v26.11.33-link: short header (1-RTT) — register the DCID.
                //
                // Each UDP packet from the browser triggers a SEPARATE
                // freedom.Process call, each creating a new pooledConn with
                // its own inbox. The Initial's pooledConn registers the DCID
                // → demux[dcid] = inbox1. When that freedom.Process returns
                // (input pipe exhausted, timer fires), pooledConn1.Close()
                // REMOVES the DCID from the demux map (udp_pool.go:730-733).
                // Subsequent short-header packets create new pooledConns but
                // don't re-register the DCID → all server replies are demux
                // misses → dropped → QUIC handshake fails → h2 fallback.
                //
                // Fix: register the DCID from short headers too. Each new
                // pooledConn that sends a short header re-registers demux[dcid]
                // → its own inbox. RegisterCID is idempotent per-conn (checks
                // scidsDCID), so this only fires once per pooledConn. The
                // demux map always points to the latest pooledConn.inbox for
                // this DCID, so the server's replies always reach a live
                // responseDone goroutine.
                //
                // Note: ParseDCID for short headers uses
                // DefaultShortHeaderCIDLen (8 bytes). This matches Firefox
                // and Chrome (which use 8-byte SCIDs, echoed by the server
                // as 8-byte DCIDs in short headers). If a client uses 0-length
                // SCID, the long-header path above already handles it.
                if dcid, _, err := quic.ParseDCID(b); err == nil {
                        c.RegisterCID(dcid)
                }

                // v26.11.35-link: THE REAL FIX for demux miss.
                //
                // The short header's DCID is B' (server's SCID), NOT A
                // (client's SCID). The server replies with DCID = A. So
                // registering B' is useless — the server never replies with B'.
                //
                // The problem: when DNS rotation sends this short header to a
                // DIFFERENT IP than the Initial, it goes to a DIFFERENT socket.
                // The Initial registered A on socket1, but the reply arrives
                // at socket2 (which only has B'). demux miss → drop → h2.
                //
                // The fix: look up the cached client SCID (A) for this source
                // IP:port (cached when the Initial was processed), and register
                // A on THIS socket's demux → demux[A] = this inbox. The server's
                // reply with DCID = A will now hit on this socket.
                if c.source != nil {
                        c.socket.pool.sourceSCIDCacheMu.RLock()
                        cachedA, ok := c.socket.pool.sourceSCIDCache[c.source.String()]
                        cl := len(c.socket.pool.sourceSCIDCache)
                        c.socket.pool.sourceSCIDCacheMu.RUnlock()
                        if ok {
                                xrayerrors.LogWarning(context.Background(), "DIAG: sourceSCIDCache HIT [", c.source.String(), "] = ", fmt.Sprintf("%x", cachedA), " size=", cl)
                                c.RegisterCID(cachedA)
                        } else {
                                xrayerrors.LogWarning(context.Background(), "DIAG: sourceSCIDCache MISS [", c.source.String(), "] size=", cl)
                        }
                } else {
                        xrayerrors.LogWarning(context.Background(), "DIAG: sourceSCIDCache SKIPPED nil source")
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
        return n, err
}

func (c *pooledConn) ReadFrom(p []byte) (int, stdnet.Addr, error) {
        select {
        case rr, ok := <-c.inbox:
                if !ok {
                        return 0, nil, io.EOF
                }
                n := copy(p, rr.data[:rr.n])
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
        // CAS ensures only one caller proceeds to close(c.done).
        if !c.closed.CompareAndSwap(false, true) {
                return nil
        }
        close(c.done)

        xrayerrors.LogWarning(context.Background(), "DIAG: Close conn=", fmt.Sprintf("%p", c), " socket=", fmt.Sprintf("%p", c.socket), " scidsDCID=", len(c.scidsDCID))
        // v26.11.34-link: DO NOT remove the DCID from the demux map on Close.
        //
        // The previous code (v26.10.15 through v26.11.33) removed the
        // DCID entries from socket.demux when the pooledConn closed:
        //
        //   for dk := range c.scidsDCID {
        //       if existing, ok := c.socket.demux[dk]; ok && existing == c.inbox {
        //           delete(c.socket.demux, dk)
        //       }
        //   }
        //
        // This was the ROOT CAUSE of the persistent demux miss and h2
        // fallback. Here's why:
        //
        // Each UDP packet from the browser triggers a SEPARATE
        // freedom.Process call, each creating a new pooledConn with its
        // own inbox. The Initial's pooledConn registers the client's SCID
        // (= A) as a DCID in the demux map → demux[A] = inbox1. When that
        // freedom.Process returns (input pipe exhausted, timer fires),
        // pooledConn1.Close() REMOVES A from the demux map. Subsequent
        // short-header packets create new pooledConns, but short headers
        // don't carry the client's SCID (A) — they carry the server's
        // SCID (B') as their DCID. So A is never re-registered. All server
        // replies (which use DCID = A, the client's SCID) → demux miss →
        // dropped → QUIC handshake fails → browser falls back to h2.
        //
        // The fix: don't remove from demux on Close. Let the inbox
        // channel be closed (close(c.done) above). The readLoop's
        // non-blocking send to a closed inbox will fail — but we need
        // to handle that gracefully (see readLoop's send logic).
        //
        // New pooledConns that register the same DCID will OVERWRITE the
        // demux entry, pointing it to their own (live) inbox. This is
        // the correct behavior: the latest pooledConn for a given DCID
        // should receive the replies.
        //
        // Stale demux entries (pointing to closed inboxes) are cleaned
        // up lazily by the readLoop when a send fails, or by the socket
        // reaper when the socket is evicted.
        //
        // Test: TestDemuxLifecycleWithFix in demux_test.go verifies this.
        //
        // scidsDCID is kept for potential future use (introspection)
        // but is no longer used for demux cleanup.

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
        // v26.11.30-link: read ONE datagram from the inbox and return it as-is.
        //
        // v26.11.25 added a software reassembly loop here, based on the
        // assumption that the pool socket receives coalesced QUIC datagrams
        // as individual IP fragments. That assumption was wrong: IP
        // fragments are kernel-reassembled BEFORE socket delivery. The
        // pool socket already receives the full coalesced datagram (up to
        // 65535 bytes) in a single ReadFrom.
        //
        // The software reassembly was therefore:
        //   - Redundant for the IP-fragment case (kernel already reassembled)
        //   - Actively harmful for the 1-RTT case: when two 1-RTT short-header
        //     packets are queued back-to-back in the inbox (common in
        //     long-lived QUIC like YouTube streaming), the loop concatenated
        //     them. SplitCoalesced then saw the first short header, treated
        //     it as "extends to end of datagram" (RFC 9000 §17.3 has no
        //     Length field), and returned ONE offset covering both packets.
        //     udpConn.Write sent the combined buffer as one UDP datagram.
        //     Browser AEAD decryption failed, dropped the packet, QUIC
        //     stalled → h2 fallback.
        //
        // Removing the loop. SplitCoalesced in worker.go handles coalesced
        // datagrams on its own. Each individual QUIC packet is sent as its
        // own UDP datagram to the browser (RFC 9000 §12.2 compliant).
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

        // v26.11.19-link / v26.11.25-link: send ICMP "Fragmentation Needed"
        // to the server when the datagram exceeds the path MTU. Best-effort
        // — many servers ignore it for the Initial (RFC 9000 §8.1
        // anti-amplification requires Initial + Handshake in one coalesced
        // datagram). SplitCoalesced is the real fix; ICMP is a nudge.
        if n > 1250 && b.UDP != nil {
                serverIP := b.UDP.Address.IP()
                sendICMPFragmentationNeeded(&stdnet.UDPAddr{IP: serverIP, Port: 443}, 1250)
        }

        return buf.MultiBuffer{b}, nil
}

// v26.11.28-link: splitCoalescedQUIC and its readQUICVarint helper removed.
// The live split logic is now quic.SplitCoalesced in
// common/protocol/quic/split.go, called from
// app/proxyman/inbound/worker.go udpConn.Write. The old in-pool splitter
// was never called (dead code from an earlier iteration that used
// buf.MultiBuffer; the live path uses byte offsets to avoid allocations).

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

// v26.11.32-link: isQUICPacket matches BOTH long headers (Initial,
// 0-RTT, Handshake, Retry) AND short headers (1-RTT). The QUIC Fixed
// Bit (0x40) is set in both forms. Version Negotiation has the Fixed
// Bit cleared (per RFC 9000 §17.2.1) so it's excluded — but VN is
// rare and handled separately.
//
// This is used by freedom.go to decide whether to route a UDP packet
// through the pool (DCID demux) or per-session. Previously only LONG
// headers were routed to the pool; short headers (1-RTT, the bulk of
// a long-lived QUIC connection) went through per-session, which uses
// a DIFFERENT socket with a different source port. The server saw
// packets from two source ports and couldn't maintain the connection
// — the pool socket received replies with unregistered DCIDs (demux
// miss → drop) and the QUIC handshake failed → browser fell back to h2.
//
// Routing ALL QUIC packets through the pool ensures the server sees
// a consistent source port. The pool's demux for short-header replies
// uses the DCID = client's SCID (registered during the Initial), so
// the demux hits correctly for 8-byte SCIDs (Firefox default).
func isQUICPacket(b []byte) bool {
        if len(b) < 1 {
                return false
        }
        // Long header: bit 7 = 1, bit 6 = 1 (Fixed Bit)
        // Short header: bit 7 = 0, bit 6 = 1 (Fixed Bit)
        // Both have bit 6 set. VN has bit 6 = 0.
        return b[0]&0x40 != 0
}

// v26.11.19-link: sendICMPFragmentationNeeded sends an ICMP
// "Destination Unreachable - Fragmentation Needed" (Type 3, Code 4)
// to the server. This tells the server's QUIC stack to reduce its
// UDP payload size to fit within the path MTU. The server will
// then send the Handshake in smaller, non-coalesced packets.
//
// This is what routers do when a packet is too large to forward.
// We're doing the same: the proxy can't forward the large coalesced
// datagram to the browser (path MTU 1500), so we tell the server
// to use smaller packets.
//
// ICMP format (RFC 792):
//
//      Type: 3 (Destination Unreachable)
//      Code: 4 (Fragmentation Needed)
//      Checksum: 16-bit ones-complement sum
//      Unused: 4 bytes (0)
//      Next-hop MTU: 2 bytes
//      Original packet: IP header + 8 bytes of original datagram
func sendICMPFragmentationNeeded(dest *stdnet.UDPAddr, nextHopMTU int) {
        destIP := dest.IP
        if destIP == nil {
                return
        }

        // Create a raw ICMP socket
        fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
        if err != nil {
                // Likely no CAP_NET_RAW — silently skip
                return
        }
        defer syscall.Close(fd)

        // Build the ICMP packet
        // Type 3, Code 4, Checksum, Unused (4 bytes), Next-hop MTU (2 bytes)
        // + original IP header (20 bytes) + 8 bytes of original payload
        icmp := make([]byte, 8+20+8) // 36 bytes

        icmp[0] = 3 // Type: Destination Unreachable
        icmp[1] = 4 // Code: Fragmentation Needed
        icmp[2] = 0 // Checksum high
        icmp[3] = 0 // Checksum low
        // Unused (4 bytes): already 0
        binary.BigEndian.PutUint16(icmp[6:8], uint16(nextHopMTU))

        // Original IP header (simplified — we don't have the real one)
        // The server's QUIC stack uses this to identify the connection.
        // Include the server's IP as destination and the local IP as source.
        ipHeader := icmp[8:28]
        ipHeader[0] = 0x45             // Version 4, IHL 5
        ipHeader[1] = 0                // DSCP/ECN
        totalLen := uint16(20 + 8 + 8) // IP + UDP + 8 bytes payload
        binary.BigEndian.PutUint16(ipHeader[2:4], totalLen)
        ipHeader[4] = 0 // Identification
        ipHeader[5] = 0
        ipHeader[6] = 0x40 // DF flag set (Fragmentation Needed requires DF)
        ipHeader[7] = 0
        ipHeader[8] = 64 // TTL
        ipHeader[9] = 17 // Protocol: UDP
        // Checksum: 0 (we don't need to compute IP checksum for ICMP to work)
        // Source IP: our IP (the proxy)
        if v4 := destIP.To4(); v4 != nil {
                // Use 0.0.0.0 as source — the kernel will fill in the real source
        }
        // Destination IP: the server
        if v4 := destIP.To4(); v4 != nil {
                copy(ipHeader[16:20], v4)
        }

        // 8 bytes of original payload (UDP header)
        udpHeader := icmp[28:36]
        // Source port: the pool socket's local port (we don't know it, use 0)
        binary.BigEndian.PutUint16(udpHeader[0:2], 0)
        // Destination port: 443
        binary.BigEndian.PutUint16(udpHeader[2:4], uint16(dest.Port))

        // Compute ICMP checksum (ones-complement sum)
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

        // Send to the server
        var addr syscall.SockaddrInet4
        if v4 := destIP.To4(); v4 != nil {
                copy(addr.Addr[:], v4)
        } else {
                return
        }
        err = syscall.Sendto(fd, icmp, 0, &addr)
        if err != nil {
                xrayerrors.LogInfo(context.Background(), "udp_pool: ICMP send failed: ", err)
        } else {
                xrayerrors.LogWarning(context.Background(), "udp_pool: sent ICMP Fragmentation Needed to ", destIP, " mtu=", nextHopMTU)
        }
}
