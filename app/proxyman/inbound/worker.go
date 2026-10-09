package inbound

import (
        "context"
        "encoding/hex"
        stdnet "net"
        "os"
        "sync"

        "github.com/xtls/xray-core/common/protocol/quic"
        "sync/atomic"
        "time"

        "github.com/xtls/xray-core/common"
        "github.com/xtls/xray-core/common/buf"
        c "github.com/xtls/xray-core/common/ctx"
        "github.com/xtls/xray-core/common/errors"
        "github.com/xtls/xray-core/common/net"
        "github.com/xtls/xray-core/common/serial"
        "github.com/xtls/xray-core/common/session"
        "github.com/xtls/xray-core/common/signal/done"
        "github.com/xtls/xray-core/common/task"
        "github.com/xtls/xray-core/features/routing"
        "github.com/xtls/xray-core/features/stats"
        "github.com/xtls/xray-core/proxy"
        "github.com/xtls/xray-core/proxy/freedom/udptimeout"
        hysteria_proxy "github.com/xtls/xray-core/proxy/hysteria"
        "github.com/xtls/xray-core/transport/internet"
        "github.com/xtls/xray-core/transport/internet/hysteria"
        "github.com/xtls/xray-core/transport/internet/stat"
        "github.com/xtls/xray-core/transport/internet/tcp"
        "github.com/xtls/xray-core/transport/internet/udp"
        "github.com/xtls/xray-core/transport/pipe"
)

type worker interface {
        Start() error
        Close() error
        Port() net.Port
        Proxy() proxy.Inbound
}

// v26.11.135: dropQUICData controls whether QUIC 1-RTT (short header)
// packets are dropped after the handshake. This causes Chrome to detect
// QUIC loss and fall back to TCP quickly (~200ms), while still allowing
// the QUIC handshake to complete (for snappy 0-RTT navigation).
//
// Enabled via config: destOverride: ["quic-fallback"]
// (also via env var: XRAY_QUIC_FALLBACK=1 for backwards compat)
var dropQUICData = os.Getenv("XRAY_QUIC_FALLBACK") != ""

// v26.11.140: dropQUICAll controls whether ALL QUIC packets are dropped
// silently (no ICMP, no reply). This replicates the C3 bug behavior:
// Chrome sends QUIC, gets silence (not port-unreachable), and Chrome's
// connection racing starts TCP in parallel. This avoids the 1-second
// delay that occurs with destOverride: ["tls"] (which sends ICMP).
//
// Enabled via config: destOverride: ["quic-drop"]
var dropQUICAll = false

// SetQUICFallback enables/disables QUIC fallback mode at runtime.
func SetQUICFallback(enable bool) {
        dropQUICData = enable
}

// SetQUICDrop enables/disables QUIC drop mode at runtime.
func SetQUICDrop(enable bool) {
        dropQUICAll = enable
}

type tcpWorker struct {
        address         net.Address
        port            net.Port
        proxy           proxy.Inbound
        stream          *internet.MemoryStreamConfig
        recvOrigDest    bool
        tag             string
        dispatcher      routing.Dispatcher
        sniffingRequest session.SniffingRequest
        uplinkCounter   stats.Counter
        downlinkCounter stats.Counter

        hub internet.Listener

        ctx context.Context
}

func getTProxyType(s *internet.MemoryStreamConfig) internet.SocketConfig_TProxyMode {
        if s == nil || s.SocketSettings == nil {
                return internet.SocketConfig_Off
        }
        return s.SocketSettings.Tproxy
}

func (w *tcpWorker) callback(conn stat.Connection) {
        ctx, cancel := context.WithCancel(w.ctx)
        sid := session.NewID()
        ctx = c.ContextWithID(ctx, sid)

        outbounds := []*session.Outbound{{}}
        if w.recvOrigDest {
                var dest net.Destination
                switch getTProxyType(w.stream) {
                case internet.SocketConfig_Redirect:
                        d, err := tcp.GetOriginalDestination(conn)
                        if err != nil {
                                errors.LogInfoInner(ctx, err, "failed to get original destination")
                        } else {
                                dest = d
                        }
                case internet.SocketConfig_TProxy:
                        dest = net.DestinationFromAddr(conn.LocalAddr())
                }

                if dest.IsValid() {
                        // Check if try to connect to this inbound itself (can cause loopback)
                        var isLoopBack bool
                        if w.address == net.AnyIP || w.address == net.AnyIPv6 {
                                if dest.Port.Value() == w.port.Value() && IsLocal(dest.Address.IP()) {
                                        isLoopBack = true
                                }
                        } else {
                                if w.hub.Addr().String() == dest.NetAddr() {
                                        isLoopBack = true
                                }
                        }
                        if isLoopBack {
                                cancel()
                                conn.Close()
                                errors.LogError(ctx, errors.New("loopback connection detected"))
                                return
                        }
                        outbounds[0].Target = dest
                }
        }
        ctx = session.ContextWithOutbounds(ctx, outbounds)

        if w.uplinkCounter != nil || w.downlinkCounter != nil {
                conn = &stat.CounterConnection{
                        Connection:   conn,
                        ReadCounter:  w.uplinkCounter,
                        WriteCounter: w.downlinkCounter,
                }
        }
        ctx = session.ContextWithInbound(ctx, &session.Inbound{
                Source:  net.DestinationFromAddr(conn.RemoteAddr()),
                Local:   net.DestinationFromAddr(conn.LocalAddr()),
                Gateway: net.TCPDestination(w.address, w.port),
                Tag:     w.tag,
                Conn:    conn,
        })

        content := new(session.Content)
        content.SniffingRequest = w.sniffingRequest
        ctx = session.ContextWithContent(ctx, content)

        if err := w.proxy.Process(ctx, net.Network_TCP, conn, w.dispatcher); err != nil {
                errors.LogInfoInner(ctx, err, "connection ends")
        }
        cancel()
        conn.Close()
}

func (w *tcpWorker) Proxy() proxy.Inbound {
        return w.proxy
}

func (w *tcpWorker) Start() error {
        ctx := context.Background()

        if v, ok := w.proxy.(*hysteria_proxy.Server); ok {
                ctx = hysteria.ContextWithValidator(ctx, v.HysteriaInboundValidator())
        }

        hub, err := internet.ListenTCP(ctx, w.address, w.port, w.stream, func(conn stat.Connection) {
                go w.callback(conn)
        })
        if err != nil {
                return errors.New("failed to listen TCP on ", w.port).Base(err)
        }
        w.hub = hub
        return nil
}

func (w *tcpWorker) Close() error {
        var errs []interface{}
        if w.hub != nil {
                if err := common.Close(w.hub); err != nil {
                        errs = append(errs, err)
                }
                if err := common.Close(w.proxy); err != nil {
                        errs = append(errs, err)
                }
        }
        if len(errs) > 0 {
                return errors.New("failed to close all resources").Base(errors.New(serial.Concat(errs...)))
        }

        return nil
}

func (w *tcpWorker) Port() net.Port {
        return w.port
}

type udpConn struct {
        lastActivityTime int64 // in seconds
        reader           buf.Reader
        writer           buf.Writer
        output           func([]byte) (int, error)
        remote           net.Addr
        local            net.Addr
        done             *done.Instance
        uplink           stats.Counter
        downlink         stats.Counter
        inactive         bool
        cancel           context.CancelFunc
        src              *net.Destination // pointer for migration
        dcid             []byte           // QUIC DCID, nil for non-QUIC
        // v26.11.117: Callback to register server SCID when seen in reply.
        // Set by freedom.Process when pool is OFF, so the per-session reader
        // can learn the server's SCID and register it in dcidIndex.
        registerServerCID func([]byte)
}

func (c *udpConn) setInactive() {
        c.inactive = true
}

func (c *udpConn) updateActivity() {
        atomic.StoreInt64(&c.lastActivityTime, time.Now().Unix())
}

// v26.11.117: RegisterServerSCID is called by freedom's reader wrapper
// when it detects a long-header reply from Google. The server's SCID
// is registered in dcidIndex so subsequent 1-RTT short headers (which
// carry DCID=server_SCID) can be routed to the correct conn.
func (c *udpConn) RegisterServerSCID(serverSCID []byte) {
        if c.registerServerCID != nil {
                c.registerServerCID(serverSCID)
        }
}

// ReadMultiBuffer implements buf.Reader
func (c *udpConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
        mb, err := c.reader.ReadMultiBuffer()
        if err != nil {
                return nil, err
        }
        c.updateActivity()

        if c.uplink != nil {
                c.uplink.Add(int64(mb.Len()))
        }

        return mb, nil
}

func (c *udpConn) Read(buf []byte) (int, error) {
        panic("not implemented")
}

// Write implements io.Writer.
func (c *udpConn) Write(buf []byte) (int, error) {
        // v26.11.135: In QUIC fallback mode, drop 1-RTT (short header) replies
        // too — so Chrome doesn't receive any QUIC data and falls back to TCP.
        if dropQUICData && len(buf) > 0 && buf[0]&0x80 == 0 {
                // Short header (1-RTT) — drop it
                return len(buf), nil
        }
        // v26.11.139: No SplitCoalesced — forward as ONE UDP datagram (testing)
        n, err := c.output(buf)
        if c.downlink != nil {
                c.downlink.Add(int64(n))
        }
        if err == nil {
                c.updateActivity()
        }
        return n, err
}

func (c *udpConn) Close() error {
        if c.cancel != nil {
                c.cancel()
        }
        common.Must(c.done.Close())
        common.Must(common.Close(c.writer))
        return nil
}

func (c *udpConn) RemoteAddr() net.Addr {
        return c.remote
}

func (c *udpConn) LocalAddr() net.Addr {
        return c.local
}

func (*udpConn) SetDeadline(time.Time) error {
        return nil
}

func (*udpConn) SetReadDeadline(time.Time) error {
        return nil
}

func (*udpConn) SetWriteDeadline(time.Time) error {
        return nil
}

type connID struct {
        src    net.Destination
        dest   net.Destination
        srcKey srcKey // v26.10.16-link: precomputed for zero-alloc map lookups
}

// v26.10.16-link: srcKey is a zero-allocation map key for
// source IP:port lookups. Replaces id.src.String() which
// triggered 4 allocations per call (IP.String + Port.String +
// two string concats). The struct is 18 bytes (16 IP + 2 port),
// comparable, and hashable — Go's map uses it directly.
//
// IPv4 addresses are stored in IPv4-in-IPv6 mapped form
// (::ffff:a.b.c.d) so that comparisons between IPv4 and IPv6
// sources never accidentally collide.
type srcKey struct {
        ip   [16]byte
        port uint16
}

// makeSrcKey computes a srcKey from a net.Destination. Called
// once per packet in callback(); the result is stored in
// connID and reused by tryQUICMigration, recordSrc, removeConn,
// and clean() — zero string allocations on the inbound path.
func makeSrcKey(d net.Destination) srcKey {
        var k srcKey
        ip := d.Address.IP()
        if ip4 := ip.To4(); ip4 != nil {
                // Store as IPv4-in-IPv6 mapped form for uniform comparison
                copy(k.ip[12:], ip4)
                k.ip[10] = 0xff
                k.ip[11] = 0xff
        } else {
                copy(k.ip[:], ip.To16())
        }
        k.port = uint16(d.Port)
        return k
}

// makeSrcKeyFromUDPAddr computes a srcKey from a stdnet.UDPAddr.
// Used by OnServerSCID to map a *stdnet.UDPAddr (handed in by the
// SCID hook) onto the same srcKey form produced by makeSrcKey, so
// that lookups in w.srcIndex succeed regardless of whether the
// source address came from a net.Destination (inbound packet
// path) or a *stdnet.UDPAddr (outbound SCID notification path).
func makeSrcKeyFromUDPAddr(addr *stdnet.UDPAddr) srcKey {
        var k srcKey
        if addr == nil || addr.IP == nil {
                return k
        }
        if ip4 := addr.IP.To4(); ip4 != nil {
                copy(k.ip[12:], ip4)
                k.ip[10] = 0xff
                k.ip[11] = 0xff
        } else {
                copy(k.ip[:], addr.IP.To16())
        }
        k.port = uint16(addr.Port)
        return k
}

// v26.10.16-link: dcidKey is a zero-allocation map key for
// QUIC DCID lookups. Replaces hex.EncodeToString(dcid) which
// allocated a 16-char string per call. The struct is 24 bytes
// (20 CID + 4 len), comparable, and hashable.
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

type udpWorker struct {
        sync.RWMutex

        proxy           proxy.Inbound
        hub             *udp.Hub
        address         net.Address
        port            net.Port
        tag             string
        stream          *internet.MemoryStreamConfig
        dispatcher      routing.Dispatcher
        sniffingRequest session.SniffingRequest
        uplinkCounter   stats.Counter
        downlinkCounter stats.Counter

        checker    *task.Periodic
        activeConn map[connID]*udpConn
        dcidIndex  map[dcidKey]connID // v26.10.16-link: struct key, zero-alloc
        srcIndex   map[srcKey]connID  // v26.10.16-link: struct key, zero-alloc

        ctx  context.Context
        cone bool
}

func (w *udpWorker) getConnection(id connID) (*udpConn, bool) {
        w.Lock()
        defer w.Unlock()

        if conn, found := w.activeConn[id]; found && !conn.done.Done() {
                conn.updateActivity()
                return conn, true
        }

        // v26.10.25-link: 256KB pipe with DiscardOverflow (not blocking).
        //
        // v26.10.24 tried removing DiscardOverflow (blocking writes) but
        // this was wrong: if the outbound truly stalls (CDN edge rotation),
        // the blocking pipe freezes the entire inbound worker's callback
        // loop, preventing ANY new connections from being processed.
        // That's a worse failure mode than dropping packets.
        //
        // The correct fix: keep DiscardOverflow but increase the size from
        // 16KB to 256KB. 16KB was only ~14 QUIC packets — YouTube burst
        // downloads overflowed it immediately. 256KB (~213 packets) absorbs
        // most bursts. When it does overflow, the drop is far enough apart
        // that QUIC retransmits recover quickly.
        pReader, pWriter := pipe.New(pipe.DiscardOverflow(), pipe.WithSizeLimit(256*1024))
        srcCopy := id.src
        conn := &udpConn{
                reader: pReader,
                writer: pWriter,
                remote: &net.UDPAddr{
                        IP:   id.src.Address.IP(),
                        Port: int(id.src.Port),
                },
                local: &net.UDPAddr{
                        IP:   w.address.IP(),
                        Port: int(w.port),
                },
                done:     done.New(),
                uplink:   w.uplinkCounter,
                downlink: w.downlinkCounter,
                src:      &srcCopy,
        }
        conn.output = func(b []byte) (int, error) {
                // Snapshot src under w.Lock() so we race-free against
                // tryQUICMigration()'s `*conn.src = id.src` reassignment. The
                // outbound hub.WriteTo call is performed outside the lock so
                // a slow network write does not block the inbound worker's
                // packet-processing loop.
                //
                // v26.10.34-link (M10 fix): use RLock instead of Lock. The
                // closure only READS *conn.src; the writer (*oldConn.src =
                // id.src in tryQUICMigration) already uses w.Lock(). RLock
                // allows multiple outbound packets to snapshot concurrently
                // instead of serializing against every inbound packet.
                w.RLock()
                srcCopy := *conn.src
                w.RUnlock()
                // v26.11.140: In quic-drop mode, don't send replies to Chrome.
                // Chrome gets silence (not ICMP), so its connection racing
                // starts TCP in parallel — no 1-second delay.
                if dropQUICAll {
                        return len(b), nil
                }
                return w.hub.WriteTo(b, srcCopy)
        }
        w.activeConn[id] = conn

        conn.updateActivity()
        return conn, false
}

func (w *udpWorker) callback(b *buf.Buffer, source net.Destination, originalDest net.Destination) {
        id := connID{
                src:    source,
                srcKey: makeSrcKey(source), // v26.10.16-link: precompute once, reuse everywhere
        }
        if originalDest.IsValid() {
                if !w.cone {
                        id.dest = originalDest
                }
                b.UDP = &originalDest
        } else {
                // v26.10.78-link: when originalDest is invalid (no TPROXY /
                // receiveOriginalDestAddress in the inbound sockopt), all UDP
                // packets from the same source port map to the same connID
                // {src, dest=zero}. This breaks when multiple QUIC connections
                // (different DCIDs) arrive from the same source port — they all
                // get mixed into one conn. Only the first QUIC Initial's SNI is
                // used for routing; subsequent QUIC connections' data goes to the
                // first connection's pipe, their handshake fails, and the client
                // falls back to TCP.
                //
                // Fix: for QUIC long-header packets (Initials), parse the DCID
                // and use it to create a unique id.dest. Different DCIDs produce
                // different connIDs, so each QUIC connection gets its own conn +
                // goroutine + sniffer + freedom dial.
                //
                // The synthetic dest is only used for connID comparison and
                // pipe routing — the actual routing destination comes from the
                // sniffer's SNI extraction in the dispatcher.
                //
                // For short-header (1-RTT) packets, the DCID is already
                // registered in dcidIndex by the Initial, so tryQUICMigration
                // handles routing. We only need the synthetic dest for Initials.
                //
                // v26.11.56-link: this block was removed in v26.11.54's history
                // rewrite and restored here. Without it, parallel QUIC
                // connections from the same source port (YouTube's DASH
                // streaming) collapse into one conn and the handshake fails.
                packetBytes := b.Bytes()
                if len(packetBytes) > 0 && packetBytes[0]&0x80 != 0 {
                        if dcid, _, err := quic.ParseDCID(packetBytes); err == nil && len(dcid) >= 4 {
                                id.dest = net.UDPDestination(net.IPAddress(dcid[:4]), 443)
                        }
                }
        }
        // v26.11.141: REMOVED DCID-first routing block (was v26.11.117).
        // This block added ParseDCID + RLock + map lookup overhead on EVERY
        // short-header packet, even when packets are being dropped.
        // v26.11.55 (smooth) did NOT have this block — it relied on
        // tryQUICMigration's fast path for short headers instead.
        //
        // v26.11.135: QUIC fallback mode — drop ALL 1-RTT (short header)
        // packets early, before any DCID parsing or lock acquisition.
        if !id.dest.IsValid() && len(b.Bytes()) > 0 && b.Bytes()[0]&0x80 == 0 {
                if dropQUICData {
                        b.Release()
                        return
                }
        }
        // Try QUIC DCID-based migration lookup before creating a new conn
        if migratedConn := w.tryQUICMigration(b.Bytes(), id); migratedConn != nil {
                migratedConn.writer.WriteMultiBuffer(buf.MultiBuffer{b})
                migratedConn.updateActivity()
                return
        }

        conn, existing := w.getConnection(id)

        // v26.11.138: RE-ADD the C3 re-check block (from v26.10.43/v26.10.78).
        // This was present in v26.11.55 when QUIC was smooth. Without it,
        // QUIC is not smooth. The re-check catches races where two Initials
        // arrive simultaneously — the second goroutine's getConnection creates
        // a duplicate conn, and the re-check discards it in favor of the
        // existing one.
        if !existing {
                w.Lock()
                if existingConn, found := w.activeConn[id]; found && !existingConn.done.Done() {
                        // Another goroutine won the race. Use their conn.
                        w.Unlock()
                        conn = existingConn
                        existing = true
                } else {
                        w.Unlock()
                }
        }

        // Record DCID and src for new QUIC connections
        if !existing {
                w.recordDCID(b.Bytes(), id, conn)
                w.recordSrc(id, conn)
                // v26.11.117: Set up server SCID registration callback.
                // When freedom.Process sees a long-header reply from Google,
                // it extracts the server's SCID and calls this callback.
                // The callback registers the SCID in dcidIndex so subsequent
                // 1-RTT short headers (which carry DCID=server_SCID) can be
                // routed to the correct conn.
                connIDCopy := id
                conn.registerServerCID = func(serverSCID []byte) {
                        if len(serverSCID) == 0 {
                                return
                        }
                        dk := makeDCIDKey(serverSCID)
                        w.Lock()
                        if _, exists := w.dcidIndex[dk]; !exists {
                                w.dcidIndex[dk] = connIDCopy
                        }
                        w.Unlock()
                }
        }

        // payload will be discarded in pipe is full.
        conn.writer.WriteMultiBuffer(buf.MultiBuffer{b})

        if !existing {
                common.Must(w.checker.Start())

                // v26.11.140: In quic-drop mode, don't start proxy.Process.
                // The sniffer still runs (extracts SNI for routing), but
                // freedom never dials Google. Chrome gets silence and
                // falls back to TCP via connection racing. This replicates
                // the C3 bug behavior but as an explicit feature.
                if dropQUICAll {
                        return
                }

                go func() {
                        ctx, cancel := context.WithCancel(w.ctx)
                        conn.cancel = cancel
                        sid := session.NewID()
                        ctx = c.ContextWithID(ctx, sid)

                        outbounds := []*session.Outbound{{}}
                        if originalDest.IsValid() {
                                outbounds[0].Target = originalDest
                        } else {
                                // v26.11.118: When originalDest is invalid (no TPROXY),
                                // the outbound Target defaults to Network_TCP (Go zero value).
                                // This causes the dispatcher to route UDP QUIC traffic as TCP.
                                // Fix: set a UDP destination so the dispatcher knows this is UDP.
                                outbounds[0].Target = net.UDPDestination(net.AnyIP, 0)
                        }
                        ctx = session.ContextWithOutbounds(ctx, outbounds)
                        local := net.DestinationFromAddr(w.hub.Addr())
                        if local.Address == net.AnyIP || local.Address == net.AnyIPv6 {
                                if source.Address.Family().IsIPv4() {
                                        local.Address = net.AnyIP
                                } else if source.Address.Family().IsIPv6() {
                                        local.Address = net.AnyIPv6
                                }
                        }

                        ctx = session.ContextWithInbound(ctx, &session.Inbound{
                                Source:  source,
                                Local:   local, // Due to some limitations, in UDP connections, localIP is always equal to listen interface IP
                                Gateway: net.UDPDestination(w.address, w.port),
                                Tag:     w.tag,
                                Conn:    conn, // v26.11.117: expose udpConn so freedom can call RegisterServerSCID
                        })
                        content := new(session.Content)
                        content.SniffingRequest = w.sniffingRequest
                        ctx = session.ContextWithContent(ctx, content)
                        if err := w.proxy.Process(ctx, net.Network_UDP, conn, w.dispatcher); err != nil {
                                errors.LogInfoInner(ctx, err, "proxy.Process error for ", source)
                        }
                        conn.Close()
                        // conn not removed by checker TODO may be lock worker here is better
                        if !conn.inactive {
                                conn.setInactive()
                                w.removeConn(id)
                        }
                }()
        }
}

func (w *udpWorker) removeConn(id connID) {
        w.Lock()
        if _, ok := w.activeConn[id]; ok {
                // v26.10.42-link (audit H2 from 2-b): delete ALL dcidIndex
                // entries pointing to this conn, not just the latest DCID.
                for dk, dcidConnID := range w.dcidIndex {
                        if dcidConnID == id {
                                delete(w.dcidIndex, dk)
                        }
                }
                delete(w.srcIndex, id.srcKey)
                delete(w.activeConn, id)
        } else {
                // H3 fix: conn was migrated and re-keyed under a new id.
                // The old id doesn't find it. We can't search by pointer
                // because we don't have it. The clean() function will
                // catch the orphaned entry within 1 minute. This is a
                // minor leak — the conn is already closed (pipe + done),
                // so it's just a map entry holding a dead pointer.
                delete(w.activeConn, id) // no-op, but safe
        }
        w.Unlock()
}

// tryQUICMigration checks if a packet belongs to an existing QUIC connection
// that has migrated. Returns the existing conn if migration is detected, nil otherwise.
//
// Handles two migration patterns:
//  1. Source port change with same DCID (Chrome desktop path probing, NAT rebind).
//     DCID lookup finds existing conn, source is updated.
//  2. CID rotation with source port change (Android YouTube aggressive CID rotation
//     via NEW_CONNECTION_ID frames). DCID lookup misses, but src IP:port lookup
//     finds existing conn. New DCID is added to dcidIndex for future packets.
func (w *udpWorker) tryQUICMigration(packet []byte, id connID) *udpConn {
        // v26.11.141: RESTORE short-header fast-path bypass (from v26.11.55).
        // For 1-RTT short-header packets from a known source, skip the full
        // DCID migration lookup entirely — just return nil so the caller
        // falls through to getConnection (which finds the existing conn via
        // srcIndex). This eliminates ParseDCID + Lock overhead on 99% of
        // packets in a long-lived QUIC connection.
        if len(packet) > 0 && packet[0]&0x80 == 0 {
                // Short header — existing conn, no migration lookup needed.
                w.RLock()
                _, found := w.srcIndex[id.srcKey]
                w.RUnlock()
                if found {
                        return nil
                }
                // src is unknown — fall through to full path
        }

        // v26.10.16-link: src-first fast path with zero-allocation struct keys.
        sk := id.srcKey

        w.Lock()

        // Fast path: src is already known.
        if oldID, found := w.srcIndex[sk]; found {
                oldConn, ok := w.activeConn[oldID]
                if !ok || oldConn.done.Done() {
                        delete(w.srcIndex, sk)
                        // Fall through to slow path (will re-lock).
                } else if oldID == id {
                        // Same src, same dest → same connection, no migration.
                        // v26.10.42-link (audit H6 from 2-b): check if the
                        // packet's DCID differs from conn.dcid. If it does,
                        // this is a NEW_CONNECTION_ID-issued DCID arriving
                        // in a 1-RTT short-header packet. Record it so
                        // future migrations to this DCID are tracked. Without
                        // this, CID-rotated connections silently lose tracking
                        // (the new DCID was never in dcidIndex).
                        if len(packet) > 0 && packet[0]&0x80 == 0 {
                                // Short header — parse DCID (8-byte default)
                                if newDcid, _, err := quic.ParseDCID(packet); err == nil && len(newDcid) > 0 {
                                        newDk := makeDCIDKey(newDcid)
                                        if _, exists := w.dcidIndex[newDk]; !exists {
                                                w.dcidIndex[newDk] = oldID
                                                // Don't overwrite conn.dcid —
                                                // keep the original for cleanup.
                                        }
                                }
                        }
                        w.Unlock()
                        return nil
                } else {
                        // H2 fix: same src, different dest → could be either:
                        // (a) genuine CID rotation (same QUIC conn, new DCID, same dest)
                        // (b) two distinct QUIC connections from the same src
                        //     to different destinations (YouTube does this)
                        //
                        // Old code treated ALL same-src-different-dest as
                        // CID rotation, mixing two connections' state machines.
                        //
                        // Fix: check if the DCID matches an existing conn
                        // in dcidIndex. If it does, it's genuine migration
                        // (same DCID found = same conn with new src). If not,
                        // it's a new connection — fall through to slow path.
                        w.Unlock()
                        dcid, _, err := quic.ParseDCID(packet)
                        if err != nil || len(dcid) == 0 {
                                return nil
                        }
                        dk := makeDCIDKey(dcid)
                        w.Lock()
                        // Re-check srcIndex under lock.
                        oldID2, found2 := w.srcIndex[sk]
                        if !found2 {
                                w.Unlock()
                                return nil
                        }
                        oldConn2, ok2 := w.activeConn[oldID2]
                        if !ok2 || oldConn2.done.Done() {
                                delete(w.srcIndex, sk)
                                w.Unlock()
                                return nil
                        }
                        // Check if this packet's DCID matches an existing conn.
                        // If dcidIndex has this DCID, it's genuine CID rotation.
                        // If not, it's a different QUIC connection — don't mix.
                        if dcidID, dcidFound := w.dcidIndex[dk]; dcidFound {
                                if dcidConn, dcidOk := w.activeConn[dcidID]; dcidOk && !dcidConn.done.Done() && dcidID == oldID2 {
                                        // Genuine CID rotation: DCID belongs to
                                        // the same src's existing conn. Update.
                                        *oldConn2.src = id.src
                                        oldConn2.updateActivity()
                                        // v26.10.42-link (audit H1 from 2-b): delete the OLD dcidIndex
                                        // entry to prevent orphan accumulation. The old DCID is no
                                        // longer valid for this conn after CID rotation.
                                        if oldConn2.dcid != nil {
                                                oldDk := makeDCIDKey(oldConn2.dcid)
                                                delete(w.dcidIndex, oldDk)
                                        }
                                        oldConn2.dcid = dcid
                                        delete(w.activeConn, oldID2)
                                        w.activeConn[id] = oldConn2
                                        w.srcIndex[sk] = id
                                        w.dcidIndex[dk] = id
                                        // v26.10.34-link (M11 fix): defer log to
                                        // after w.Unlock() — errors.LogInfo does
                                        // formatted I/O and can block on a slow
                                        // logger sink, blocking ALL inbound packet
                                        // processing for this worker while held.
                                        dcidHex := hex.EncodeToString(dcid)
                                        oldSrc := oldID2.src
                                        newSrc := id.src
                                        w.Unlock()
                                        errors.LogInfo(context.Background(), "QUIC CID rotation detected: new DCID ", dcidHex, " from ", oldSrc, " to ", newSrc)
                                        // v26.10.34-link (C2 fix): the original code
                                        // had a w.Unlock() at the fall-through case
                                        // AND a w.Unlock() at the end of the outer
                                        // block. When the fall-through ran, it
                                        // double-unlocked and panicked. We return
                                        // here on the rotation path; the
                                        // fall-through below does NOT unlock — the
                                        // single w.Unlock() at the end of the
                                        // outer block releases it.
                                        return oldConn2
                                }
                        }
                        // Not a CID rotation — different QUIC connection.
                        // Fall through to slow path (dcidIndex lookup).
                        // v26.10.34-link (C2 fix): do NOT unlock here. The
                        // single w.Unlock() at the end of the outer block (after
                        // this if/else) releases the lock acquired at L544.
                        // Unlocking here would double-unlock and panic.
                }
        }
        w.Unlock()

        // Slow path: src is unknown. Parse DCID and check dcidIndex for
        // migration (source port change with same DCID — Chrome path
        // probing, NAT rebind).
        dcid, _, err := quic.ParseDCID(packet)
        if err != nil || len(dcid) == 0 {
                return nil
        }
        dk := makeDCIDKey(dcid)

        w.Lock()

        if oldID, found := w.dcidIndex[dk]; found {
                oldConn, ok := w.activeConn[oldID]
                if !ok || oldConn.done.Done() {
                        delete(w.dcidIndex, dk)
                        w.Unlock()
                        return nil
                }
                if oldID == id {
                        w.Unlock()
                        return nil // same conn, normal packet (shouldn't happen
                        // since src was unknown, but defensive)
                }
                oldSK := oldID.srcKey
                *oldConn.src = id.src
                oldConn.updateActivity()
                // v26.10.43-link (audit H4 from 2-b): update remote
                // so RemoteAddr() returns the post-migration source.
                oldConn.remote = &net.UDPAddr{
                        IP:   id.src.Address.IP(),
                        Port: int(id.src.Port),
                }
                delete(w.activeConn, oldID)
                w.activeConn[id] = oldConn
                w.dcidIndex[dk] = id
                delete(w.srcIndex, oldSK)
                w.srcIndex[id.srcKey] = id
                // v26.10.34-link (M11+L11 fix): defer log to after w.Unlock()
                // (formatted I/O under lock blocks inbound processing), and
                // print DCID as hex (was raw []byte which xray formats as
                // decimal "[1 2 3 ...]"). Use hex.EncodeToString for readability.
                // Note: removed `defer w.Unlock()` from this function — the
                // explicit unlocks on each return path replace it. Mixing the
                // two would double-unlock.
                dcidHex := hex.EncodeToString(dcid)
                oldSrc := oldID.src
                newSrc := id.src
                w.Unlock()
                errors.LogInfo(context.Background(), "QUIC migration detected: DCID ", dcidHex, " from ", oldSrc, " to ", newSrc)
                return oldConn
        }

        w.Unlock()
        return nil
}

// recordSrc associates a source IP:port with a connID for future CID rotation lookup.
func (w *udpWorker) recordSrc(id connID, conn *udpConn) {
        w.Lock()
        defer w.Unlock()
        if _, exists := w.srcIndex[id.srcKey]; !exists {
                w.srcIndex[id.srcKey] = id
        }
}

// recordDCID associates a QUIC DCID with a connID for future migration lookup.
// Only records on first sighting of a DCID.
func (w *udpWorker) recordDCID(packet []byte, id connID, conn *udpConn) {
        // v26.10.36-link: 1-RTT short-header packets have no DCID length field
        // (it's implicit — 8 bytes for Chrome/Firefox/Safari). The existing
        // conn already has its DCID recorded from the Initial. Skip the parse
        // + map write for 99% of packets in a long-lived QUIC connection.
        if len(packet) > 0 && packet[0]&0x80 == 0 {
                return
        }
        dcid, _, err := quic.ParseDCID(packet)
        if err != nil {
                return
        }
        if len(dcid) == 0 {
                return
        }
        dk := makeDCIDKey(dcid)

        w.Lock()
        defer w.Unlock()

        if _, exists := w.dcidIndex[dk]; !exists {
                w.dcidIndex[dk] = id
                conn.dcid = dcid
        }
}

// OnServerSCID is invoked by the quic worker-hook dispatcher when a
// server-side Initial (or other long-header) packet is observed
// carrying serverSCID. The browserSrc is the *stdnet.UDPAddr of the
// downstream browser that the server-side dispatcher saw the packet
// from. We translate that into a srcKey and, if a connection already
// exists for that srcKey, additionally record the server SCID → connID
// association in w.dcidIndex so that subsequent 1-RTT packets with the
// rotated DCID can be demuxed to the correct udpConn.
//
// This implements the browser-side half of Solution B: the browser
// never has to wait for a CID rotation — we record the server-chosen
// SCID as soon as we observe it and treat it as an alternate DCID for
// the same udpConn.
func (w *udpWorker) OnServerSCID(serverSCID []byte, browserSrc *stdnet.UDPAddr) {
        if len(serverSCID) == 0 || browserSrc == nil {
                return
        }
        sk := makeSrcKeyFromUDPAddr(browserSrc)
        if sk.port == 0 && sk.ip == ([16]byte{}) {
                return
        }
        w.Lock()
        defer w.Unlock()
        existingID, found := w.srcIndex[sk]
        if !found {
                return
        }
        existingConn, ok := w.activeConn[existingID]
        if !ok || existingConn.done.Done() {
                delete(w.srcIndex, sk)
                return
        }
        _ = existingConn
        dk := makeDCIDKey(serverSCID)
        if _, exists := w.dcidIndex[dk]; !exists {
                w.dcidIndex[dk] = existingID
        }
}

func (w *udpWorker) handlePackets() {
        receive := w.hub.Receive()
        for payload := range receive {
                w.callback(payload.Payload, payload.Source, payload.Target)
        }
}

func (w *udpWorker) clean() error {
        nowSec := time.Now().Unix()
        w.Lock()
        defer w.Unlock()

        if len(w.activeConn) == 0 {
                return errors.New("no more connections. stopping...")
        }

        for addr, conn := range w.activeConn {
                if nowSec-atomic.LoadInt64(&conn.lastActivityTime) > udptimeout.SessionIdleSeconds() {
                        if !conn.inactive {
                                conn.setInactive()
                                // v26.10.42-link (audit H2 from 2-b): delete ALL
                                // dcidIndex entries pointing to this conn, not just
                                // the latest DCID. CID rotation may have created
                                // multiple dcidIndex entries for the same conn.
                                // The old code only deleted conn.dcid (the latest),
                                // leaving orphaned entries for rotated-away DCIDs.
                                connID := addr
                                for dk, dcidConnID := range w.dcidIndex {
                                        if dcidConnID == connID {
                                                delete(w.dcidIndex, dk)
                                        }
                                }
                                delete(w.srcIndex, addr.srcKey)
                                delete(w.activeConn, addr)
                        }
                        conn.Close()
                }
        }

        if len(w.activeConn) == 0 {
                w.activeConn = make(map[connID]*udpConn, 16)
                w.dcidIndex = make(map[dcidKey]connID)
                w.srcIndex = make(map[srcKey]connID)
        }

        return nil
}

func (w *udpWorker) Start() error {
        w.activeConn = make(map[connID]*udpConn, 16)
        w.dcidIndex = make(map[dcidKey]connID)
        w.srcIndex = make(map[srcKey]connID)
        ctx := context.Background()
        h, err := udp.ListenUDP(ctx, w.address, w.port, w.stream, udp.HubCapacity(256))
        if err != nil {
                return err
        }

        w.cone = w.ctx.Value("cone").(bool)

        w.checker = &task.Periodic{
                Interval: time.Minute,
                Execute:  w.clean,
        }

        w.hub = h
        quic.RegisterWorkerSCIDHook(w)
        go w.handlePackets()
        return nil
}

func (w *udpWorker) Close() error {
        quic.UnregisterWorkerSCIDHook(w)
        w.Lock()
        defer w.Unlock()

        var errs []interface{}

        if w.hub != nil {
                if err := w.hub.Close(); err != nil {
                        errs = append(errs, err)
                }
        }

        if w.checker != nil {
                if err := w.checker.Close(); err != nil {
                        errs = append(errs, err)
                }
        }

        if err := common.Close(w.proxy); err != nil {
                errs = append(errs, err)
        }

        if len(errs) > 0 {
                return errors.New("failed to close all resources").Base(errors.New(serial.Concat(errs...)))
        }
        return nil
}

func (w *udpWorker) Port() net.Port {
        return w.port
}

func (w *udpWorker) Proxy() proxy.Inbound {
        return w.proxy
}

type dsWorker struct {
        address         net.Address
        proxy           proxy.Inbound
        stream          *internet.MemoryStreamConfig
        tag             string
        dispatcher      routing.Dispatcher
        sniffingRequest session.SniffingRequest
        uplinkCounter   stats.Counter
        downlinkCounter stats.Counter

        hub internet.Listener

        ctx context.Context
}

func (w *dsWorker) callback(conn stat.Connection) {
        ctx, cancel := context.WithCancel(w.ctx)
        sid := session.NewID()
        ctx = c.ContextWithID(ctx, sid)

        if w.uplinkCounter != nil || w.downlinkCounter != nil {
                conn = &stat.CounterConnection{
                        Connection:   conn,
                        ReadCounter:  w.uplinkCounter,
                        WriteCounter: w.downlinkCounter,
                }
        }
        ctx = session.ContextWithInbound(ctx, &session.Inbound{
                Source:  net.DestinationFromAddr(conn.RemoteAddr()),
                Local:   net.DestinationFromAddr(conn.LocalAddr()),
                Gateway: net.UnixDestination(w.address),
                Tag:     w.tag,
                Conn:    conn,
        })

        content := new(session.Content)
        content.SniffingRequest = w.sniffingRequest
        ctx = session.ContextWithContent(ctx, content)

        if err := w.proxy.Process(ctx, net.Network_UNIX, conn, w.dispatcher); err != nil {
                errors.LogInfoInner(ctx, err, "connection ends")
        }
        cancel()
        if err := conn.Close(); err != nil {
                errors.LogInfoInner(ctx, err, "failed to close connection")
        }
}

func (w *dsWorker) Proxy() proxy.Inbound {
        return w.proxy
}

func (w *dsWorker) Port() net.Port {
        return net.Port(0)
}

func (w *dsWorker) Start() error {
        ctx := context.Background()
        hub, err := internet.ListenUnix(ctx, w.address, w.stream, func(conn stat.Connection) {
                go w.callback(conn)
        })
        if err != nil {
                return errors.New("failed to listen Unix Domain Socket on ", w.address).Base(err)
        }
        w.hub = hub
        return nil
}

func (w *dsWorker) Close() error {
        var errs []interface{}
        if w.hub != nil {
                if err := common.Close(w.hub); err != nil {
                        errs = append(errs, err)
                }
                if err := common.Close(w.proxy); err != nil {
                        errs = append(errs, err)
                }
        }
        if len(errs) > 0 {
                return errors.New("failed to close all resources").Base(errors.New(serial.Concat(errs...)))
        }

        return nil
}

func IsLocal(ip net.IP) bool {
        addrs, err := net.InterfaceAddrs()
        if err != nil {
                return false
        }
        for _, addr := range addrs {
                if ipnet, ok := addr.(*net.IPNet); ok {
                        if ipnet.IP.Equal(ip) {
                                return true
                        }
                }
        }
        return false
}
