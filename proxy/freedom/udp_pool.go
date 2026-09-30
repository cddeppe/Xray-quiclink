package freedom

import (
    "context"
    "encoding/hex"
    "io"
    stdnet "net"
    "sync"
    "time"

    "github.com/xtls/xray-core/common/buf"
    "github.com/xtls/xray-core/common/errors"
    xraynet "github.com/xtls/xray-core/common/net"
    "github.com/xtls/xray-core/common/protocol/quic"
    "github.com/xtls/xray-core/features/stats"
)

// UDPSocketPool pools UDP sockets by destination IP:port so that many
// inbound QUIC sessions going to the same destination share one outbound
// UDP socket. Reply packets are demuxed by parsing the QUIC DCID.
type UDPSocketPool struct {
    mu      sync.Mutex
    sockets map[string]*pooledSocket
    reaper  *time.Ticker
}

type pooledSocket struct {
    mu            sync.Mutex
    conn          stdnet.PacketConn
    dest          *stdnet.UDPAddr
    refCount      int
    lastUsed      time.Time
    lastReplyTime time.Time
    demux         map[string]chan<- readResult
    closed        chan struct{}
    closeOnce     sync.Once
    dead          bool
}

type readResult struct {
    data []byte
    addr stdnet.Addr
}

type pooledConn struct {
    socket *pooledSocket
    inbox  chan readResult
    done   chan struct{}
    mu     sync.Mutex
    closed bool
    scids  map[string]bool
}

func NewUDPSocketPool() *UDPSocketPool {
    p := &UDPSocketPool{
        sockets: make(map[string]*pooledSocket),
    }
    p.startReaper()
    return p
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
        isIdle := time.Since(sock.lastReplyTime) > 10*time.Minute && sock.refCount > 0
        isUnused := time.Since(sock.lastUsed) > 5*time.Minute && sock.refCount == 0
        sock.mu.Unlock()

        if isDead || isIdle || isUnused {
            sock.MarkDead()
            delete(p.sockets, key)
            errors.LogInfo(context.Background(), "udp_pool: evicted stale socket for ", key)
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
        sock.mu.Lock()
        sock.refCount++
        sock.lastUsed = time.Now()
        sock.mu.Unlock()
    }
    p.mu.Unlock()

    if !ok {
        pc, err := stdnet.ListenUDP("udp", nil)
        if err != nil {
            return nil, err
        }

        sock = &pooledSocket{
            conn:     pc,
            dest:     dest,
            demux:    make(map[string]chan<- readResult),
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
        socket: sock,
        inbox:  inbox,
        done:   make(chan struct{}),
        scids:  make(map[string]bool),
    }
    return conn, nil
}

func (s *pooledSocket) readLoop() {
    b := make([]byte, 1500)
    for {
        select {
        case <-s.closed:
            return
        default:
        }

        // Set a 30-second read deadline.
        // If no packets arrive within 30 seconds, the socket is likely dead
        // (e.g., the CDN edge rotated and is silently dropping packets).
        // This forces instant detection and eviction, rather than waiting
        // for the browser to time out or the 10-minute idle reaper to run.
        _ = s.conn.SetReadDeadline(time.Now().Add(30 * time.Second))

        n, addr, err := s.conn.ReadFrom(b)
        if err != nil {
            if s.IsClosed() {
                return
            }
            // Check if the error is a timeout (net.Error)
            if netErr, ok := err.(stdnet.Error); ok && netErr.Timeout() {
                errors.LogInfo(context.Background(), "udp_pool: read timeout (30s), marking socket dead: ", s.dest)
                s.MarkDead()
                return
            }
            errors.LogInfo(context.Background(), "udp_pool: read error, marking socket dead: ", err)
            s.MarkDead()
            return
        }

        packet := make([]byte, n)
        copy(packet, b[:n])

        dcid, _, err := quic.ParseDCID(packet)
        if err != nil {
            continue
        }
        dcidHex := hex.EncodeToString(dcid)

        s.mu.Lock()
        ch, ok := s.demux[dcidHex]
        s.lastUsed = time.Now()
        s.lastReplyTime = time.Now()
        s.mu.Unlock()

        if !ok {
            continue
        }

        select {
        case ch <- readResult{data: packet, addr: addr}:
        default:
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
    cidHex := hex.EncodeToString(cid)

    c.mu.Lock()
    if c.closed {
        c.mu.Unlock()
        return
    }
    already := c.scids[cidHex]
    if !already {
        c.scids[cidHex] = true
    }
    c.mu.Unlock()

    if !already {
        c.socket.mu.Lock()
        c.socket.demux[cidHex] = c.inbox
        c.socket.mu.Unlock()
    }
}

func (c *pooledConn) WriteTo(b []byte, addr stdnet.Addr) (int, error) {
    if c.IsClosed() {
        return 0, io.EOF
    }

    if scid, _, err := parseQUICSCID(b); err == nil && len(scid) > 0 {
        c.RegisterCID(scid)
    }

    n, err := c.socket.conn.WriteTo(b, c.socket.dest)
    if err != nil {
        c.socket.MarkDead()
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
    c.mu.Lock()
    defer c.mu.Unlock()
    return c.closed
}

func (c *pooledConn) Close() error {
    c.mu.Lock()
    if c.closed {
        c.mu.Unlock()
        return nil
    }
    c.closed = true
    close(c.done)

    c.socket.mu.Lock()
    for cidHex := range c.scids {
        if existing, ok := c.socket.demux[cidHex]; ok && existing == c.inbox {
            delete(c.socket.demux, cidHex)
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
    if len(b) < 1 {
        return nil, false, quic.ErrTooShort
    }
    firstByte := b[0]

    if firstByte&0x80 != 0 {
        if firstByte&0x40 == 0 {
            return nil, true, quic.ErrNotQUIC
        }
        if len(b) < 6 {
            return nil, true, quic.ErrTooShort
        }
        dcidLen := int(b[5])
        if dcidLen > quic.MaxCIDLen {
            return nil, true, quic.ErrBadCILen
        }
        scidLenOffset := 6 + dcidLen
        if len(b) < scidLenOffset+1 {
            return nil, true, quic.ErrTooShort
        }
        scidLen := int(b[scidLenOffset])
        if scidLen > quic.MaxCIDLen {
            return nil, true, quic.ErrBadCILen
        }
        scidEnd := scidLenOffset + 1 + scidLen
        if len(b) < scidEnd {
            return nil, true, quic.ErrTooShort
        }
        scid := make([]byte, scidLen)
        copy(scid, b[scidLenOffset+1:scidEnd])
        return scid, true, nil
    }

    return nil, false, nil
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
