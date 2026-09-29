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
// UDP socket. This eliminates per-connection socket creation overhead
// for applications (e.g. Android YouTube) that open many short-lived
// QUIC connections to the same destination.
//
// Reply packets are demultiplexed by parsing the QUIC DCID, which (for
// packets sent by the server back to the client) carries the client's
// own connection ID. Outgoing packets carry the client's CID as the
// SCID, so the pool can match each reply to the originating session.
type UDPSocketPool struct {
    mu      sync.Mutex
    sockets map[string]*pooledSocket
}

type pooledSocket struct {
    mu        sync.Mutex
    conn      stdnet.PacketConn
    dest      *stdnet.UDPAddr
    refCount  int
    lastUsed  time.Time
    demux     map[string]chan<- readResult
    closed    chan struct{}
    closeOnce sync.Once
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

// NewUDPSocketPool creates a new pool.
func NewUDPSocketPool() *UDPSocketPool {
    return &UDPSocketPool{
        sockets: make(map[string]*pooledSocket),
    }
}

func destKey(dest *stdnet.UDPAddr) string {
    return dest.String()
}

// Acquire returns a *pooledConn for the given destination. The caller
// must call Close() on it when done.
func (p *UDPSocketPool) Acquire(dest *stdnet.UDPAddr) (*pooledConn, error) {
    key := destKey(dest)

    p.mu.Lock()
    sock, ok := p.sockets[key]
    if ok && sock.IsClosed() {
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
        if existing, ok := p.sockets[key]; ok && !existing.IsClosed() {
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

        n, addr, err := s.conn.ReadFrom(b)
        if err != nil {
            if s.IsClosed() {
                return
            }
            errors.LogInfo(context.Background(), "udp_pool: read error: ", err)
            continue
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

func (s *pooledSocket) release() {
    s.mu.Lock()
    if s.refCount > 0 {
        s.refCount--
    }
    s.lastUsed = time.Now()
    s.mu.Unlock()
}

func (s *pooledSocket) Close() error {
    s.closeOnce.Do(func() {
        close(s.closed)
        _ = s.conn.Close()
    })
    return nil
}

// RegisterCID tells the pool that replies with this DCID belong to this session.
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

// WriteTo sends a packet via the shared socket.
func (c *pooledConn) WriteTo(b []byte, addr stdnet.Addr) (int, error) {
    if c.IsClosed() {
        return 0, io.EOF
    }

    if scid, _, err := parseQUICSCID(b); err == nil && len(scid) > 0 {
        c.RegisterCID(scid)
    }

    return c.socket.conn.WriteTo(b, c.socket.dest)
}

// ReadFrom returns the next reply packet for this session.
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

// Close releases this session's hold on the pooled socket.
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

// parseQUICSCID extracts the Source Connection ID from a QUIC long header.
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

// PooledPacketReader is a buf.Reader that reads packets from a pooled UDP socket.
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

// PooledPacketWriter is a buf.Writer that sends packets to a pooled UDP socket.
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
