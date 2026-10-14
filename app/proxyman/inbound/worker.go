package inbound

import (
	"context"
	"encoding/hex"
	stderrors "errors"
	"hash/crc32"
	stdnet "net"
	"sync"
	"syscall"

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
	connID           connID // v26.12.53: stored for learnSrc (IP fallback)
	local            net.Addr
	done             *done.Instance
	uplink           stats.Counter
	downlink         stats.Counter
	inactive         bool
	cancel           context.CancelFunc
	src              *net.Destination // pointer for migration
	dcid             []byte           // QUIC DCID, nil for non-QUIC
	// v26.12.39: Back-reference to the worker for shared socket access.
	worker *udpWorker
	// v26.11.117: Callback to register server SCID when seen in reply.
	// Set by freedom.Process when pool is OFF, so the per-session reader
	// can learn the server's SCID and register it in dcidIndex.
	registerServerCID func([]byte)
	// v26.11.156: registerPoolCID registers a new DCID in the UDP socket
	// pool's demux. Called when CID rotation is detected — without this,
	// the pool's readLoop drops replies with the new DCID, causing Google
	// to think the connection is dead and stop replying (20-second freeze).
	registerPoolCID func([]byte)
	// v26.11.196: Persistent outbound conn (to Google). Survives Process
	// restarts so the source port stays stable for the entire QUIC
	// connection. Without this, each Process restart dials a new socket
	// with a new source port → Google sees connection migration → path
	// validation → stall.
	outboundConn net.Conn
	outboundMu   sync.Mutex
	outboundDest net.Destination
	// v26.11.196: Track whether the Process goroutine is running. The
	// inbound callback uses this to decide whether to start (or restart)
	// the goroutine: a returning Process (e.g. from responseDone's
	// goroutine-leak fix) leaves the persistent outboundConn alive so
	// the next packet can re-enter Process and reuse it.
	processRunning atomic.Bool
	// v26.11.202: Persistent pooledConn. Survives Process restarts so
	// short-header (1-RTT) packets that arrive after Process returned
	// still use the pool (same socket, same source port). Without this,
	// the goroutine restart peeks a short header, skips the pool, and
	// dials a new socket → stall.
	pooledConnPtr interface{} // *pooledConn, stored as interface to avoid import cycle
	// v26.12.27: Per-connection UDP socket + permanent reader goroutine.
	// Ported from v26.11.272. Chrome always uses 0-length SCID → pool's
	// DCID demux can't route replies. Each udpConn gets its own socket,
	// reader goroutine, and replyCh. The socket survives Process restarts.
	// Only clean() closes it.
	sessionSocket      stdnet.PacketConn
	sessionReplyCh     chan []byte
	sessionReaderDn    chan struct{}
	sessionReaderMu    sync.Mutex
	sessionReaderAlive bool
	sessionSocketDest  net.Destination
	sessionSocketMu    sync.Mutex

	// v26.12.36-link: Diagnostic counters for the QUIC reply path.
	// Logged every 5 seconds by the counter logger goroutine.
	// These tell us exactly which segment of the reply path dies.
	cntSockRead atomic.Int64 // packets read from Google's socket
	cntSockErr  atomic.Int64 // read errors (socket closed, etc.)
	cntChDrop   atomic.Int64 // packets dropped (channel full)
	cntReplyOut atomic.Int64 // packets written to Chrome (udpConn.Write)
	// v26.12.55: Write errors — hub.WriteTo failed (NAT expiry, etc).
	// replyOut counts BEFORE the write; these count failures AFTER.
	// If replyOut > writeErr but sockRead freezes, the client isn't
	// receiving → Google sees loss → cwnd collapses → video stalls.
	cntWriteErr atomic.Int64
	// v26.12.57: Content integrity check. Running hash of all bytes
	// at two points: (1) socket read in reader goroutine, (2) udpConn.Write
	// entry before SplitCoalesced. If readBytes == writeBytes but
	// readHash != writeHash, data was corrupted between read and write.
	cntReadBytes  atomic.Int64
	cntReadHash   atomic.Int64 // sum of CRC32 of each packet read
	cntWriteBytes atomic.Int64
	cntWriteHash  atomic.Int64 // sum of CRC32 of each packet written
	cntReqSent    atomic.Int64 // packets Chrome->Google (via PacketWriter)
	// v26.12.52: Inbound pipe overflow drops.
	cntPipeDrop *atomic.Int64 // pointer to local pipeDropCounter
	// v26.12.54: Silent drops inside PacketWriter.WriteMultiBuffer.
	cntNilAddr           atomic.Int64
	cntRuleBlock         atomic.Int64
	cntResolveFail       atomic.Int64
	cntSystemResolveFail atomic.Int64
}

func (c *udpConn) setInactive() {
	c.inactive = true
}

func (c *udpConn) updateActivity() {
	atomic.StoreInt64(&c.lastActivityTime, time.Now().Unix())
}

// v26.11.212: UpdateActivity is an exported wrapper for updateActivity.
// Called by pooledConn.onActivity when data flows through the pool path
// (WriteTo or ReadFrom). This keeps clean() from retiring active
// connections — without it, BufferedPacketReader and PooledPacketWriter
// bypass udpConn.Write/Read, so lastActivityTime is never updated and
// clean() retires the conn after sessionIdleTimeout, killing the pool
// socket mid-session.
func (c *udpConn) UpdateActivity() {
	c.updateActivity()
}

// v26.11.196: GetOutboundConn returns the persistent outbound conn (to
// Google). Called by freedom.Process to check if a previous Process call
// left a conn that can be reused (keeping the source port stable).
func (c *udpConn) GetOutboundConn() net.Conn {
	c.outboundMu.Lock()
	defer c.outboundMu.Unlock()
	return c.outboundConn
}

// v26.11.196: SetOutboundConn stores the outbound conn for reuse by future
// Process calls. Called by freedom.Process after a successful dial.
// If a previous conn exists that isn't the same one, it is closed first
// to avoid leaking sockets when the destination changes.
func (c *udpConn) SetOutboundConn(conn net.Conn, dest net.Destination) {
	c.outboundMu.Lock()
	defer c.outboundMu.Unlock()
	// v26.12.37-link: Log socket replacement. If the socket changes
	// mid-connection, Google sees QUIC connection migration (source
	// port/IP changed) → path validation → silent death. This log line
	// tells us if that's happening.
	replacing := c.outboundConn != nil && c.outboundConn != conn
	if replacing {
		errors.LogWarning(context.Background(),
			"DIAG: SetOutboundConn REPLACING socket old=", c.outboundConn.LocalAddr(),
			"->", c.outboundConn.RemoteAddr(),
			" new=", conn.LocalAddr(), "->", conn.RemoteAddr())
		c.outboundConn.Close()
	} else {
		errors.LogInfo(context.Background(),
			"DIAG: SetOutboundConn installing socket local=", conn.LocalAddr(),
			" remote=", conn.RemoteAddr())
	}
	c.outboundConn = conn
	c.outboundDest = dest
	// v26.12.43: Enlarge the kernel UDP receive buffer on the per-session
	// outbound socket. The blocking channel send (above) means the reader
	// goroutine now applies backpressure when sessionReplyCh is full; the
	// kernel buffer absorbs the burst during that window. Without this,
	// the kernel itself becomes the dropper when the channel is full,
	// reproducing the same collapse one layer down. Default kernel
	// rmem_max on many distros is 212992 (~208 KB) — try 4 MB, the kernel
	// silently clamps to rmem_max if it's smaller. Run `sysctl -w
	// net.core.rmem_max=4194304` to allow the full 4 MB.
	type readBufferSetter interface {
		SetReadBuffer(int) error
	}
	if rbs, ok := conn.(readBufferSetter); ok {
		if err := rbs.SetReadBuffer(4 * 1024 * 1024); err != nil {
			errors.LogWarning(context.Background(),
				"DIAG: SetReadBuffer(4MB) failed: ", err)
		} else {
			errors.LogInfo(context.Background(),
				"DIAG: SetReadBuffer(4MB) ok local=", conn.LocalAddr())
		}
	}
	// v26.12.39: Also store in the worker's shared socket map so future
	// QUIC connections from the same client to the same server reuse
	// this socket (stable source port, no migration detection).
	if c.worker != nil {
		key := c.src.String() + "->" + dest.String()
		c.worker.SetSharedOutboundConn(key, conn)
		errors.LogInfo(context.Background(),
			"DIAG: shared socket stored key=", key,
			" local=", conn.LocalAddr())
	}
}

// v26.12.39: GetSharedOutboundConn checks if a shared socket exists for
// this (client source, destination) pair. Called by freedom.Process before
// dialing to potentially reuse an existing socket with a stable source port.
func (c *udpConn) GetSharedOutboundConn(dest net.Destination) net.Conn {
	if c.worker == nil || c.src == nil {
		return nil
	}
	key := c.src.String() + "->" + dest.String()
	conn := c.worker.GetSharedOutboundConn(key)
	if conn != nil {
		// Check if the shared socket is still alive
		if conn.RemoteAddr() == nil {
			return nil
		}
		errors.LogInfo(context.Background(),
			"DIAG: shared socket REUSED key=", key,
			" local=", conn.LocalAddr())
	}
	return conn
}

// v26.12.27: EnsureSessionReader starts a permanent reader goroutine.
// v26.12.35-link: REMOVED sync.Once — made reader restartable. The old
// sync.Once meant the goroutine could die permanently (when SetOutboundConn
// closed the old socket on CDN rotation) and never restart. Now each call
// checks if the reader is alive and starts a new one if not.
// v26.12.29-link: reads from outboundConn (set by SetOutboundConn).
func (c *udpConn) EnsureSessionReader() {
	c.sessionReaderMu.Lock()
	defer c.sessionReaderMu.Unlock()

	// v26.12.45: Diagnostic — log every call so we can see how many
	// times this is called vs how many readers actually start.
	// If 138 SetOutboundConn calls produce only 9 reader STARTs, this
	// log will show whether the alive guard is the gate.
	errors.LogWarning(context.Background(),
		"DIAG: EnsureSessionReader called alive=", c.sessionReaderAlive,
		" conn=", c.outboundConn != nil,
		" src=", c.src)

	// Already running — don't start a second one
	if c.sessionReaderAlive {
		return
	}

	// Initialize channels if needed.
	// v26.12.43: Enlarged from 1024 to 8192 to absorb Google's burst rate
	// (observed 2260 pkt/s = 22 Mbit/s during ramp-up). 1024 slots = 450 ms
	// headroom at burst rate; 8192 = 3.6 s. Combined with blocking send
	// (below) and a 4 MB kernel receive buffer, this should drop to zero
	// during normal QUIC ramp-ups. The previous 1024-slot channel overflowed
	// in 5 seconds and dropped 1574 packets, collapsing QUIC's cwnd.
	if c.sessionReplyCh == nil {
		c.sessionReplyCh = make(chan []byte, 8192)
	}
	// v26.12.45: Fix the dn channel bug. Close() closes sessionReaderDn
	// but never sets it to nil. The old code only checked == nil, so a
	// closed-but-not-nil channel was passed to the goroutine, which
	// immediately exited on `case <-dn: return` — before the START log.
	// This caused sockRead=0: the reader "started" but never read anything.
	// Fix: check if the channel is closed (non-blocking recv) and create
	// a new one if so.
	if c.sessionReaderDn == nil {
		c.sessionReaderDn = make(chan struct{})
	} else {
		select {
		case <-c.sessionReaderDn:
			// Channel is closed (from a previous Close() call) — create fresh.
			errors.LogWarning(context.Background(),
				"DIAG: EnsureSessionReader dn was CLOSED, creating new channel src=", c.src)
			c.sessionReaderDn = make(chan struct{})
		default:
			// Channel is open — reuse it.
		}
	}

	// v26.12.45: Drain stale packets from the channel. If a previous
	// Process's responseDone exited (buf.Copy returned) but the reader
	// kept running, it filled the channel with packets that no consumer
	// ever read. Those packets are now stale (the Process that needed
	// them is gone). Draining prevents the new Process from receiving
	// old packets AND prevents the reader from being blocked on a full
	// channel (the second bug: sockRead freezes at a non-zero value
	// because the reader is blocked on `sessionReplyCh <- pkt` with
	// no consumer).
	drained := 0
	for {
		select {
		case <-c.sessionReplyCh:
			drained++
		default:
			goto drainDone
		}
	}
drainDone:
	if drained > 0 {
		errors.LogWarning(context.Background(),
			"DIAG: EnsureSessionReader drained=", drained, " stale packets from channel src=", c.src)
	}

	c.sessionReaderAlive = true
	dn := c.sessionReaderDn

	go func() {
		defer func() {
			c.sessionReaderMu.Lock()
			c.sessionReaderAlive = false
			c.sessionReaderMu.Unlock()
		}()

		b := make([]byte, 65535)
		// v26.12.44: Track whether we've logged the START and FIRST READ
		// for this reader instance. These one-shot diagnostics confirm:
		//   - START: the reader goroutine actually launched (and when)
		//   - FIRST READ: the reader successfully read at least one packet
		// If sockRead=0 appears in the counter without a matching FIRST READ,
		// the reader is blocked on oc.Read() — likely on a stale socket that
		// was replaced by SetOutboundConn while the reader was blocked.
		loggedStart := false
		loggedFirstRead := false
		for {
			select {
			case <-dn:
				return
			default:
			}
			c.outboundMu.Lock()
			oc := c.outboundConn
			c.outboundMu.Unlock()
			if oc == nil {
				// Socket not set yet — wait and retry instead of dying
				select {
				case <-dn:
					return
				case <-time.After(100 * time.Millisecond):
					continue
				}
			}
			if !loggedStart {
				loggedStart = true
				// v26.12.46: Include client source port so reader START can be
				// correlated with DIAG COUNTERS src=udp:... lines. Without this,
				// there's no way to match a reader START to a specific connection.
				var srcStr string
				if c.src != nil {
					srcStr = c.src.String()
				}
				errors.LogWarning(context.Background(),
					"DIAG: reader START src=", srcStr,
					" local=", oc.LocalAddr(),
					" remote=", oc.RemoteAddr())
			}
			// v26.12.44: Set a 1-second read deadline so oc.Read() can't
			// block forever on a stale socket. If SetOutboundConn replaces
			// the socket while we're blocked on Read, Go on Linux does NOT
			// reliably unblock the Read on Close() — the goroutine stays
			// stuck on the dead socket forever. sessionReaderAlive stays
			// true (goroutine isn't dead, just blocked), so EnsureSessionReader
			// won't restart it. sockRead freezes. This deadline forces Read
			// to return every 1s; on timeout we loop back, re-read
			// c.outboundConn (picking up any replacement), and retry.
			type deadlineSetter interface {
				SetReadDeadline(time.Time) error
			}
			if ds, ok := oc.(deadlineSetter); ok {
				_ = ds.SetReadDeadline(time.Now().Add(1 * time.Second))
			}
			n, err := oc.Read(b)
			if err != nil {
				// v26.12.44: Check for timeout before incrementing sockErr.
				// A timeout is EXPECTED — it means no packets arrived in 1s.
				// Don't log it as an error, don't increment sockErr, just retry.
				var ne stdnet.Error
				if stderrors.As(err, &ne) && ne.Timeout() {
					// Read deadline expired — no packets in 1s. Loop back,
					// re-read c.outboundConn (in case it was replaced), retry.
					// This is the critical fix: if the socket was replaced
					// while we were blocked, we now pick up the new one.
					continue
				}
				c.cntSockErr.Add(1)
				errors.LogWarning(context.Background(),
					"DIAG: reader EXIT sockErr=", c.cntSockErr.Load(),
					" sockRead=", c.cntSockRead.Load(),
					" err=", err)
				select {
				case <-dn:
					return
				default:
				}
				var errno syscall.Errno
				if stderrors.As(err, &errno) {
					switch errno {
					case syscall.EAGAIN, syscall.ENOMEM, syscall.ENOBUFS,
						syscall.EHOSTUNREACH, syscall.ENETUNREACH, syscall.ECONNREFUSED:
						continue
					}
				}
				return
			}
			if !loggedFirstRead {
				loggedFirstRead = true
				errors.LogWarning(context.Background(),
					"DIAG: reader FIRST READ n=", n,
					" local=", oc.LocalAddr(),
					" sockRead=", c.cntSockRead.Load()+1)
			}
			c.cntSockRead.Add(1)
			pkt := make([]byte, n)
			copy(pkt, b[:n])
			// v26.12.57: Content integrity — hash at read point.
			c.cntReadBytes.Add(int64(n))
			c.cntReadHash.Add(int64(crc32.ChecksumIEEE(pkt)))
			// v26.12.41-link: Register server SCID from long-header replies.
			// The server's Initial/Handshake reply carries its SCID, which
			// Chrome uses as the DCID for 1-RTT packets. Without registering
			// it in dcidIndex, every 1-RTT packet falls back to srcIndex
			// routing — which sends packets to the wrong server when multiple
			// QUIC connections share a client source port.
			if c.registerServerCID != nil && len(pkt) > 0 && pkt[0]&0x80 != 0 {
				if scid, _, perr := quic.ParseSCID(pkt); perr == nil && len(scid) > 0 {
					c.registerServerCID(scid)
				}
			}
			// v26.12.43: Removed the `default:` drop path — a relay must
			// never silently drop a QUIC packet.
			// v26.12.46: THE DEADLOCK FIX. v26.12.43's blocking send
			// traded a drop for a deadlock: if the consumer (responseDone →
			// sessionReplyReader) exits, the channel fills to capacity and
			// the reader blocks on the next send forever. sockRead freezes
			// at a non-zero value, chDrop=0, sockErr=0, no reader EXIT —
			// a clean-looking black hole. The kernel buffer then fills,
			// Google sees loss, and the connection collapses silently.
			//
			// Fix: bounded block. If the channel stays full for 5 seconds,
			// the consumer is dead. Log it, exit the reader (which sets
			// sessionReaderAlive=false via defer), and let EnsureSessionReader
			// restart it when a new consumer appears. The 5s bound is
			// generous — a live consumer draining at even 10 pkt/s would
			// never trigger it. Only a dead consumer does.
			select {
			case c.sessionReplyCh <- pkt:
			case <-dn:
				return
			case <-time.After(5 * time.Second):
				errors.LogWarning(context.Background(),
					"DIAG: reader BLOCKED on full channel 5s, exiting. depth=",
					len(c.sessionReplyCh),
					" sockRead=", c.cntSockRead.Load(),
					" src=", c.src)
				return
			}
		}
	}()
}

// v26.12.27: ReadSessionReply returns one reply packet from the permanent
// reader goroutine. Called by freedom.Process's responseDone.
// v26.12.35-link: guard against nil channels — return false instead of
// hanging forever if reader was never started or died.
func (c *udpConn) ReadSessionReply() ([]byte, bool) {
	ch := c.sessionReplyCh
	dn := c.sessionReaderDn
	if ch == nil || dn == nil {
		return nil, false
	}
	select {
	case pkt, ok := <-c.sessionReplyCh:
		return pkt, ok
	case <-c.sessionReaderDn:
		return nil, false
	}
}

// v26.12.36-link: Counter methods for the QUIC reply path diagnostics.
// Called from freedom.go's requestDone to count packets sent to Google.
func (c *udpConn) IncReqSent()          { c.cntReqSent.Add(1) }
func (c *udpConn) IncReqSentBy(n int64) { c.cntReqSent.Add(n) } // v26.12.42

// GetCounters returns a snapshot of all reply-path counters for logging.
func (c *udpConn) GetCounters() (sockRead, sockErr, chDrop, replyOut, reqSent, pipeDrop int64) {
	pd := int64(0)
	if c.cntPipeDrop != nil {
		pd = c.cntPipeDrop.Load()
	}
	return c.cntSockRead.Load(), c.cntSockErr.Load(), c.cntChDrop.Load(),
		c.cntReplyOut.Load(), c.cntReqSent.Load(), pd
}

// v26.12.36-link: StartCounterLogger starts a goroutine that logs the
// reply-path counters every 5 seconds. This tells us exactly which
// segment of the reply path dies after the QUIC handshake.
func (c *udpConn) StartCounterLogger(src string) {
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-c.sessionReaderDn:
				return
			case <-t.C:
				sr, se, cd, ro, rs, pd := c.GetCounters()
				if sr == 0 && ro == 0 && rs == 0 && pd == 0 {
					continue // no activity yet, skip
				}
				// v26.12.51: Include destination so the reqSent:sockRead ratio
				// can be correlated with content (video vs thumbnail).
				destStr := ""
				c.outboundMu.Lock()
				if c.outboundDest.IsValid() {
					destStr = c.outboundDest.String()
				}
				c.outboundMu.Unlock()
				errors.LogWarning(context.Background(),
					"DIAG COUNTERS src=", src,
					" dest=", destStr,
					" sockRead=", sr,
					" sockErr=", se,
					" chDrop=", cd,
					" replyOut=", ro,
					" reqSent=", rs,
					" pipeDrop=", pd,
					" nilAddr=", c.cntNilAddr.Load(),
					" ruleBlock=", c.cntRuleBlock.Load(),
					" writeErr=", c.cntWriteErr.Load(),
					" readB=", c.cntReadBytes.Load(),
					" writeB=", c.cntWriteBytes.Load(),
					" readH=", c.cntReadHash.Load(),
					" writeH=", c.cntWriteHash.Load())
				// v26.12.49: Also log worker-level inbound drops.
				if c.worker != nil {
					c.worker.LogWorkerDrops()
				}
			}
		}
	}()
}

// v26.12.53: mostRecentConnForIP finds the most recently active
// connection for a given client IP address. Used as a last-resort
// fallback for 1-RTT packets with empty DCIDs arriving from a source
// port the demux doesn't know (QUIC connection migration / new socket).
// Returns nil if no active conn exists for that IP.
//
// v26.12.56: CONSTRAINED to single-connection cases only. When multiple
// connections exist for the same client IP, the fallback would pick the
// most recently active one — but with 14 connections live, it frequently
// picks the WRONG one. A misattributed ACK goes to the wrong Google edge,
// that edge never gets its ACKs, its window stalls, and the video dies.
// The one that played was the one whose attribution happened to be right.
//
// Now: only return a conn when exactly one active conn exists for this IP.
// When multiple exist, return nil (drop) — a drop is recoverable by QUIC
// retransmission; a misroute poisons both connections.
func (w *udpWorker) mostRecentConnForIP(addr net.Address) *udpConn {
	var best *udpConn
	var bestTime int64
	count := 0
	w.RLock()
	for _, c := range w.activeConn {
		if c.done.Done() || c.src == nil {
			continue
		}
		// Match by IP address (not port — the port may have changed)
		if c.src.Address == addr {
			count++
			lat := atomic.LoadInt64(&c.lastActivityTime)
			if lat > bestTime {
				bestTime = lat
				best = c
			}
		}
	}
	w.RUnlock()
	// v26.12.56: Only return a conn when there's exactly one for this IP.
	// With multiple conns, we can't know which one this packet belongs to,
	// and guessing sends ACKs to the wrong server.
	if count != 1 {
		if count > 1 {
			w.cntFallbackRefusedMulti.Add(1)
			errors.LogWarning(context.Background(),
				"DIAG: IP fallback REFUSED (multi-conn) count=", count,
				" addr=", addr)
		}
		return nil
	}
	return best
}

// v26.12.53: learnSrc registers a source port for an existing conn,
// so future packets from that port route normally via srcIndex.
// Called when the IP-based fallback attributes a packet to a conn
// whose source port differs from the packet's source port.
func (c *udpConn) learnSrc(srcKey srcKey) {
	if c.worker == nil {
		return
	}
	c.worker.Lock()
	// Don't overwrite if another conn already owns this srcKey
	if _, exists := c.worker.srcIndex[srcKey]; !exists {
		c.worker.srcIndex[srcKey] = c.connID
		c.worker.cntPortLearned.Add(1)
	}
	c.worker.Unlock()
}

// v26.12.54: GetDropCounters returns pointers to the PacketWriter drop
// counters. Called from freedom.go to wire them into PacketWriter.
func (c *udpConn) GetDropCounters() (*atomic.Int64, *atomic.Int64, *atomic.Int64, *atomic.Int64) {
	return &c.cntNilAddr, &c.cntRuleBlock, &c.cntResolveFail, &c.cntSystemResolveFail
}

// v26.12.49: GetWorkerDrops returns worker-level inbound drop counters.
func (w *udpWorker) GetWorkerDrops() (shortDrop, fallbackRefused, selfDialDropped, attributedFallback int64) {
	return w.cntShortDrop.Load(), w.cntFallbackRefused.Load(), w.cntSelfDialDropped.Load(),
		w.cntAttributedFallback.Load()
}

// v26.12.59: GetRoutingCounts returns per-routing-method counters.
func (w *udpWorker) GetRoutingCounts() (srcHit, cidHit, cidHitAlt, ipFallback, fallbackRefusedMulti, shortDropNoConn, newConnFromShort, pktIn, longHdr, portLearned int64) {
	return w.cntSrcHit.Load(), w.cntCidHit.Load(), w.cntCidHitAlt.Load(),
		w.cntIpFallback.Load(), w.cntFallbackRefusedMulti.Load(),
		w.cntShortDropNoConn.Load(), w.cntNewConnFromShort.Load(),
		w.cntPktIn.Load(), w.cntLongHdr.Load(), w.cntPortLearned.Load()
}

// v26.12.49: LogWorkerDrops logs worker-level drop counters periodically.
func (w *udpWorker) LogWorkerDrops() {
	sd, fr, sdd, af := w.GetWorkerDrops()
	sh, ch, cha, ipf, frm, sdn, ncs, pi, lh, pl := w.GetRoutingCounts()
	identityCheck := sh + ch + cha + ipf + frm + sdn + ncs + lh
	bal := pi - identityCheck
	if sd > 0 || fr > 0 || sdd > 0 || af > 0 || pi > 0 {
		errors.LogWarning(context.Background(),
			"DIAG ROUTING pktIn=", pi,
			" longHdr=", lh,
			" srcHit=", sh,
			" cidHit=", ch,
			" cidHitAlt=", cha,
			" ipFallback=", ipf,
			" fbRefusedMulti=", frm,
			" shortDropNoConn=", sdn,
			" newConnFromShort=", ncs,
			" portLearned=", pl,
			" unbalanced=", bal,
			" tag=", w.tag)
	}
}

// v26.11.202: GetPooledConn returns the persistent pooledConn.
// Called by freedom.Process to check if a previous Process call left
// a pooledConn that can be reused (goroutine restart for short headers).
func (c *udpConn) GetPooledConn() interface{} {
	return c.pooledConnPtr
}

// v26.11.202: SetPooledConn stores the pooledConn for reuse by future
// Process calls. Called by freedom.Process after creating a pooledConn.
func (c *udpConn) SetPooledConn(pc interface{}) {
	c.pooledConnPtr = pc
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

// v26.11.156: SetRegisterPoolCID sets the callback for registering
// new DCIDs in the pool's demux. Called by freedom when the pool is used.
func (c *udpConn) SetRegisterPoolCID(f func([]byte)) {
	c.registerPoolCID = f
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
	c.cntReplyOut.Add(1)
	// v26.12.57: Content integrity — hash at write point.
	// Computed BEFORE SplitCoalesced so it matches the read-side hash
	// of the original datagram.
	c.cntWriteBytes.Add(int64(len(buf)))
	c.cntWriteHash.Add(int64(crc32.ChecksumIEEE(buf)))
	// v26.11.144: Re-add SplitCoalesced (from v26.11.55).
	// Packets > 1250 bytes are split into separate UDP datagrams.
	// This allows coalesced QUIC packets (Initial+Handshake) to be
	// delivered even when the path MTU can't handle the full packet.
	// v26.12.63: Removed SplitCoalesced. Coalesced QUIC packets MUST
	// be delivered as a single UDP datagram. Splitting them breaks QUIC
	// semantics — the client receives fragments that aren't valid
	// standalone QUIC packets, causing protocol errors.
	n, err := c.output(buf)
	if c.downlink != nil {
		c.downlink.Add(int64(n))
	}
	if err != nil {
		c.cntWriteErr.Add(1)
		errors.LogWarning(context.Background(),
			"DIAG: udpConn.Write ERROR err=", err, " src=", c.src)
	} else {
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
	// v26.12.27: Stop the session reader goroutine and close the socket.
	if c.sessionReaderDn != nil {
		close(c.sessionReaderDn)
		// v26.12.45: Set to nil so EnsureSessionReader creates a fresh one
		// on restart. Without this, the closed-but-not-nil channel causes
		// the reader goroutine to exit immediately on `case <-dn: return`.
		c.sessionReaderDn = nil
	}
	c.sessionSocketMu.Lock()
	if c.sessionSocket != nil {
		c.sessionSocket.Close()
		c.sessionSocket = nil
	}
	c.sessionSocketMu.Unlock()
	// v26.11.196: Close the persistent outbound conn too. Without this,
	// Process restarts accumulate outbound sockets (one per dial), which
	// eventually exhausts file descriptors and stalls new connections.
	c.outboundMu.Lock()
	if c.outboundConn != nil {
		c.outboundConn.Close()
		c.outboundConn = nil
	}
	c.outboundMu.Unlock()
	// v26.11.231: Close the persistent pooledConn too. Without this,
	// pool sockets survive udpConn retirement and accumulate forever
	// (the pool's refCount never reaches 0, so the reaper never evicts
	// them). Closing the pooledConn here decrements refCount so the
	// reaper can do its job.
	//
	// The interface{} dance avoids an import cycle: app/proxyman/inbound
	// cannot import proxy/freedom (which would form a cycle through
	// proxy/proxyman/etc.), so the pooledConn pointer is stored as
	// interface{} and only Close() is called via a tiny interface.
	if c.pooledConnPtr != nil {
		type closer interface{ Close() error }
		if pc, ok := c.pooledConnPtr.(closer); ok {
			pc.Close()
		}
		c.pooledConnPtr = nil
	}
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

	// v26.12.39-link: Shared outbound sockets per (client source, destination).
	// One socket per (client port, Google IP) held across QUIC connections.
	// This keeps the source port stable so Google doesn't see connection migration.
	// No demux needed — every packet on this socket belongs to that one client.
	sharedSockets   map[string]net.Conn
	sharedSocketsMu sync.Mutex

	// v26.12.49: Worker-level counters for inbound packet drops.
	cntShortDrop       atomic.Int64
	cntFallbackRefused atomic.Int64
	// v26.12.50: Self-dial drops (127.0.0.1 on our own port).
	cntSelfDialDropped atomic.Int64
	// v26.12.53: Packets routed via client-IP fallback (empty DCID +
	// unknown source port). These are 1-RTT packets from a migrated
	// source port that the demux can't identify by CID or by port.
	cntAttributedFallback atomic.Int64
	// v26.12.59: Routing-method counters. Until now, shortDrop=0 could
	// mean "everything routed correctly" OR "everything routed by IP
	// fallback (which misroutes)". These distinguish:
	cntSrcHit               atomic.Int64 // routed by srcIndex (known port)
	cntCidHit               atomic.Int64 // routed by DCID lookup (default 8 bytes)
	cntCidHitAlt            atomic.Int64 // routed by alt CID length (from dcidIndex keys)
	cntIpFallback           atomic.Int64 // routed by IP fallback (single-conn)
	cntFallbackRefusedMulti atomic.Int64 // IP fallback refused (multi-conn) — was never incremented before v26.12.59
	cntShortDropNoConn      atomic.Int64 // dropped: no conn found for this IP
	cntNewConnFromShort     atomic.Int64 // invisible path: short header created a NEW conn (orphaned 1-RTT re-homed)
	// v26.12.60: Identity-check counters.
	cntPktIn       atomic.Int64 // every UDP packet entering callback
	cntLongHdr     atomic.Int64 // long-header packets (Initials etc)
	cntPortLearned atomic.Int64 // learnSrc actually inserted a new key

	ctx  context.Context
	cone bool
}

// v26.12.39: GetSharedOutboundConn returns a shared outbound socket for
// (client source, destination) if one exists. This keeps the source port
// stable across QUIC connections from the same client to the same server.
func (w *udpWorker) GetSharedOutboundConn(key string) net.Conn {
	w.sharedSocketsMu.Lock()
	defer w.sharedSocketsMu.Unlock()
	return w.sharedSockets[key]
}

// v26.12.39: SetSharedOutboundConn stores a shared outbound socket.
func (w *udpWorker) SetSharedOutboundConn(key string, conn net.Conn) {
	w.sharedSocketsMu.Lock()
	defer w.sharedSocketsMu.Unlock()
	if old := w.sharedSockets[key]; old != nil && old != conn {
		old.Close()
	}
	w.sharedSockets[key] = conn
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
	pReader, pWriter := pipe.New(pipe.DiscardOverflow(), pipe.WithSizeLimit(64*1024))
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
		connID:   id, // v26.12.53: stored for learnSrc (IP fallback)
		worker:   w,  // v26.12.39: back-reference for shared socket
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
		return w.hub.WriteTo(b, srcCopy)
	}
	w.activeConn[id] = conn

	conn.updateActivity()
	return conn, false
}

func (w *udpWorker) callback(b *buf.Buffer, source net.Destination, originalDest net.Destination) {
	w.cntPktIn.Add(1)
	if pb := b.Bytes(); len(pb) > 0 && pb[0]&0x80 != 0 {
		w.cntLongHdr.Add(1)
	}
	// v26.12.50: Self-dial guard. A destination of 127.0.0.1 on this
	// inbound's own listen port means the sniffer hasn't produced a
	// destination yet and dokodemo's !FollowRedirect placeholder leaked
	// through. Dialling it connects to ourselves and the reader then waits
	// forever on a socket that can never receive a reply.
	// Drop it and let the client retransmit the Initial.
	// Port-based check: dest.Port == w.port. This can't touch DNS on :53.
	if originalDest.IsValid() && originalDest.Port == w.port &&
		originalDest.Address.Family().IsIP() && originalDest.Address.IP().IsLoopback() {
		w.cntSelfDialDropped.Add(1)
		b.Release()
		return
	}
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
	// v26.11.117: DCID-first routing for short headers.
	//
	// Chrome multiplexes multiple QUIC connections through ONE UDP socket
	// (same source port). The old Solution A routed ALL short headers from
	// a source port to the FIRST connection — connection #2's packets went
	// to connection #1's server, causing stalls.
	//
	// Fix: For short headers, try DCID lookup FIRST. The DCID in a 1-RTT
	// short header is the server's SCID (learned from the server's Initial
	// reply). If dcidIndex has it, route to the correct conn.
	//
	// Fall back to srcIndex only if DCID lookup misses AND there's exactly
	// one conn for this source (safe for single-connection cases like h3
	// test sites).
	if !id.dest.IsValid() && len(b.Bytes()) > 0 && b.Bytes()[0]&0x80 == 0 {
		// Try DCID lookup first
		if dcid, _, err := quic.ParseDCID(b.Bytes()); err == nil && len(dcid) > 0 {
			dk := makeDCIDKey(dcid)
			w.RLock()
			if existingID, found := w.dcidIndex[dk]; found {
				if existingConn, connFound := w.activeConn[existingID]; connFound && !existingConn.done.Done() {
					w.RUnlock()
					w.cntCidHit.Add(1)
					// v26.12.58: Bind the source port so future packets
					// from this port go through the fast path (srcIndex),
					// which handles CID rotation. Without this, every
					// packet from a new port does a DCID lookup, and
					// CID rotation registration (which only fires when
					// the port is known) never runs → rotated CIDs
					// are never registered → the next rotation kills
					// the connection.
					existingConn.learnSrc(id.srcKey)
					existingConn.writer.WriteMultiBuffer(buf.MultiBuffer{b})
					existingConn.updateActivity()
					return
				}
			}
			w.RUnlock()
			// v26.12.59: Try alt CID lengths derived from dcidIndex keys.
			// dcidKey is length-tagged (cid [20]byte; len int), so a 4-byte
			// parse can only match a registered 4-byte CID — no cross-length
			// false positives. The default 8 was already tried above.
			triedLens := map[int]bool{8: true}
			w.RLock()
			for dk := range w.dcidIndex {
				if !triedLens[dk.len] {
					triedLens[dk.len] = true
					if 1+dk.len <= len(b.Bytes()) {
						altDcid := b.Bytes()[1 : 1+dk.len]
						altDk := makeDCIDKey(altDcid)
						if existingID, found := w.dcidIndex[altDk]; found {
							if existingConn, connFound := w.activeConn[existingID]; connFound && !existingConn.done.Done() {
								w.RUnlock()
								w.cntCidHitAlt.Add(1)
								existingConn.learnSrc(id.srcKey)
								existingConn.writer.WriteMultiBuffer(buf.MultiBuffer{b})
								existingConn.updateActivity()
								return
							}
						}
					}
				}
			}
			w.RUnlock()
		}

		// v26.12.41-link: DCID miss — fall back to srcIndex ONLY when
		// that source port has exactly one active connection. If multiple
		// connections share the port, routing to the wrong one sends
		// packets to the wrong server. A drop is recoverable by QUIC;
		// a misroute poisons both connections.
		w.RLock()
		if existingID, found := w.srcIndex[id.srcKey]; found {
			if existingConn, connFound := w.activeConn[existingID]; connFound && !existingConn.done.Done() {
				// Count active conns for this source port
				activeCount := 0
				for _, c := range w.activeConn {
					if !c.done.Done() && c.src != nil && c.src.Port == id.src.Port {
						activeCount++
					}
				}
				if activeCount <= 1 {
					w.RUnlock()
					w.cntSrcHit.Add(1)
					existingConn.writer.WriteMultiBuffer(buf.MultiBuffer{b})
					existingConn.updateActivity()
					return
				}
				// Multiple conns — don't guess. Drop and let QUIC retransmit.
				w.RUnlock()
				w.cntShortDrop.Add(1)
				errors.LogWarning(context.Background(),
					"DIAG: short header DROPPED (multi-conn srcKey) src=", source)
				b.Release()
				return
			}
		}
		w.RUnlock()

		// v26.11.120: Short headers that miss BOTH DCID and srcIndex.
		// v26.12.38-link: Log the drop.
		// v26.12.49: Count it.
		// v26.12.53: Before dropping, try the client-IP fallback.
		//   The user's original diagnosis was right: Chrome sends 1-RTT
		//   packets with an empty DCID (DCID=0). When the source port
		//   is also unknown (migration / new socket), the demux has
		//   nothing to route by — and dropping kills the connection
		//   at the exact moment Chrome switches to 1-RTT.
		//   Fix: attribute to the most recently active conn for this
		//   client IP, and learn the new source port so future packets
		//   route normally via srcIndex.
		dcidLen := 0
		if d, _, e := quic.ParseDCID(b.Bytes()); e == nil {
			dcidLen = len(d)
		}
		if conn := w.mostRecentConnForIP(source.Address); conn != nil {
			// Attribute this packet to the most recent conn for this IP.
			// learnSrc teaches the demux this source port so future
			// packets route normally without needing the fallback.
			conn.learnSrc(id.srcKey)
			conn.writer.WriteMultiBuffer(buf.MultiBuffer{b})
			conn.updateActivity()
			w.cntIpFallback.Add(1)
			w.cntAttributedFallback.Add(1)
			errors.LogWarning(context.Background(),
				"DIAG: short header ATTRIBUTED via IP fallback src=", source,
				" dcidLen=", dcidLen,
				" -> conn src=", conn.src)
			return
		}
		// No conn found for this IP — genuine unknown packet. Drop it.
		w.cntShortDropNoConn.Add(1)
		errors.LogWarning(context.Background(),
			"DIAG: short header DROPPED (no conn for IP) src=", source,
			" dcidLen=", dcidLen,
			" firstByte=", b.Bytes()[0])
		b.Release()
		return
	}
	// Try QUIC DCID-based migration lookup before creating a new conn
	if migratedConn := w.tryQUICMigration(b.Bytes(), id); migratedConn != nil {
		migratedConn.writer.WriteMultiBuffer(buf.MultiBuffer{b})
		migratedConn.updateActivity()
		return
	}

	conn, existing := w.getConnection(id)

	// v26.12.59: Count the invisible path — a short header that created
	// a NEW conn. This happens when a 1-RTT packet arrives from an unknown
	// port AND the DCID lookup missed (or was skipped because id.dest was
	// valid). The packet gets re-homed into a fresh conn with a fresh
	// outbound socket → Google sees a new source port → path validation
	// → "starts, then dies" shape. Until now this was invisible: it isn't
	// a drop, so no counter counted it.
	if !existing && len(b.Bytes()) > 0 && b.Bytes()[0]&0x80 == 0 {
		w.cntNewConnFromShort.Add(1)
		dcidLen := 0
		if d, _, e := quic.ParseDCID(b.Bytes()); e == nil {
			dcidLen = len(d)
		}
		errors.LogWarning(context.Background(),
			"DIAG: NEW conn from SHORT header src=", source,
			" dcidLen=", dcidLen,
			" dest=", id.dest)
	}

	// v26.12.36-link: Removed per-packet DIAG: EXISTING conn logging.
	// It fires on every steady-state packet at Warning level and floods the log.
	// Keep NEW conn, CID rotation, and Process RETURNED for diagnostics.

	// v26.11.118: REMOVED the C3 re-check block (v26.10.43/v26.10.78).
	// The re-check ALWAYS found the conn that getConnection just created
	// (because getConnection stores it in activeConn before returning),
	// setting existing=true and skipping the goroutine that starts
	// proxy.Process. This is why UDP QUIC traffic was silently dropped —
	// the goroutine never started, so the sniffer never ran, so the
	// dispatcher never routed the traffic.
	// getConnection already holds the lock during creation, so the race
	// is already prevented.

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

	// v26.11.196: Start (or restart) the Process goroutine. The condition
	// covers two cases:
	//   1. !existing — first packet for this conn, start the goroutine.
	//   2. existing && !processRunning — Process returned (e.g. from
	//      responseDone's goroutine-leak fix on a timer fire), but the
	//      conn is still alive. Restart it so the persistent
	//      outboundConn / pooledConnPtr are reused: this keeps the
	//      outbound source port stable (no Google path validation) and
	//      keeps the pool socket's DCID registrations alive.
	if !existing || (existing && !conn.processRunning.Load()) {
		if !existing {
			errors.LogWarning(context.Background(), "DIAG: NEW conn src=", source, " dest=", id.dest)
			common.Must(w.checker.Start())
		}
		conn.processRunning.Store(true)

		go func() {
			startTime := time.Now()
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
			errors.LogWarning(context.Background(), "DIAG: Process RETURNED src=", source, " after=", time.Since(startTime).Round(time.Millisecond))
			// v26.11.196: DON'T close conn or removeConn here.
			// The persistent outboundConn / pooledConnPtr survive
			// Process restarts. clean() retires the conn after
			// the idle timeout (SessionIdleSeconds) — and the
			// v26.11.212 activity tracking keeps it alive while
			// packets are flowing through the pool path.
			conn.processRunning.Store(false)
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
	// v26.11.117: Removed the short-header fast-path bypass.
	// Previously, short headers from a known source skipped DCID lookup
	// entirely and returned nil. This prevented DCID-based routing for
	// parallel QUIC connections sharing a source port.
	// Now short headers go through the full DCID lookup path.

	// v26.10.16-link: src-first fast path with zero-allocation struct keys.
	//
	// For steady-state 1-RTT traffic (99% of packets in a long-lived
	// QUIC connection), the source IP:port is already in srcIndex and
	// matches the existing conn. We check src FIRST using id.srcKey
	// (a precomputed 18-byte struct) so we can return nil (no
	// migration) without parsing the DCID, hex-encoding it, or
	// allocating any string. This eliminates 4 allocations per
	// inbound packet (the old id.src.String() triggered IP.String +
	// Port.String + two string concats).
	//
	// Only if src is unknown (new connection) OR src is known but the
	// dest differs (CID rotation) do we parse the DCID.
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
						// v26.11.156: Also register in pool's demux so
						// readLoop can route replies with the new DCID.
						// Without this, Google's replies with the rotated
						// DCID get dropped → connection dies after ~20s.
						if oldConn.registerPoolCID != nil {
							oldConn.registerPoolCID(newDcid)
						}
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
			// v26.11.165: For short-header packets (1-RTT), CID rotation
			// is the most likely cause. The new DCID won't be in dcidIndex
			// (it was never registered — it just arrived). But if the source
			// is known and the packet is a short header, register the new
			// DCID for the existing conn and return nil (same conn, no migration).
			// This prevents creating a new connection for CID rotation.
			if len(packet) > 0 && packet[0]&0x80 == 0 {
				if newDcid, _, err := quic.ParseDCID(packet); err == nil && len(newDcid) > 0 {
					newDk := makeDCIDKey(newDcid)
					if _, exists := w.dcidIndex[newDk]; !exists {
						// New DCID not in index → CID rotation.
						// Register it for this conn + pool demux.
						w.dcidIndex[newDk] = oldID
						if oldConn.registerPoolCID != nil {
							oldConn.registerPoolCID(newDcid)
						}
						w.Unlock()
						return nil
					}
				}
			}
			// Long header or DCID already exists → check dcidIndex
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
		w.sharedSockets = make(map[string]net.Conn) // v26.12.39
	}

	return nil
}

func (w *udpWorker) Start() error {
	w.activeConn = make(map[connID]*udpConn, 16)
	w.dcidIndex = make(map[dcidKey]connID)
	w.srcIndex = make(map[srcKey]connID)
	w.sharedSockets = make(map[string]net.Conn) // v26.12.39
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
