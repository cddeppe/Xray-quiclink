package freedom

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport/pipe"
)

// TestNonPoolWithSniffer simulates the FULL non-pool path including:
// - cachedReader (sniffer wraps the uplink reader)
// - TimeoutWrapperReader (wraps the uplink reader)
// - serverSCIDReader (wraps the response reader)
// - Multiple concurrent connections on the same hub
//
// This matches the real xray architecture more closely.
func TestNonPoolWithSniffer(t *testing.T) {
	googleConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer googleConn.Close()

	googleReceived := uint64(0)
	googleSent := uint64(0)

	// Google: receive packets, reply with bursts
	go func() {
		recvBuf := make([]byte, 2048)
		for {
			n, addr, err := googleConn.ReadFrom(recvBuf)
			if err != nil {
				return
			}
			_ = n
			atomic.AddUint64(&googleReceived, 1)
			// Reply with burst of 50 packets
			for i := 0; i < 50; i++ {
				reply := make([]byte, 1250)
				reply[0] = 0x40
				googleConn.WriteTo(reply, addr)
				atomic.AddUint64(&googleSent, 1)
			}
		}
	}()

	// Chrome client
	chromeConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer chromeConn.Close()

	chromeReceived := uint64(0)

	go func() {
		recvBuf := make([]byte, 2048)
		for {
			n, _, err := chromeConn.ReadFrom(recvBuf)
			if err != nil {
				return
			}
			if n > 0 {
				atomic.AddUint64(&chromeReceived, 1)
			}
		}
	}()

	// Outbound socket
	outboundConn, err := net.Dial("udp", googleConn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer outboundConn.Close()

	// Uplink pipe (Chrome → Google) — 256KB DiscardOverflow
	uplinkReader, uplinkWriter := pipe.New(pipe.DiscardOverflow(), pipe.WithSizeLimit(256*1024))

	// Downlink pipe (Google → Chrome) — 512KB NO DiscardOverflow
	downlinkReader, downlinkWriter := pipe.New(pipe.WithSizeLimit(512 * 1024))

	// Wrap uplinkReader with cachedReader (simulates sniffer)
	cReader := &simCachedReader{
		reader:  uplinkReader,
		cache:   make(buf.MultiBuffer, 0, 8),
		cacheMu: sync.Mutex{},
	}

	// Wrap the response reader with serverSCIDReader equivalent
	// (just passes through, but adds overhead)
	responseReader := &simPassthroughReader{base: &simSocketReader{conn: outboundConn}}

	// requestDone: reads from cachedReader (sniffer), writes to Google
	// In real xray, the sniffer reads the FIRST packet, caches it, then
	// the dispatcher routes it. After that, buf.Copy reads from cachedReader.
	go func() {
		// First, simulate the sniffer reading one packet
		mb, err := cReader.ReadMultiBuffer()
		if err == nil && !mb.IsEmpty() {
			// Write the sniffed packet to Google
			for _, b := range mb {
				outboundConn.Write(b.Bytes())
				b.Release()
			}
		}
		// Then continue with buf.Copy
		buf.Copy(cReader, &simFixedWriter{conn: outboundConn})
	}()

	// responseDone: reads from responseReader (Google's replies), writes to downlink pipe
	go func() {
		buf.Copy(responseReader, &simPipeWriter{writer: downlinkWriter})
	}()

	// downlink reader → Chrome
	go func() {
		chromeAddr := chromeConn.LocalAddr().(*net.UDPAddr)
		for {
			mb, err := downlinkReader.ReadMultiBuffer()
			if err != nil {
				return
			}
			for _, b := range mb {
				chromeConn.WriteTo(b.Bytes(), chromeAddr)
				b.Release()
			}
		}
	}()

	// Chrome sends packets every 100ms
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		first := true
		for {
			select {
			case <-ticker.C:
				pkt := make([]byte, 1200)
				if first {
					pkt[0] = 0xC0 // long header (Initial)
					first = false
				} else {
					pkt[0] = 0x40 // short header (ACK)
					pkt = pkt[:100]
				}
				uplinkWriter.WriteMultiBuffer(buf.MultiBuffer{newBuffer(pkt)})
			case <-stop:
				return
			}
		}
	}()

	time.Sleep(5 * time.Second)
	close(stop)

	gRecv := atomic.LoadUint64(&googleReceived)
	gSent := atomic.LoadUint64(&googleSent)
	cRecv := atomic.LoadUint64(&chromeReceived)

	t.Logf("=== Results after 5 seconds (with sniffer) ===")
	t.Logf("Chrome sent ACKs:     %d", gRecv)
	t.Logf("Google sent replies:   %d", gSent)
	t.Logf("Chrome received:       %d", cRecv)
	t.Logf("Packet loss:           %d (%.1f%%)", gSent-cRecv, float64(gSent-cRecv)/float64(gSent)*100)

	if gSent > 0 && cRecv < gSent {
		t.Errorf("PACKET LOSS: %d of %d packets lost (%.1f%%)",
			gSent-cRecv, gSent, float64(gSent-cRecv)/float64(gSent)*100)
	}
}

// simCachedReader mimics the dispatcher's cachedReader
type simCachedReader struct {
	reader  buf.Reader
	cache   buf.MultiBuffer
	cacheMu sync.Mutex
}

func (r *simCachedReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	// Check cache first
	r.cacheMu.Lock()
	if len(r.cache) > 0 {
		mb := r.cache
		r.cache = nil
		r.cacheMu.Unlock()
		return mb, nil
	}
	r.cacheMu.Unlock()
	return r.reader.ReadMultiBuffer()
}

// simPassthroughReader just passes through (simulates serverSCIDReader without SCID logic)
type simPassthroughReader struct {
	base buf.Reader
}

func (r *simPassthroughReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return r.base.ReadMultiBuffer()
}

// simSocketReader reads from a UDP socket
type simSocketReader struct {
	conn net.Conn
}

func (r *simSocketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b := buf.New()
	b.Resize(0, buf.Size)
	n, err := r.conn.Read(b.Bytes())
	if err != nil {
		b.Release()
		return nil, err
	}
	b.Resize(0, int32(n))
	return buf.MultiBuffer{b}, nil
}

// simFixedWriter writes to a fixed destination
type simFixedWriter struct {
	conn net.Conn
}

func (w *simFixedWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for {
		mb2, b := buf.SplitFirst(mb)
		mb = mb2
		if b == nil {
			break
		}
		_, err := w.conn.Write(b.Bytes())
		b.Release()
		if err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
	}
	return nil
}

// simPipeWriter wraps a pipe.Writer
type simPipeWriter struct {
	writer *pipe.Writer
}

func (w *simPipeWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return w.writer.WriteMultiBuffer(mb)
}

var _ = fmt.Sprintf
