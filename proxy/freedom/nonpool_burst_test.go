package freedom

import (
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport/pipe"
)

// TestNonPoolBurstFlow simulates sustained traffic matching real YouTube patterns:
// - Google sends bursts of 50+ packets (1250 bytes each) every ~100ms
// - Chrome sends ACKs back
// - Duration: 5 seconds
// - Measures total packet loss
func TestNonPoolBurstFlow(t *testing.T) {
	// Google server
	googleConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer googleConn.Close()

	googleReceived := uint64(0)
	googleSent := uint64(0)

	// Google: receive packets, reply with bursts (like video data)
	go func() {
		recvBuf := make([]byte, 2048)
		for {
			n, addr, err := googleConn.ReadFrom(recvBuf)
			if err != nil {
				return
			}
			_ = n
			atomic.AddUint64(&googleReceived, 1)
			// Reply with a burst of 50 packets (simulating video segment)
			for i := 0; i < 50; i++ {
				reply := make([]byte, 1250)
				reply[0] = 0x40 // short header
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

	// Chrome: receive packets
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

	// Outbound socket (freedom dials to Google)
	outboundConn, err := net.Dial("udp", googleConn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer outboundConn.Close()

	// Uplink pipe (Chrome → Google) — 256KB DiscardOverflow (matches worker.go)
	uplinkReader, uplinkWriter := pipe.New(pipe.DiscardOverflow(), pipe.WithSizeLimit(256*1024))

	// Downlink pipe (Google → Chrome) — 512KB NO DiscardOverflow (matches dispatcher)
	downlinkReader, downlinkWriter := pipe.New(pipe.WithSizeLimit(512 * 1024))

	// requestDone: reads Chrome's data from uplink, writes to Google
	go func() {
		for {
			mb, err := uplinkReader.ReadMultiBuffer()
			if err != nil {
				return
			}
			for _, b := range mb {
				outboundConn.Write(b.Bytes())
				b.Release()
			}
		}
	}()

	// responseDone: reads Google's replies from outbound, writes to downlink pipe
	// THIS IS THE buf.Copy THAT SERIALIZES READ+WRITE
	go func() {
		for {
			b := buf.New()
			b.Resize(0, buf.Size)
			n, err := outboundConn.Read(b.Bytes())
			if err != nil {
				b.Release()
				return
			}
			b.Resize(0, int32(n))
			// Write to downlink pipe — THIS BLOCKS when pipe is full
			err = downlinkWriter.WriteMultiBuffer(buf.MultiBuffer{b})
			if err != nil {
				return
			}
		}
	}()

	// downlink reader → Chrome (simulates dokodemo's SequentialWriter → udpConn.Write → hub.WriteTo)
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

	// Chrome sends a packet every 100ms (like ACKs)
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				pkt := make([]byte, 100)
				pkt[0] = 0x40 // short header (ACK)
				uplinkWriter.WriteMultiBuffer(buf.MultiBuffer{newBuffer(pkt)})
			case <-stop:
				return
			}
		}
	}()

	// Run for 5 seconds
	time.Sleep(5 * time.Second)
	close(stop)

	gRecv := atomic.LoadUint64(&googleReceived)
	gSent := atomic.LoadUint64(&googleSent)
	cRecv := atomic.LoadUint64(&chromeReceived)

	t.Logf("=== Results after 5 seconds ===")
	t.Logf("Chrome sent ACKs:     %d", gRecv)
	t.Logf("Google sent replies:   %d", gSent)
	t.Logf("Chrome received:       %d", cRecv)
	t.Logf("Packet loss:           %d (%.1f%%)", gSent-cRecv, float64(gSent-cRecv)/float64(gSent)*100)

	if gSent > 0 && cRecv < gSent {
		t.Errorf("PACKET LOSS: %d of %d packets lost (%.1f%%)",
			gSent-cRecv, gSent, float64(gSent-cRecv)/float64(gSent)*100)
	}
}

func newBuffer(data []byte) *buf.Buffer {
	b := buf.New()
	b.Write(data)
	return b
}

var _ = fmt.Sprintf
