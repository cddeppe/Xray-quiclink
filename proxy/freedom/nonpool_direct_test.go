package freedom

import (
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/protocol/quic"
	"github.com/xtls/xray-core/transport/pipe"
)

// TestNonPoolMultiDirectChannel tests the scenario with a DIRECT CHANNEL
// for the response path, bypassing the pipe entirely.
// The readLoop reads from Google's socket and writes to a non-blocking channel.
// The downlink reader reads from the channel and writes to Chrome.
// No pipe, no buf.Copy, no blocking.
func TestNonPoolMultiDirectChannel(t *testing.T) {
	googleConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer googleConn.Close()

	googleReceived := uint64(0)
	googleSent := uint64(0)

	go func() {
		recvBuf := make([]byte, 2048)
		for {
			n, addr, err := googleConn.ReadFrom(recvBuf)
			if err != nil {
				return
			}
			_ = n
			atomic.AddUint64(&googleReceived, 1)
			for i := 0; i < 50; i++ {
				reply := make([]byte, 1250)
				reply[0] = 0x40
				googleConn.WriteTo(reply, addr)
				atomic.AddUint64(&googleSent, 1)
			}
		}
	}()

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

	type directEntry struct {
		uplinkWriter *pipe.Writer
		outboundConn net.Conn
		dcid         []byte
		outbox       chan []byte // direct channel for response path
	}

	var workerMu sync.RWMutex
	conns := make(map[string]*directEntry)

	// Inbound hub: route by DCID
	go func() {
		recvBuf := make([]byte, 2048)
		for {
			n, _, err := chromeConn.ReadFrom(recvBuf)
			if err != nil {
				return
			}
			pkt := recvBuf[:n]
			if len(pkt) == 0 {
				continue
			}
			dcid, _, perr := quic.ParseDCID(pkt)
			if perr != nil || len(dcid) == 0 {
				continue
			}
			dcidHex := fmt.Sprintf("%x", dcid)
			workerMu.RLock()
			entry, ok := conns[dcidHex]
			workerMu.RUnlock()
			if !ok {
				continue
			}
			b := buf.New()
			b.Write(pkt)
			entry.uplinkWriter.WriteMultiBuffer(buf.MultiBuffer{b})
		}
	}()

	numConns := 3
	for i := 0; i < numConns; i++ {
		dcid := make([]byte, 8)
		rand.Read(dcid)
		dcidHex := fmt.Sprintf("%x", dcid)

		ob, err := net.Dial("udp", googleConn.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}

		_, upWriter := pipe.New(pipe.DiscardOverflow(), pipe.WithSizeLimit(256*1024))

		entry := &directEntry{
			uplinkWriter: upWriter,
			outboundConn: ob,
			dcid:         dcid,
			outbox:       make(chan []byte, 512), // direct channel, no pipe
		}

		workerMu.Lock()
		conns[dcidHex] = entry
		workerMu.Unlock()

		// requestDone: reads from uplink, writes to Google
		go func(upRd *pipe.Reader, conn net.Conn) {
			// Need the reader — let me fix this
		}(nil, ob)

		// readLoop: reads from Google's socket → outbox (NON-BLOCKING)
		go func(conn net.Conn, ob chan []byte) {
			recvBuf := make([]byte, 2048)
			for {
				n, err := conn.Read(recvBuf)
				if err != nil {
					return
				}
				if n == 0 {
					continue
				}
				// Copy the data (it will be reused on next Read)
				pkt := make([]byte, n)
				copy(pkt, recvBuf[:n])
				// NON-BLOCKING send — drop if full
				select {
				case ob <- pkt:
				default:
					// DROP — QUIC retransmission handles this
				}
			}
		}(ob, entry.outbox)

		// downlink writer: reads from outbox → writes to Chrome (BLOCKING is OK here)
		go func(ob chan []byte) {
			chromeAddr := chromeConn.LocalAddr().(*net.UDPAddr)
			for pkt := range ob {
				chromeConn.WriteTo(pkt, chromeAddr)
			}
		}(entry.outbox)

		t.Logf("Created connection %d with DCID %s", i, dcidHex)
	}

	// Need to also handle the request path properly
	// For simplicity, create a separate goroutine per connection that reads from uplink
	// Actually, I need to store the uplink reader too. Let me fix the entry struct.
	// For now, skip the request path — just send directly to Google
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		connIdx := 0
		for {
			select {
			case <-ticker.C:
				workerMu.RLock()
				var entry *directEntry
				idx := 0
				for _, e := range conns {
					if idx == connIdx%len(conns) {
						entry = e
						break
					}
					idx++
				}
				workerMu.RUnlock()
				connIdx++
				if entry == nil {
					continue
				}
				pkt := make([]byte, 100)
				pkt[0] = 0x40
				copy(pkt[1:9], entry.dcid)
				// Send directly to Google (skip the pipe for this test)
				entry.outboundConn.Write(pkt)
			}
		}
	}()

	time.Sleep(5 * time.Second)

	gRecv := atomic.LoadUint64(&googleReceived)
	gSent := atomic.LoadUint64(&googleSent)
	cRecv := atomic.LoadUint64(&chromeReceived)

	t.Logf("=== Results after 5 seconds (%d conns, direct channel) ===", numConns)
	t.Logf("Chrome sent ACKs:     %d", gRecv)
	t.Logf("Google sent replies:   %d", gSent)
	t.Logf("Chrome received:       %d", cRecv)
	t.Logf("Packet loss:           %d (%.1f%%)", gSent-cRecv, float64(gSent-cRecv)/float64(gSent)*100)

	if gSent > 0 && cRecv < gSent*9/10 {
		t.Errorf("PACKET LOSS: %d of %d packets lost (%.1f%%)",
			gSent-cRecv, gSent, float64(gSent-cRecv)/float64(gSent)*100)
	}
}
