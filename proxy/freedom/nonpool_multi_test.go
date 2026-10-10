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

// TestNonPoolMultipleConnections simulates MULTIPLE concurrent QUIC connections
// from the same Chrome source port, with CID rotation and lock contention.
// This matches the real YouTube pattern where Chrome multiplexes several
// QUIC connections through one UDP socket.
func TestNonPoolMultipleConnections(t *testing.T) {
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
                        for i := 0; i < 50; i++ {
                                reply := make([]byte, 1250)
                                reply[0] = 0x40
                                googleConn.WriteTo(reply, addr)
                                atomic.AddUint64(&googleSent, 1)
                        }
                }
        }()

        // Chrome client — single socket, multiple QUIC connections
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

        // Simulate the worker's lock + dcidIndex + srcIndex
        type connEntry struct {
                uplinkReader *pipe.Reader
                uplinkWriter *pipe.Writer
                downReader   *pipe.Reader
                downWriter   *pipe.Writer
                outboundConn net.Conn
                dcid         []byte
        }

        var workerMu sync.RWMutex
        conns := make(map[string]*connEntry) // keyed by DCID hex

        // Inbound hub simulation: receives from Chrome, routes to correct conn
        // based on DCID. This simulates callback() + tryQUICMigration.
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

                        // Parse DCID
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

                        // Write to the connection's uplink pipe
                        b := buf.New()
                        b.Write(pkt)
                        entry.uplinkWriter.WriteMultiBuffer(buf.MultiBuffer{b})
                }
        }()

        // Create multiple connections (simulating YouTube's DASH streaming)
        numConns := 3
        for i := 0; i < numConns; i++ {
                dcid := make([]byte, 8)
                rand.Read(dcid)
                dcidHex := fmt.Sprintf("%x", dcid)

                // Create outbound socket
                ob, err := net.Dial("udp", googleConn.LocalAddr().String())
                if err != nil {
                        t.Fatal(err)
                }

                // Create pipes — downlink with DiscardOverflow (v26.11.204 fix)
                upReader, upWriter := pipe.New(pipe.DiscardOverflow(), pipe.WithSizeLimit(256*1024))
                downReader, downWriter := pipe.New(pipe.DiscardOverflow(), pipe.WithSizeLimit(512*1024))

                entry := &connEntry{
                        uplinkReader: upReader,
                        uplinkWriter: upWriter,
                        downReader:   downReader,
                        downWriter:   downWriter,
                        outboundConn: ob,
                        dcid:         dcid,
                }

                workerMu.Lock()
                conns[dcidHex] = entry
                workerMu.Unlock()

                // requestDone: reads from uplink, writes to Google
                go func(e *connEntry) {
                        for {
                                mb, err := e.uplinkReader.ReadMultiBuffer()
                                if err != nil {
                                        return
                                }
                                for _, b := range mb {
                                        e.outboundConn.Write(b.Bytes())
                                        b.Release()
                                }
                        }
                }(entry)

                // responseDone: reads from Google, writes to downlink
                go func(e *connEntry) {
                        for {
                                b := buf.New()
                                b.Resize(0, buf.Size)
                                n, err := e.outboundConn.Read(b.Bytes())
                                if err != nil {
                                        b.Release()
                                        return
                                }
                                b.Resize(0, int32(n))
                                err = e.downWriter.WriteMultiBuffer(buf.MultiBuffer{b})
                                if err != nil {
                                        return
                                }
                        }
                }(entry)

                // downlink reader → Chrome
                go func(e *connEntry) {
                        chromeAddr := chromeConn.LocalAddr().(*net.UDPAddr)
                        for {
                                mb, err := e.downReader.ReadMultiBuffer()
                                if err != nil {
                                        return
                                }
                                for _, b := range mb {
                                        chromeConn.WriteTo(b.Bytes(), chromeAddr)
                                        b.Release()
                                }
                        }
                }(entry)

                t.Logf("Created connection %d with DCID %s", i, dcidHex)
        }

        // Chrome sends packets to all connections
        stop := make(chan struct{})
        go func() {
                ticker := time.NewTicker(100 * time.Millisecond)
                defer ticker.Stop()
                connIdx := 0
                for {
                        select {
                        case <-ticker.C:
                                // Get a connection
                                workerMu.RLock()
                                var entry *connEntry
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

                                // Create a short-header packet with this conn's DCID
                                pkt := make([]byte, 100)
                                pkt[0] = 0x40 // short header
                                // DCID is 8 bytes after the first byte
                                copy(pkt[1:9], entry.dcid)
                                entry.uplinkWriter.WriteMultiBuffer(buf.MultiBuffer{newBuffer(pkt)})
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

        t.Logf("=== Results after 5 seconds (%d concurrent connections) ===", numConns)
        t.Logf("Chrome sent ACKs:     %d", gRecv)
        t.Logf("Google sent replies:   %d", gSent)
        t.Logf("Chrome received:       %d", cRecv)
        t.Logf("Packet loss:           %d (%.1f%%)", gSent-cRecv, float64(gSent-cRecv)/float64(gSent)*100)

        if gSent > 0 && cRecv < gSent {
                t.Errorf("PACKET LOSS: %d of %d packets lost (%.1f%%)",
                        gSent-cRecv, gSent, float64(gSent-cRecv)/float64(gSent)*100)
        }
}
