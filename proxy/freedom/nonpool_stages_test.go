package freedom

import (
        "crypto/rand"
        "fmt"
        "net"
        "sync"
        "sync/atomic"
        "testing"
        "time"

        "github.com/xtls/xray-core/common/protocol/quic"
)

// TestNonPoolStageCounters measures packet loss at EACH STAGE of the response path:
//   1. Google sends (googleSent)
//   2. VPS outbound socket readLoop reads (readLoopRead)
//   3. VPS outbox receives (outboxRecv)
//   4. VPS writes to Chrome socket (chromeWrite)
//   5. Chrome receives (chromeReceived)
//
// This tells us EXACTLY where packets are lost.
func TestNonPoolStageCounters(t *testing.T) {
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

        // Multiple Chrome readers to keep up with the receive buffer
        for i := 0; i < 4; i++ {
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
        }

        type entry struct {
                outboundConn net.Conn
                dcid         []byte
                outbox       chan []byte
        }

        var workerMu sync.RWMutex
        conns := make(map[string]*entry)

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
                        // Send directly to Google
                        entry.outboundConn.Write(pkt)
                }
        }()

        numConns := 3
        readLoopRead := uint64(0)
        outboxRecv := uint64(0)
        chromeWrite := uint64(0)

        for i := 0; i < numConns; i++ {
                dcid := make([]byte, 8)
                rand.Read(dcid)
                dcidHex := fmt.Sprintf("%x", dcid)

                ob, err := net.Dial("udp", googleConn.LocalAddr().String())
                if err != nil {
                        t.Fatal(err)
                }

                // Increase outbound socket buffer
                ob.(interface{ SetReadBuffer(int) error }).SetReadBuffer(4 * 1024 * 1024)

                e := &entry{
                        outboundConn: ob,
                        dcid:         dcid,
                        outbox:       make(chan []byte, 512),
                }

                workerMu.Lock()
                conns[dcidHex] = e
                workerMu.Unlock()

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
                                atomic.AddUint64(&readLoopRead, 1)
                                pkt := make([]byte, n)
                                copy(pkt, recvBuf[:n])
                                select {
                                case ob <- pkt:
                                        atomic.AddUint64(&outboxRecv, 1)
                                default:
                                        // DROP
                                }
                        }
                }(ob, e.outbox)

                // downlink writer: outbox → Chrome (with rate limiting)
                go func(ob chan []byte) {
                        chromeAddr := chromeConn.LocalAddr().(*net.UDPAddr)
                        for pkt := range ob {
                                chromeConn.WriteTo(pkt, chromeAddr)
                                atomic.AddUint64(&chromeWrite, 1)
                                // Small delay to avoid overwhelming Chrome's receive buffer
                                time.Sleep(50 * time.Microsecond)
                        }
                }(e.outbox)

                t.Logf("Created connection %d with DCID %s", i, dcidHex)
        }

        // Chrome sends packets
        stop := make(chan struct{})
        go func() {
                ticker := time.NewTicker(100 * time.Millisecond)
                defer ticker.Stop()
                connIdx := 0
                for {
                        select {
                        case <-ticker.C:
                                workerMu.RLock()
                                var e *entry
                                idx := 0
                                for _, ent := range conns {
                                        if idx == connIdx%len(conns) {
                                                e = ent
                                                break
                                        }
                                        idx++
                                }
                                workerMu.RUnlock()
                                connIdx++
                                if e == nil {
                                        continue
                                }
                                pkt := make([]byte, 100)
                                pkt[0] = 0x40
                                copy(pkt[1:9], e.dcid)
                                e.outboundConn.Write(pkt)
                        case <-stop:
                                return
                        }
                }
        }()

        time.Sleep(5 * time.Second)
        close(stop)

        gRecv := atomic.LoadUint64(&googleReceived)
        gSent := atomic.LoadUint64(&googleSent)
        _ = gRecv
        rRead := atomic.LoadUint64(&readLoopRead)
        oRecv := atomic.LoadUint64(&outboxRecv)
        cWrite := atomic.LoadUint64(&chromeWrite)
        cRecv := atomic.LoadUint64(&chromeReceived)

        t.Logf("=== Stage-by-stage results (5s, %d conns) ===", numConns)
        t.Logf("1. Google sent replies:       %d", gSent)
        t.Logf("2. VPS readLoop read:         %d  (loss: %d)", rRead, gSent-rRead)
        t.Logf("3. VPS outbox received:       %d  (loss: %d)", oRecv, rRead-oRecv)
        t.Logf("4. VPS wrote to Chrome:       %d  (loss: %d)", cWrite, oRecv-cWrite)
        t.Logf("5. Chrome received:           %d  (loss: %d)", cRecv, cWrite-cRecv)
        t.Logf("Total loss: %d (%.1f%%)", gSent-cRecv, float64(gSent-cRecv)/float64(gSent)*100)

        if gSent > 0 && cRecv < gSent*9/10 {
                t.Errorf("PACKET LOSS: %d of %d packets lost (%.1f%%)",
                        gSent-cRecv, gSent, float64(gSent-cRecv)/float64(gSent)*100)
        }
}
