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

// TestNonPoolVideoStream simulates REAL YouTube video streaming:
// - Google sends bursts of 100+ packets (1250 bytes each)
// - Bursts every 20ms (not 100ms — real video segment rate)
// - Multiple concurrent connections
// - Measures loss with and without rate limiting
func TestNonPoolVideoStream(t *testing.T) {
        // Test with different burst sizes and rates
        scenarios := []struct {
                name      string
                burstSize int
                burstEvery time.Duration
                packetSize int
                numConns   int
        }{
                {"50pkt/100ms/1250B/3conn", 50, 100 * time.Millisecond, 1250, 3},
                {"100pkt/20ms/1250B/3conn", 100, 20 * time.Millisecond, 1250, 3},
                {"100pkt/20ms/1250B/5conn", 100, 20 * time.Millisecond, 1250, 5},
                {"200pkt/10ms/1250B/3conn", 200, 10 * time.Millisecond, 1250, 3},
        }

        for _, sc := range scenarios {
                t.Run(sc.name, func(t *testing.T) {
                        runVideoStreamTest(t, sc.burstSize, sc.burstEvery, sc.packetSize, sc.numConns, 0)
                })
        }
}

// TestNonPoolVideoStreamRateLimited tests the same scenarios WITH rate limiting
func TestNonPoolVideoStreamRateLimited(t *testing.T) {
        scenarios := []struct {
                name      string
                burstSize int
                burstEvery time.Duration
                packetSize int
                numConns   int
        }{
                {"50pkt/100ms/1250B/3conn", 50, 100 * time.Millisecond, 1250, 3},
                {"100pkt/20ms/1250B/3conn", 100, 20 * time.Millisecond, 1250, 3},
                {"100pkt/20ms/1250B/5conn", 100, 20 * time.Millisecond, 1250, 5},
                {"200pkt/10ms/1250B/3conn", 200, 10 * time.Millisecond, 1250, 3},
        }

        for _, sc := range scenarios {
                t.Run(sc.name, func(t *testing.T) {
                        runVideoStreamTest(t, sc.burstSize, sc.burstEvery, sc.packetSize, sc.numConns, 3*time.Microsecond)
                })
        }
}

func runVideoStreamTest(t *testing.T, burstSize int, burstEvery time.Duration, packetSize, numConns int, writeDelay time.Duration) {
        googleConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
        if err != nil {
                t.Fatal(err)
        }
        defer googleConn.Close()

        googleSent := uint64(0)
        googleReceived := uint64(0)

        // Google: receive packets, reply with LARGE bursts
        go func() {
                recvBuf := make([]byte, 2048)
                for {
                        n, addr, err := googleConn.ReadFrom(recvBuf)
                        if err != nil {
                                return
                        }
                        _ = n
                        atomic.AddUint64(&googleReceived, 1)
                        // Reply with a burst of video data
                        for i := 0; i < burstSize; i++ {
                                reply := make([]byte, packetSize)
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

        // Increase Chrome's socket receive buffer to 4MB (like a real OS would have)
        chromeConn.SetReadBuffer(4 * 1024 * 1024)
        chromeConn.SetWriteBuffer(4 * 1024 * 1024)

        chromeReceived := uint64(0)

        // Multiple Chrome readers
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
                readLoopRead uint64
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
                        entry.outboundConn.Write(pkt)
                }
        }()

        totalReadLoop := uint64(0)
        _ = totalReadLoop
        totalChromeWrite := uint64(0)

        for i := 0; i < numConns; i++ {
                dcid := make([]byte, 8)
                rand.Read(dcid)
                dcidHex := fmt.Sprintf("%x", dcid)

                ob, err := net.Dial("udp", googleConn.LocalAddr().String())
                if err != nil {
                        t.Fatal(err)
                }

                e := &entry{
                        outboundConn: ob,
                        dcid:         dcid,
                        outbox:       make(chan []byte, 512),
                }

                workerMu.Lock()
                conns[dcidHex] = e
                workerMu.Unlock()

                // readLoop: Google socket → outbox (NON-BLOCKING)
                go func(conn net.Conn, ob chan []byte, counter *uint64) {
                        recvBuf := make([]byte, 2048)
                        for {
                                n, err := conn.Read(recvBuf)
                                if err != nil {
                                        return
                                }
                                if n == 0 {
                                        continue
                                }
                                atomic.AddUint64(counter, 1)
                                pkt := make([]byte, n)
                                copy(pkt, recvBuf[:n])
                                select {
                                case ob <- pkt:
                                default:
                                        // DROP
                                }
                        }
                }(ob, e.outbox, &e.readLoopRead)

                // downlink writer: outbox → Chrome (with optional rate limiting)
                go func(ob chan []byte) {
                        chromeAddr := chromeConn.LocalAddr().(*net.UDPAddr)
                        for pkt := range ob {
                                chromeConn.WriteTo(pkt, chromeAddr)
                                atomic.AddUint64(&totalChromeWrite, 1)
                                if writeDelay > 0 {
                                        time.Sleep(writeDelay)
                                }
                        }
                }(e.outbox)
        }

        // Chrome sends ACKs
        stop := make(chan struct{})
        go func() {
                ticker := time.NewTicker(burstEvery)
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

        gSent := atomic.LoadUint64(&googleSent)
        cRecv := atomic.LoadUint64(&chromeReceived)
        cWrite := atomic.LoadUint64(&totalChromeWrite)

        delayStr := "no delay"
        if writeDelay > 0 {
                delayStr = writeDelay.String()
        }

        t.Logf("[%s, %s] Google sent: %d, VPS wrote: %d, Chrome received: %d, loss: %d (%.1f%%)",
                t.Name(), delayStr, gSent, cWrite, cRecv, gSent-cRecv,
                func() float64 {
                        if gSent == 0 {
                                return 0
                        }
                        return float64(gSent-cRecv) / float64(gSent) * 100
                }())
}
