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

// TestNonPoolMultiBuffered tests multiple concurrent connections WITH
// the BufferedPacketReader fix (dedicated readLoop with non-blocking drop).
func TestNonPoolMultiBuffered(t *testing.T) {
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

        // Increase socket buffers
        chromeConn.SetReadBuffer(4 * 1024 * 1024)  // 4MB
        chromeConn.SetWriteBuffer(4 * 1024 * 1024) // 4MB

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

        type bufferedEntry struct {
                uplinkWriter *pipe.Writer
                downReader   *pipe.Reader
                downWriter   *pipe.Writer
                outboundConn net.Conn
                dcid         []byte
        }

        var workerMu sync.RWMutex
        conns := make(map[string]*bufferedEntry)

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

                upReader, upWriter := pipe.New(pipe.DiscardOverflow(), pipe.WithSizeLimit(256*1024))
                downReader, downWriter := pipe.New(pipe.WithSizeLimit(512 * 1024))

                entry := &bufferedEntry{
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
                go func(rd *pipe.Reader, conn net.Conn) {
                        for {
                                mb, err := rd.ReadMultiBuffer()
                                if err != nil {
                                        return
                                }
                                for _, b := range mb {
                                        conn.Write(b.Bytes())
                                        b.Release()
                                }
                        }
                }(upReader, ob)

                // responseDone WITH BufferedPacketReader:
                // readLoop: reads from Google's socket → inbox (NON-BLOCKING, drops on full)
                // consumer: reads from inbox → writes to downlink pipe
                inbox := make(chan buf.MultiBuffer, 256)
                var readLoopDone atomic.Bool

                go func(conn net.Conn) {
                        for {
                                b := buf.New()
                                b.Resize(0, buf.Size)
                                n, err := conn.Read(b.Bytes())
                                if err != nil {
                                        b.Release()
                                        readLoopDone.Store(true)
                                        // Signal EOF
                                        select {
                                        case inbox <- nil:
                                        default:
                                        }
                                        return
                                }
                                b.Resize(0, int32(n))
                                // NON-BLOCKING send — drop if inbox full
                                select {
                                case inbox <- buf.MultiBuffer{b}:
                                default:
                                        b.Release() // DROP
                                }
                        }
                }(ob)

                // Consumer: inbox → downlink pipe
                go func(dw *pipe.Writer) {
                        for {
                                select {
                                case mb, ok := <-inbox:
                                        if !ok || mb == nil {
                                                return
                                        }
                                        if mb.IsEmpty() {
                                                continue
                                        }
                                        err := dw.WriteMultiBuffer(mb)
                                        if err != nil {
                                                return
                                        }
                                default:
                                        if readLoopDone.Load() {
                                                return
                                        }
                                        // Small sleep to avoid busy-wait
                                        time.Sleep(100 * time.Microsecond)
                                }
                        }
                }(downWriter)

                // downlink reader → Chrome
                go func(rd *pipe.Reader) {
                        chromeAddr := chromeConn.LocalAddr().(*net.UDPAddr)
                        for {
                                mb, err := rd.ReadMultiBuffer()
                                if err != nil {
                                        return
                                }
                                for _, b := range mb {
                                        chromeConn.WriteTo(b.Bytes(), chromeAddr)
                                        b.Release()
                                }
                        }
                }(downReader)

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
                                workerMu.RLock()
                                var entry *bufferedEntry
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

        t.Logf("=== Results after 5 seconds (%d conns, BufferedPacketReader) ===", numConns)
        t.Logf("Chrome sent ACKs:     %d", gRecv)
        t.Logf("Google sent replies:   %d", gSent)
        t.Logf("Chrome received:       %d", cRecv)
        t.Logf("Packet loss:           %d (%.1f%%)", gSent-cRecv, float64(gSent-cRecv)/float64(gSent)*100)

        if gSent > 0 && cRecv < gSent*9/10 {
                t.Errorf("PACKET LOSS: %d of %d packets lost (%.1f%%)",
                        gSent-cRecv, gSent, float64(gSent-cRecv)/float64(gSent)*100)
        }
}
