package freedom

import (
        "context"
        "fmt"
        "net"
        "sync"
        "sync/atomic"
        "testing"
        "time"

        "github.com/xtls/xray-core/common/buf"
        "github.com/xtls/xray-core/transport/pipe"
)

// TestNonPoolDataFlow simulates the exact non-pool UDP data path:
//
// Chrome → hub → callback → uplink pipe → freedom.Process → outbound socket → Google
// Google → outbound socket → PacketReader → buf.Copy → downlink pipe → udpConn.Write → hub.WriteTo → Chrome
//
// It sends a burst of packets from Google and measures how many arrive at Chrome.
func TestNonPoolDataFlow(t *testing.T) {
        // Create the "Google" UDP server (outbound destination)
        googleAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
        if err != nil {
                t.Fatal(err)
        }
        googleConn, err := net.ListenUDP("udp", googleAddr)
        if err != nil {
                t.Fatal(err)
        }
        defer googleConn.Close()
        googlePort := googleConn.LocalAddr().(*net.UDPAddr).Port

        // Google will reply to packets by echoing them back
        googleReplies := uint64(0)
        googleReceived := uint64(0)
        go func() {
                buf := make([]byte, 2048)
                for {
                        n, addr, err := googleConn.ReadFrom(buf)
                        if err != nil {
                                return
                        }
                        atomic.AddUint64(&googleReceived, 1)
                        // Reply with a burst of 10 packets (simulating video data)
                        for i := 0; i < 10; i++ {
                                reply := make([]byte, 1250)
                                reply[0] = 0x40 // short header (simulated)
                                copy(reply[1:], fmt.Appendf(nil, "reply-%d-%d", n, i))
                                googleConn.WriteTo(reply, addr)
                                atomic.AddUint64(&googleReplies, 1)
                        }
                }
        }()

        // Create the "Chrome" UDP client
        chromeAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
        if err != nil {
                t.Fatal(err)
        }
        chromeConn, err := net.ListenUDP("udp", chromeAddr)
        if err != nil {
                t.Fatal(err)
        }
        defer chromeConn.Close()
        chromePort := chromeConn.LocalAddr().(*net.UDPAddr).Port

        // Chrome receives packets
        chromeReceived := uint64(0)
        go func() {
                buf := make([]byte, 2048)
                for {
                        n, _, err := chromeConn.ReadFrom(buf)
                        if err != nil {
                                return
                        }
                        if n > 0 {
                                atomic.AddUint64(&chromeReceived, 1)
                        }
                }
        }()

        // Create the outbound socket (freedom dials to Google)
        outboundConn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", googlePort))
        if err != nil {
                t.Fatal(err)
        }
        defer outboundConn.Close()

        // Create the uplink pipe (Chrome → Google)
        // 256KB with DiscardOverflow — matches worker.go
        uplinkReader, uplinkWriter := pipe.New(pipe.DiscardOverflow(), pipe.WithSizeLimit(256*1024))

        // Create the downlink pipe (Google → Chrome)
        // Default 512KB, NO DiscardOverflow — matches dispatcher
        downlinkReader, downlinkWriter := pipe.New(pipe.WithSizeLimit(512 * 1024))

        // The "udpConn" — simulates what worker.go creates
        // Chrome sends to uplinkWriter, reads from downlinkReader
        // freedom reads from uplinkReader, writes to downlinkWriter
        type simConn struct {
                reader *pipe.Reader // uplinkReader — Chrome's data
                writer *pipe.Writer // downlinkWriter — Google's replies to Chrome
        }
        _ = simConn{}

        // output writer: writes Google's replies to Chrome via downlinkWriter
        // This is what freedom's responseDone writes to
        output := &pipeWriterAdapter{writer: downlinkWriter}

        // input reader: reads Chrome's data from uplinkReader
        // This is what freedom's requestDone reads from
        input := &pipeReaderAdapter{reader: uplinkReader}

        // The PacketWriter for the request path (Chrome → Google)
        // Uses the outbound conn (finalmask.PacketConnWrapper equivalent)
        packetWriter := &simplePacketWriter{
                conn: outboundConn,
        }

        // The PacketReader for the response path (Google → VPS)
        // Uses the outbound conn to read Google's replies
        packetReader := &simplePacketReader{
                conn: outboundConn,
        }

        ctx, cancel := context.WithCancel(context.Background())
        defer cancel()
        _ = ctx

        // requestDone: reads Chrome's data from input, writes to Google via packetWriter
        requestDone := func() error {
                return buf.Copy(input, packetWriter)
        }

        // responseDone: reads Google's replies from packetReader, writes to output pipe
        responseDone := func() error {
                return buf.Copy(packetReader, output)
        }

        // Start the goroutines (like task.Run)
        go func() {
                _ = requestDone()
        }()
        go func() {
                _ = responseDone()
        }()

        // Also start a goroutine to read from downlinkReader and send to Chrome
        // (this is what dokodemo's SequentialWriter/udpConn.Write does)
        go func() {
                for {
                        mb, err := downlinkReader.ReadMultiBuffer()
                        if err != nil {
                                return
                        }
                        for _, b := range mb {
                                chromeConn.WriteTo(b.Bytes(), &net.UDPAddr{
                                        IP:   chromeAddr.IP,
                                        Port: chromePort,
                                })
                                b.Release()
                        }
                }
        }()

        // Now simulate Chrome sending a QUIC Initial
        initialPacket := make([]byte, 1200)
        initialPacket[0] = 0xC0 // long header
        copy(initialPacket[1:], "CHROME-INITIAL-PACKET")

        // Write to uplink pipe (Chrome → Google)
        chromeBuf := buf.New()
        chromeBuf.Write(initialPacket)
        uplinkWriter.WriteMultiBuffer(buf.MultiBuffer{chromeBuf})

        // Wait for data to flow
        time.Sleep(2 * time.Second)

        // Check results
        gRecv := atomic.LoadUint64(&googleReceived)
        gReply := atomic.LoadUint64(&googleReplies)
        cRecv := atomic.LoadUint64(&chromeReceived)

        t.Logf("Google received: %d packets from Chrome", gRecv)
        t.Logf("Google sent: %d reply packets", gReply)
        t.Logf("Chrome received: %d packets from VPS", cRecv)

        if gRecv == 0 {
                t.Error("Google never received any packets from Chrome — request path is broken")
        }
        if gReply == 0 {
                t.Error("Google never sent any replies — server not working")
        }
        if cRecv == 0 {
                t.Error("Chrome never received any packets from VPS — response path is broken")
        }

        if gReply > 0 && cRecv == 0 {
                t.Errorf("RESPONSE PATH BROKEN: Google sent %d packets but Chrome received 0", gReply)
        }
        if gReply > 0 && cRecv < gReply/2 {
                t.Errorf("PACKET LOSS: Google sent %d, Chrome only received %d (%.1f%% loss)",
                        gReply, cRecv, float64(gReply-cRecv)/float64(gReply)*100)
        }
}

// simplePacketWriter writes buffers to a fixed UDP destination (Google)
type simplePacketWriter struct {
        conn net.Conn
}

func (w *simplePacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
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

// simplePacketReader reads UDP packets from the outbound socket (Google's replies)
type simplePacketReader struct {
        conn net.Conn
}

func (r *simplePacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
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

// pipeWriterAdapter wraps a pipe.Writer as a buf.Writer
type pipeWriterAdapter struct {
        writer *pipe.Writer
}

func (w *pipeWriterAdapter) WriteMultiBuffer(mb buf.MultiBuffer) error {
        return w.writer.WriteMultiBuffer(mb)
}

// pipeReaderAdapter wraps a pipe.Reader as a buf.Reader
type pipeReaderAdapter struct {
        reader *pipe.Reader
}

func (r *pipeReaderAdapter) ReadMultiBuffer() (buf.MultiBuffer, error) {
        return r.reader.ReadMultiBuffer()
}

var _ = sync.Mutex{}
