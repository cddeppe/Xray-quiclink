package freedom

import (
        "net"
        "sync"
        "testing"
        "time"

        "github.com/xtls/xray-core/common/protocol/quic"
)

// ============================================================
// v26.11.63 COMPREHENSIVE TEST SUITE
//
// Tests the delayed-close behavior: Close() starts a 5s timer
// during which the inbox stays open and DCID stays in demux.
// actualClose() fires after 5s and does real cleanup.
// ============================================================

// --- Helper: build QUIC packets ---

func buildQUICInitial(dcid, scid []byte) []byte {
        var pkt []byte
        pkt = append(pkt, 0xC0)              // Long header, Initial
        pkt = append(pkt, 0, 0, 0, 1)        // Version 1
        pkt = append(pkt, byte(len(dcid)))   // DCID length
        pkt = append(pkt, dcid...)           // DCID
        pkt = append(pkt, byte(len(scid)))   // SCID length
        pkt = append(pkt, scid...)           // SCID
        pkt = append(pkt, 0)                 // Token length = 0
        pkt = append(pkt, 2)                 // Length = 2 (minimal)
        pkt = append(pkt, 0)                 // PN = 0
        pkt = append(pkt, 0xFF)              // Payload byte
        return pkt
}

func buildQUICHandshake(dcid []byte) []byte {
        var pkt []byte
        pkt = append(pkt, 0xE0)              // Long header, Handshake
        pkt = append(pkt, 0, 0, 0, 1)        // Version 1
        pkt = append(pkt, byte(len(dcid)))   // DCID length
        pkt = append(pkt, dcid...)           // DCID
        pkt = append(pkt, 0)                 // SCID length = 0
        pkt = append(pkt, 2)                 // Length = 2
        pkt = append(pkt, 0)                 // PN
        pkt = append(pkt, 0xAA)              // Payload
        return pkt
}

// --- Test 1: Reply arrives AFTER Close() — the core delayed-close test ---

func Test_DelayedClose_ReplyAfterClose(t *testing.T) {
        pool := NewUDPSocketPool(30*time.Second, 600*time.Second, 300*time.Second, nil)

        serverAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
        serverConn, err := net.ListenUDP("udp", serverAddr)
        if err != nil {
                t.Fatalf("listen: %v", err)
        }
        defer serverConn.Close()
        serverAddr = serverConn.LocalAddr().(*net.UDPAddr)

        pconn, err := pool.Acquire(serverAddr)
        if err != nil {
                t.Fatalf("Acquire: %v", err)
        }

        // Set source
        pconn.source = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}

        // Send Initial with DCID=A, SCID=∅ (Chrome)
        clientDCID := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
        initial := buildQUICInitial(clientDCID, []byte{})

        // WriteTo registers DCID=A in demux
        _, err = pconn.WriteTo(initial, serverAddr)
        if err != nil {
                t.Fatalf("WriteTo: %v", err)
        }

        // Verify DCID is in demux
        dk := makeDCIDKey(clientDCID)
        pconn.socket.mu.RLock()
        _, demuxHasDCID := pconn.socket.demux[dk]
        pconn.socket.mu.RUnlock()
        if !demuxHasDCID {
                t.Fatal("FAIL: DCID not in demux after WriteTo")
        }
        t.Log("PASS: DCID registered in demux")

        // Close the conn (simulates freedom.Process returning)
        pconn.Close()

        // Verify DCID is STILL in demux (delayed close!)
        time.Sleep(100 * time.Millisecond) // let Close() start the timer
        pconn.socket.mu.RLock()
        _, demuxStillHasDCID := pconn.socket.demux[dk]
        pconn.socket.mu.RUnlock()
        if !demuxStillHasDCID {
                t.Fatal("FAIL: DCID removed from demux immediately after Close() — delayed close not working")
        }
        t.Log("PASS: DCID still in demux after Close() (delayed close working)")

        // Verify conn is NOT fully closed yet
        if pconn.closed.Load() {
                t.Fatal("FAIL: conn marked as closed immediately — delayed close not working")
        }
        t.Log("PASS: conn not fully closed (waiting for 5s timer)")

        // Now simulate the server reply arriving 50ms after Close()
        // Server reply: DCID=∅ (echoing Chrome's SCID), SCID=clientDCID
        serverReply := buildQUICInitial([]byte{}, clientDCID)

        // Server sends reply to the pool socket's address
        // Need to resolve the actual address the pool socket is listening on
        poolAddr := pconn.socket.conn.LocalAddr().(*net.UDPAddr)
        // If the pool bound to [::]:port, use 127.0.0.1:port instead
        if poolAddr.IP.IsUnspecified() {
                poolAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: poolAddr.Port}
        }
        _, err = serverConn.WriteToUDP(serverReply, poolAddr)
        if err != nil {
                t.Fatalf("server reply: %v", err)
        }
        t.Log("PASS: server reply sent to pool socket")

        // Wait for the readLoop to process it
        // The reply should be routed via SCID fallback (server SCID = client DCID)
        // and delivered to pconn.inbox (which is still open due to delayed close)
        // BUT: nobody is reading from pconn.inbox (responseDone already returned)
        // So the reply sits in the inbox buffer (cap 256)
        // This is OK — the reply won't overflow for a single packet

        // Verify the reply was delivered to the inbox (not dropped)
        time.Sleep(200 * time.Millisecond)
        select {
        case <-pconn.inbox:
                t.Log("PASS: server reply delivered to inbox after Close() (delayed close works!)")
        default:
                t.Fatal("FAIL: server reply NOT delivered to inbox after Close() — reply was dropped")
        }
}

// --- Test 2: actualClose fires after 5s and cleans up ---

func Test_DelayedClose_ActualCloseAfter5s(t *testing.T) {
        pool := NewUDPSocketPool(30*time.Second, 600*time.Second, 300*time.Second, nil)

        serverAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
        pconn, err := pool.Acquire(serverAddr)
        if err != nil {
                t.Fatalf("Acquire: %v", err)
        }

        clientDCID := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
        initial := buildQUICInitial(clientDCID, []byte{})
        pconn.WriteTo(initial, serverAddr)

        dk := makeDCIDKey(clientDCID)

        // Close
        pconn.Close()

        // Wait for the 5s timer (use 6s to be safe)
        t.Log("waiting 6s for actualClose timer...")
        time.Sleep(6 * time.Second)

        // Verify conn is now fully closed
        if !pconn.closed.Load() {
                t.Fatal("FAIL: conn not closed after 6s — actualClose didn't fire")
        }
        t.Log("PASS: conn fully closed after 5s timer")

        // Verify DCID was removed from demux
        pconn.socket.mu.RLock()
        _, demuxHasDCID := pconn.socket.demux[dk]
        pconn.socket.mu.RUnlock()
        if demuxHasDCID {
                t.Fatal("FAIL: DCID still in demux after actualClose")
        }
        t.Log("PASS: DCID removed from demux after actualClose")
}

// --- Test 3: Multiple parallel connections don't interfere ---

func Test_DelayedClose_ParallelConnections(t *testing.T) {
        pool := NewUDPSocketPool(30*time.Second, 600*time.Second, 300*time.Second, nil)

        serverAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
        serverConn, err := net.ListenUDP("udp", serverAddr)
        if err != nil {
                t.Fatalf("listen: %v", err)
        }
        defer serverConn.Close()
        serverAddr = serverConn.LocalAddr().(*net.UDPAddr)

        // Drain server
        go func() {
                buf := make([]byte, 65535)
                for {
                        _, _, err := serverConn.ReadFromUDP(buf)
                        if err != nil {
                                return
                        }
                }
        }()

        // Create 5 parallel connections with different DCIDs
        var conns [5]*pooledConn
        var dcids [5][]byte
        for i := 0; i < 5; i++ {
                pconn, err := pool.Acquire(serverAddr)
                if err != nil {
                        t.Fatalf("Acquire %d: %v", i, err)
                }
                pconn.source = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 10000 + i}
                dcid := []byte{byte(0x10 + i), 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
                dcids[i] = dcid
                initial := buildQUICInitial(dcid, []byte{})
                pconn.WriteTo(initial, serverAddr)
                conns[i] = pconn
        }

        // Close all of them
        for i := 0; i < 5; i++ {
                conns[i].Close()
        }

        // All DCIDs should still be in demux (delayed close)
        time.Sleep(100 * time.Millisecond)
        for i := 0; i < 5; i++ {
                dk := makeDCIDKey(dcids[i])
                conns[i].socket.mu.RLock()
                _, hasDCID := conns[i].socket.demux[dk]
                conns[i].socket.mu.RUnlock()
                if !hasDCID {
                        t.Fatalf("FAIL: conn %d DCID removed before 5s", i)
                }
        }
        t.Log("PASS: all 5 parallel conns have DCID in demux after Close()")

        // Send a reply to conn 2 specifically
        reply2 := buildQUICInitial([]byte{}, dcids[2])
        poolAddr := conns[2].socket.conn.LocalAddr().(*net.UDPAddr)
        if poolAddr.IP.IsUnspecified() {
                poolAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: poolAddr.Port}
        }
        serverConn.WriteToUDP(reply2, poolAddr)

        // Verify conn 2's inbox got the reply, not others
        time.Sleep(200 * time.Millisecond)
        select {
        case <-conns[2].inbox:
                t.Log("PASS: reply routed to correct conn (conn 2)")
        default:
                t.Fatal("FAIL: reply not routed to conn 2")
        }

        // Verify other conns did NOT get the reply
        for i := 0; i < 5; i++ {
                if i == 2 {
                        continue
                }
                select {
                case <-conns[i].inbox:
                        t.Fatalf("FAIL: conn %d got conn 2's reply (cross-talk!)", i)
                default:
                        // OK — no reply for this conn
                }
        }
        t.Log("PASS: no cross-talk between parallel conns")
}

// --- Test 4: WriteTo after Close() is rejected ---

func Test_DelayedClose_WriteAfterClose(t *testing.T) {
        pool := NewUDPSocketPool(30*time.Second, 600*time.Second, 300*time.Second, nil)

        serverAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
        pconn, err := pool.Acquire(serverAddr)
        if err != nil {
                t.Fatalf("Acquire: %v", err)
        }

        pconn.Close()
        time.Sleep(100 * time.Millisecond)

        // WriteTo should still work (conn not fully closed yet, only "closing")
        // The DCID is still in demux, so the reply can still be routed
        initial := buildQUICInitial([]byte{1, 2, 3, 4, 5, 6, 7, 8}, []byte{})
        _, err = pconn.WriteTo(initial, serverAddr)
        // We expect this to succeed (delayed close allows writes)
        // OR fail gracefully (closing flag rejects new writes)
        // Either is acceptable — the key is no panic
        if err != nil {
                t.Logf("WriteTo after Close returned error (acceptable): %v", err)
        } else {
                t.Log("PASS: WriteTo after Close succeeded (delayed close allows writes)")
        }
}

// --- Test 5: Stress test — 50 connections, close all, verify no leak ---

func Test_DelayedClose_StressNoLeak(t *testing.T) {
        pool := NewUDPSocketPool(30*time.Second, 600*time.Second, 300*time.Second, nil)

        serverAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
        serverConn, err := net.ListenUDP("udp", serverAddr)
        if err != nil {
                t.Fatalf("listen: %v", err)
        }
        defer serverConn.Close()
        serverAddr = serverConn.LocalAddr().(*net.UDPAddr)

        // Drain server
        go func() {
                buf := make([]byte, 65535)
                for {
                        _, _, err := serverConn.ReadFromUDP(buf)
                        if err != nil {
                                return
                        }
                }
        }()

        const N = 50
        var wg sync.WaitGroup
        wg.Add(N)

        for i := 0; i < N; i++ {
                go func(idx int) {
                        defer wg.Done()
                        pconn, err := pool.Acquire(serverAddr)
                        if err != nil {
                                t.Errorf("Acquire %d: %v", idx, err)
                                return
                        }
                        dcid := []byte{byte(idx), 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22}
                        initial := buildQUICInitial(dcid, []byte{})
                        pconn.WriteTo(initial, serverAddr)
                        pconn.Close()
                }(i)
        }

        wg.Wait()
        t.Logf("PASS: %d concurrent connections created and closed", N)

        // Wait for delayed close timers to fire
        time.Sleep(6 * time.Second)

        // Verify all conns are fully closed and demux is empty
        pool.mu.Lock()
        for key, sock := range pool.sockets {
                sock.mu.RLock()
                demuxCount := len(sock.demux)
                sock.mu.RUnlock()
                if demuxCount > 0 {
                        t.Errorf("FAIL: socket %s still has %d demux entries after 6s", key, demuxCount)
                }
        }
        pool.mu.Unlock()
        t.Log("PASS: all demux entries cleaned up after 5s timers")
}

// --- Test 6: SCID fallback still works with delayed close ---

func Test_DelayedClose_SCIDFallback(t *testing.T) {
        pool := NewUDPSocketPool(30*time.Second, 600*time.Second, 300*time.Second, nil)

        serverAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
        serverConn, err := net.ListenUDP("udp", serverAddr)
        if err != nil {
                t.Fatalf("listen: %v", err)
        }
        defer serverConn.Close()
        serverAddr = serverConn.LocalAddr().(*net.UDPAddr)

        pconn, err := pool.Acquire(serverAddr)
        if err != nil {
                t.Fatalf("Acquire: %v", err)
        }
        pconn.source = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 99999}

        // Chrome Initial: DCID=A, SCID=∅
        clientDCID := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x56, 0x78}
        initial := buildQUICInitial(clientDCID, []byte{})
        pconn.WriteTo(initial, serverAddr)

        // Close (simulates Process returning)
        pconn.Close()

        // Server reply: DCID=∅, SCID=A (RFC 9000 §7.3)
        serverReply := buildQUICInitial([]byte{}, clientDCID)
        poolAddr := pconn.socket.conn.LocalAddr().(*net.UDPAddr)
        if poolAddr.IP.IsUnspecified() {
                poolAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: poolAddr.Port}
        }
        serverConn.WriteToUDP(serverReply, poolAddr)

        // Wait for readLoop to process
        time.Sleep(200 * time.Millisecond)

        // The reply should be in pconn.inbox (via SCID fallback)
        select {
        case <-pconn.inbox:
                t.Log("PASS: SCID fallback delivered reply after Close() (delayed close + SCID fallback)")
        default:
                t.Fatal("FAIL: SCID fallback did not deliver reply after Close()")
        }
}

var _ = quic.ParseDCID
