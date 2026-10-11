package freedom

import (
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol/quic"
)

// Test_SCIDFallback_Chrome0LengthSCID proves the v26.11.55 fix:
// when Chrome sends an Initial with 0-length SCID, the server's reply
// (DCID=∅, SCID=clientDCID) is routed via the SCID-based fallback
// in readLoop, not silently dropped.
//
// Before the fix:
//   - WriteTo only registered the SCID (∅) → skipped → demux empty
//   - readLoop parsed DCID=∅ → demux miss → DROPPED
//   - Hook never fired (sentOk=false)
//   - Handshake failed → TCP fallback
//
// After the fix:
//   - WriteTo also registers the DCID (A) → demux[A] = inbox
//   - readLoop: demux[∅] miss → SCID fallback → demux[A] HIT → routed
//   - Hook fires → dcidIndex populated for 1-RTT routing
func Test_SCIDFallback_Chrome0LengthSCID(t *testing.T) {
	pool := NewUDPSocketPool(
		30*time.Second,
		600*time.Second,
		300*time.Second,
		nil,
	)

	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:19997")
	if err != nil {
		t.Fatal(err)
	}
	serverConn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		t.Fatalf("failed to listen on server addr: %v", err)
	}
	defer serverConn.Close()

	pconn, err := pool.Acquire(serverAddr)
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}
	defer pconn.Close()

	browserSrc := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 54321}
	pconn.source = browserSrc

	// Step 1: Chrome sends Initial with DCID=A (8 bytes), SCID=∅ (0 bytes)
	clientDCID := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	initial := buildTestQUICInitial(t, clientDCID, []byte{})

	n, err := pconn.WriteTo(initial, serverAddr)
	if err != nil || n != len(initial) {
		t.Fatalf("WriteTo failed: n=%d err=%v", n, err)
	}

	// Server reads the Initial, captures the pool's source addr
	poolSrcCh := make(chan *net.UDPAddr, 1)
	go func() {
		buf := make([]byte, 65535)
		_, src, err := serverConn.ReadFromUDP(buf)
		if err != nil {
			poolSrcCh <- nil
			return
		}
		poolSrcCh <- src
	}()

	select {
	case poolSrc := <-poolSrcCh:
		if poolSrc == nil {
			t.Fatal("FAIL: server did not receive the Initial from the pool")
		}
		go func() {
			buf := make([]byte, 65535)
			for {
				_, _, err := serverConn.ReadFromUDP(buf)
				if err != nil {
					return
				}
			}
		}()

		dk := makeDCIDKey(clientDCID)
		pconn.socket.mu.RLock()
		inbox, demuxHasDCID := pconn.socket.demux[dk]
		pconn.socket.mu.RUnlock()
		if !demuxHasDCID {
			t.Fatal("FAIL: WriteTo did not register the DCID in demux — the WriteTo fix is missing")
		}
		if inbox != pconn.inbox {
			t.Fatal("FAIL: demux entry points to wrong inbox")
		}
		t.Log("PASS: WriteTo registered client DCID in demux (the WriteTo fix)")

		serverReply := buildTestQUICInitial(t, []byte{}, clientDCID)

		resultCh := make(chan []byte, 1)
		go func() {
			buf := make([]byte, 65535)
			n, _, err := pconn.ReadFrom(buf)
			if err != nil {
				resultCh <- nil
				return
			}
			resultCh <- buf[:n]
		}()

		_, err = serverConn.WriteToUDP(serverReply, poolSrc)
		if err != nil {
			t.Fatalf("server WriteToUDP failed: %v", err)
		}

		select {
		case data := <-resultCh:
			if len(data) == 0 {
				t.Fatal("FAIL: readLoop dropped the server's reply (0-length DCID demux miss) — the SCID fallback fix is missing")
			}
			t.Log("PASS: readLoop routed server reply via SCID fallback (the readLoop fix)")

			replyDCID, _, _ := quic.ParseDCID(data)
			if len(replyDCID) != 0 {
				t.Fatalf("FAIL: expected 0-length DCID in reply, got %d bytes", len(replyDCID))
			}
			replySCID, _, _ := quic.ParseSCID(data)
			if len(replySCID) != len(clientDCID) {
				t.Fatalf("FAIL: expected %d-byte SCID in reply, got %d bytes", len(clientDCID), len(replySCID))
			}
			t.Log("PASS: reply has DCID=∅ (echoing Chrome's SCID) and SCID=A (client's Initial DCID)")

		case <-time.After(3 * time.Second):
			t.Fatal("FAIL: readLoop did not deliver the server's reply within 3s — the reply was DROPPED (the bug)")
		}

	case <-time.After(3 * time.Second):
		t.Fatal("FAIL: server did not receive Initial within 3s")
	}
}

// Test_SCIDFallback_ParallelChromeConnections proves the fix handles
// multiple parallel Chrome connections (the YouTube scenario) without
// collision. Each connection has a unique Initial DCID, so demux entries
// don't collide.
func Test_SCIDFallback_ParallelChromeConnections(t *testing.T) {
	pool := NewUDPSocketPool(30*time.Second, 600*time.Second, 300*time.Second, nil)

	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:19996")
	if err != nil {
		t.Fatal(err)
	}
	serverConn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer serverConn.Close()

	browserSrc1 := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 50001}
	browserSrc2 := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 50002}

	pconn1, err := pool.Acquire(serverAddr)
	if err != nil {
		t.Fatalf("Acquire1 failed: %v", err)
	}
	defer pconn1.Close()
	pconn1.source = browserSrc1

	pconn2, err := pool.Acquire(serverAddr)
	if err != nil {
		t.Fatalf("Acquire2 failed: %v", err)
	}
	defer pconn2.Close()
	pconn2.source = browserSrc2

	dcid1 := []byte{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}
	dcid2 := []byte{0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22}

	initial1 := buildTestQUICInitial(t, dcid1, []byte{})
	initial2 := buildTestQUICInitial(t, dcid2, []byte{})

	pconn1.WriteTo(initial1, serverAddr)
	pconn2.WriteTo(initial2, serverAddr)

	dk1 := makeDCIDKey(dcid1)
	dk2 := makeDCIDKey(dcid2)
	pconn1.socket.mu.RLock()
	inbox1 := pconn1.socket.demux[dk1]
	inbox2 := pconn1.socket.demux[dk2]
	pconn1.socket.mu.RUnlock()

	if inbox1 == nil || inbox2 == nil {
		t.Fatal("FAIL: both DCIDs should be registered in demux")
	}
	if inbox1 == inbox2 {
		t.Fatal("FAIL: both connections mapped to same inbox — collision!")
	}
	t.Log("PASS: parallel Chrome connections have unique demux entries (no collision)")

	poolSrcCh := make(chan *net.UDPAddr, 2)
	go func() {
		buf := make([]byte, 65535)
		for i := 0; i < 2; i++ {
			_, src, err := serverConn.ReadFromUDP(buf)
			if err != nil {
				poolSrcCh <- nil
				return
			}
			poolSrcCh <- src
		}
		for {
			_, _, err := serverConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
		}
	}()

	var poolSrc *net.UDPAddr
	for i := 0; i < 2; i++ {
		select {
		case src := <-poolSrcCh:
			if src != nil {
				poolSrc = src
			}
		case <-time.After(3 * time.Second):
			t.Fatal("FAIL: server did not receive Initials within 3s")
		}
	}

	reply1 := buildTestQUICInitial(t, []byte{}, dcid1)

	resultCh := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 65535)
		n, _, _ := pconn1.ReadFrom(buf)
		resultCh <- buf[:n]
	}()

	serverConn.WriteToUDP(reply1, poolSrc)

	select {
	case data := <-resultCh:
		if len(data) == 0 {
			t.Fatal("FAIL: reply for conn1 was dropped")
		}
		t.Log("PASS: server reply for conn1 routed to conn1's inbox (not conn2's)")
	case <-time.After(3 * time.Second):
		t.Fatal("FAIL: reply for conn1 was not delivered within 3s")
	}
}

// --- Helpers ---

func buildTestQUICInitial(t *testing.T, dcid, scid []byte) []byte {
	t.Helper()
	if len(dcid) > 20 || len(scid) > 20 {
		t.Fatalf("CID too long: dcid=%d scid=%d", len(dcid), len(scid))
	}
	var pkt []byte
	pkt = append(pkt, 0xC0)
	pkt = append(pkt, 0, 0, 0, 1)
	pkt = append(pkt, byte(len(dcid)))
	pkt = append(pkt, dcid...)
	pkt = append(pkt, byte(len(scid)))
	pkt = append(pkt, scid...)
	pkt = append(pkt, 0) // token length
	pkt = append(pkt, 2) // length
	pkt = append(pkt, 0) // PN
	pkt = append(pkt, 0xFF)
	return pkt
}

func buildTestQUICHandshake(t *testing.T, dcid []byte) []byte {
	t.Helper()
	if len(dcid) > 20 {
		t.Fatalf("CID too long: %d", len(dcid))
	}
	var pkt []byte
	pkt = append(pkt, 0xE0) // Handshake type
	pkt = append(pkt, 0, 0, 0, 1)
	pkt = append(pkt, byte(len(dcid)))
	pkt = append(pkt, dcid...)
	pkt = append(pkt, 0) // SCID length = 0
	pkt = append(pkt, 2) // length
	pkt = append(pkt, 0) // PN
	pkt = append(pkt, 0xAA)
	return pkt
}
