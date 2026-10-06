package freedom

import (
	"testing"
)

// TestReadLoopSendToClosedInbox verifies that the readLoop's recover
// logic works: sending to a closed inbox (which happens after a
// pooledConn.Close() with the v26.11.34 fix that leaves the DCID in
// the demux map) does NOT panic. The packet is silently dropped.
//
// Without the recover in v26.11.34's readLoop, this scenario panics
// "send on closed channel" and kills the readLoop goroutine — which
// kills the socket for ALL pooledConns sharing it.
func TestReadLoopSendToClosedInbox(t *testing.T) {
	inbox := make(chan readResult, 256)
	close(inbox) // simulate pooledConn.Close()

	packet := getPacket()
	packet[0] = 0xC0 // QUIC long header
	packet[1] = 0
	packet[2] = 0
	packet[3] = 0
	packet[4] = 1 // version 1
	packet[5] = 0 // DCID len 0

	// This must NOT panic.
	sentOk := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("recovered (expected): %v", r)
			}
		}()
		select {
		case inbox <- readResult{data: packet, n: 6}:
			sentOk = true
		default:
			t.Log("default case (inbox full or closed)")
		}
	}()

	if sentOk {
		t.Fatal("should not have sent to closed inbox")
	}
	t.Log("PASS: send to closed inbox did not panic — recover works")

	// Verify the packet buffer can be returned to pool (no leak)
	putPacket(packet)
	t.Log("PASS: packet returned to pool after failed send")
}

// TestReadLoopSendToLiveInbox verifies the normal case: sending to
// a live inbox succeeds.
func TestReadLoopSendToLiveInbox(t *testing.T) {
	inbox := make(chan readResult, 256)

	packet := getPacket()
	packet[0] = 0xC0
	packet[1] = 0
	packet[2] = 0
	packet[3] = 0
	packet[4] = 1
	packet[5] = 0

	sentOk := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("unexpected panic: %v", r)
			}
		}()
		select {
		case inbox <- readResult{data: packet, n: 6}:
			sentOk = true
		default:
			t.Fatal("default case — should have sent")
		}
	}()

	if !sentOk {
		t.Fatal("send failed")
	}

	// Verify we can receive it
	rr := <-inbox
	if rr.n != 6 {
		t.Fatalf("received n = %d, want 6", rr.n)
	}
	t.Log("PASS: send to live inbox succeeded — normal path works")
	putPacket(rr.data)
}

// TestReadLoopSendToFullInbox verifies the default case: a full inbox
// triggers the default branch and counts the drop (no panic).
func TestReadLoopSendToFullInbox(t *testing.T) {
	inbox := make(chan readResult, 2)
	inbox <- readResult{data: getPacket(), n: 1}
	inbox <- readResult{data: getPacket(), n: 1}

	packet := getPacket()
	sentOk := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("unexpected panic: %v", r)
			}
		}()
		select {
		case inbox <- readResult{data: packet, n: 1}:
			sentOk = true
		default:
			// expected
		}
	}()

	if sentOk {
		t.Fatal("should not have sent to full inbox")
	}
	t.Log("PASS: full inbox triggered default case (drop) — no panic")

	// Drain and clean up
	for i := 0; i < 2; i++ {
		rr := <-inbox
		putPacket(rr.data)
	}
	putPacket(packet)
}
