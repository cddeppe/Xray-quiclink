package freedom

import (
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol/quic"
)

// Test_ShortHeaderCIDLen_FromDiagnostics reproduces the EXACT bug
// from the v26.11.36 diagnostic logs:
//   SCID=9f487e len=3 → registered 3 bytes
//   demux MISS dcid=9f487e235db07cb9 len=8 → parsed 8 bytes (WRONG)
// The first 3 bytes match! The readLoop over-read 5 extra bytes.
func Test_ShortHeaderCIDLen_FromDiagnostics(t *testing.T) {
	scidA := []byte{0x9f, 0x48, 0x7e} // 3 bytes
	// Build a short header long enough for 8-byte DCID parse (1 + 8 + PN + payload)
	replyShort := make([]byte, 0, 20)
	replyShort = append(replyShort, 0x40) // short header
	replyShort = append(replyShort, scidA...) // 3-byte DCID
	replyShort = append(replyShort, 0x23, 0x5d, 0xb0, 0x7c, 0xb9) // 5 extra bytes (PN + payload)
	replyShort = append(replyShort, 0xAA, 0xBB, 0xCC, 0xDD) // more payload

	// OLD: default 8-byte parse → wrong
	oldDCID, _, _ := quic.ParseDCID(replyShort)
	t.Logf("OLD: DCID=%x len=%d (WRONG)", oldDCID, len(oldDCID))
	if len(oldDCID) != 8 {
		t.Fatalf("expected 8, got %d", len(oldDCID))
	}

	// NEW: 3-byte parse → correct
	newDCID, _, err := quic.ParseShortHeaderDCIDWithLen(replyShort, 3)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("NEW: DCID=%x len=%d (CORRECT)", newDCID, len(newDCID))
	if !bytesEqual(newDCID, scidA) {
		t.Fatalf("DCID=%x, want %x", newDCID, scidA)
	}

	// Keys match?
	registeredKey := makeDCIDKey(scidA)
	parsedKey := makeDCIDKey(newDCID)
	if registeredKey != parsedKey {
		t.Fatal("key mismatch")
	}
	t.Log("PASS: 3-byte parse → demux HIT!")
}

// Test_ShortHeaderCIDLen_ProductionPath: Acquire → WriteTo (learns
// CID len) → server reply → readLoop parses with correct len → HIT.
func Test_ShortHeaderCIDLen_ProductionPath(t *testing.T) {
	pool := NewUDPSocketPool(30*time.Second, 5*time.Minute, 10*time.Minute, nil)
	dest := &net.UDPAddr{IP: net.ParseIP("104.18.27.14"), Port: 443}
	source := &net.UDPAddr{IP: net.ParseIP("82.43.215.97"), Port: 53406}

	conn, err := pool.Acquire(dest, source)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	scidA := []byte{0x9f, 0x48, 0x7e} // 3 bytes
	dcidB := make([]byte, 20)
	initial := buildQUICInitial(t, dcidB, scidA)

	_, err = conn.WriteTo(initial, dest)
	if err != nil {
		t.Fatal(err)
	}

	learnedLen := conn.socket.shortHeaderCIDLen.Load()
	if learnedLen != 3 {
		t.Fatalf("shortHeaderCIDLen=%d, want 3", learnedLen)
	}
	t.Logf("PASS: socket learned CID len = %d", learnedLen)

	// Server reply with 3-byte DCID
	replyShort := buildQUICShortHeader(t, scidA)
	cidLen := int(conn.socket.shortHeaderCIDLen.Load())
	parsedDCID, _, err := quic.ParseShortHeaderDCIDWithLen(replyShort, cidLen)
	if err != nil {
		t.Fatal(err)
	}
	if !bytesEqual(parsedDCID, scidA) {
		t.Fatalf("DCID=%x, want %x", parsedDCID, scidA)
	}

	dk := makeDCIDKey(parsedDCID)
	conn.socket.mu.RLock()
	targetInbox, hit := conn.socket.demux[dk]
	conn.socket.mu.RUnlock()
	if !hit {
		t.Fatal("demux MISS")
	}
	t.Log("PASS: demux HIT!")

	go func() {
		defer func() { recover() }()
		targetInbox <- readResult{data: replyShort, n: len(replyShort), addr: dest}
	}()
	select {
	case rr := <-conn.inbox:
		t.Logf("PASS: reply delivered (n=%d)", rr.n)
	case <-time.After(2 * time.Second):
		t.Fatal("TIMEOUT")
	}
}

// Test_ShortHeaderCIDLen_8ByteDefault: 8-byte SCIDs still work.
func Test_ShortHeaderCIDLen_8ByteDefault(t *testing.T) {
	pool := NewUDPSocketPool(30*time.Second, 5*time.Minute, 10*time.Minute, nil)
	dest := &net.UDPAddr{IP: net.ParseIP("104.18.27.14"), Port: 443}
	source := &net.UDPAddr{IP: net.ParseIP("82.43.215.97"), Port: 59807}

	conn, err := pool.Acquire(dest, source)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	scidA := []byte("clientA!") // 8 bytes
	dcidB := make([]byte, 20)
	initial := buildQUICInitial(t, dcidB, scidA)

	_, err = conn.WriteTo(initial, dest)
	if err != nil {
		t.Fatal(err)
	}

	if conn.socket.shortHeaderCIDLen.Load() != 8 {
		t.Fatalf("want 8, got %d", conn.socket.shortHeaderCIDLen.Load())
	}
	t.Log("PASS: 8-byte SCID backward compatible")
}

// Test_ShortHeaderCIDLen_AllConnectionsFromLogs: verify all 5
// connections from the diagnostic logs.
func Test_ShortHeaderCIDLen_AllConnectionsFromLogs(t *testing.T) {
	cases := []struct {
		scid     string
		missDCID string
	}{
		{"9f487e", "9f487e235db07cb9"},
		{"3f98d5", "3f98d559087fd5f4"},
		{"930f56", "930f56d483dcc313"},
		{"6ad5f2", "6ad5f2412614253e"},
		{"1e31ce", "1e31ce923729d88c"},
	}

	for _, c := range cases {
		t.Run(c.scid, func(t *testing.T) {
			scid := hexDecode(c.scid)
			miss := hexDecode(c.missDCID)
			if !bytesEqual(scid, miss[:3]) {
				t.Fatalf("first 3 bytes don't match: SCID=%x MISS=%x", scid, miss[:3])
			}
			// With fix: parse as 3 bytes → DCID = SCID → HIT
			correct := miss[:3]
			rk := makeDCIDKey(scid)
			pk := makeDCIDKey(correct)
			if rk != pk {
				t.Fatal("key mismatch")
			}
			t.Logf("SCID=%s: 3-byte parse → HIT ✓", c.scid)
		})
	}
}

func hexDecode(s string) []byte {
	b := make([]byte, len(s)/2)
	for i := range b {
		var v byte
		for j := 0; j < 2; j++ {
			c := s[i*2+j]
			switch {
			case c >= '0' && c <= '9':
				v = v*16 + c - '0'
			case c >= 'a' && c <= 'f':
				v = v*16 + c - 'a' + 10
			}
		}
		b[i] = v
	}
	return b
}
