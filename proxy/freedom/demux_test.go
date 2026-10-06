package freedom

import (
        "encoding/binary"
        "testing"
)

// TestDemuxLifecycle_BUG_v26_11_33 documents the bug that v26.11.33
// (and all prior versions) had: Close() removed the DCID from demux.
// This test verifies the bug exists in the OLD code path — it's kept
// as documentation. The fix is in TestDemuxLifecycleWithFix.
//
// This test was written against v26.11.33's behavior. With v26.11.34,
// Close() no longer removes from demux, so the assertion at step 2
// would fail. We keep this test as t.Skip to document the history.
func TestDemuxLifecycle_BUG_v26_11_33(t *testing.T) {
        t.Skip("Documenting v26.11.33 bug — fixed in v26.11.34. See TestDemuxLifecycleWithFix.")
        // Build a minimal QUIC Initial packet (long header)
        // DCID = B (server's initial DCID), SCID = A (client's SCID)
        dcidB := []byte("serverB!") // 8 bytes
        scidA := []byte("clientA!") // 8 bytes

        buildQUICInitial(t, dcidB, scidA)

        // Build a server reply Initial: DCID = A (echoing client's SCID), SCID = B'
        scidBprime := []byte("srvB2000") // 8 bytes (server's chosen SCID)
        replyInitial := buildQUICInitial(t, scidA, scidBprime)

        // Parse the DCID from the reply
        replyDCID, _, err := parseDCIDForTest(replyInitial)
        if err != nil {
                t.Fatalf("parseDCID failed: %v", err)
        }
        if !bytesEqual(replyDCID, scidA) {
                t.Fatalf("reply DCID = %x, expected %x (client's SCID)", replyDCID, scidA)
        }
        t.Logf("Server reply DCID = %x (client's SCID A)", replyDCID)

        // Build a client short header (1-RTT): DCID = B' (server's SCID)
        shortHeader := buildQUICShortHeader(t, scidBprime)

        // Parse the DCID from the short header
        shortDCID, _, err := parseDCIDForTest(shortHeader)
        if err != nil {
                t.Fatalf("parseDCID short header failed: %v", err)
        }
        if !bytesEqual(shortDCID, scidBprime) {
                t.Fatalf("short header DCID = %x, expected %x (server's SCID B')", shortDCID, scidBprime)
        }
        t.Logf("Client short header DCID = %x (server's SCID B')", shortDCID)

        // Now simulate the lifecycle:
        // 1. pooledConn1 for the Initial
        pooledConn1 := &pooledConn{
                scidsDCID: make(map[dcidKey]bool),
                inbox:     make(chan readResult, 256),
                done:      make(chan struct{}),
                socket: &pooledSocket{
                        demux: make(map[dcidKey]chan<- readResult),
                },
        }

        // Register SCID=A and DCID=B from the Initial
        pooledConn1.RegisterCID(scidA)
        pooledConn1.RegisterCID(dcidB)

        // Verify demux has both
        if _, ok := pooledConn1.socket.demux[makeDCIDKey(scidA)]; !ok {
                t.Fatal("demux should have A after Initial registration")
        }
        if _, ok := pooledConn1.socket.demux[makeDCIDKey(dcidB)]; !ok {
                t.Fatal("demux should have B after Initial registration")
        }
        t.Log("Step 1: Initial registered A and B in demux ✓")

        // 2. freedom.Process returns → pooledConn1.Close()
        pooledConn1.Close()

        // Verify demux NO LONGER has A or B (this is the bug!)
        if _, ok := pooledConn1.socket.demux[makeDCIDKey(scidA)]; ok {
                t.Fatal("BUG: demux still has A after Close — should be removed")
        }
        if _, ok := pooledConn1.socket.demux[makeDCIDKey(dcidB)]; ok {
                t.Fatal("BUG: demux still has B after Close — should be removed")
        }
        t.Log("Step 2: pooledConn1.Close() removed A and B from demux (THE BUG)")

        // 3. pooledConn2 for the short header
        pooledConn2 := &pooledConn{
                scidsDCID: make(map[dcidKey]bool),
                inbox:     make(chan readResult, 256),
                done:      make(chan struct{}),
                socket:    pooledConn1.socket, // same socket (same destination)
        }

        // v26.11.33 fix: register DCID from short header
        // The short header's DCID is B' (server's SCID), NOT A (client's SCID)
        if len(shortHeader) > 0 && shortHeader[0]&0x80 != 0 {
                // long header path
        } else if len(shortHeader) > 0 && shortHeader[0]&0x40 != 0 {
                // short header path (v26.11.33 fix)
                if dcid, _, err := parseDCIDForTest(shortHeader); err == nil {
                        pooledConn2.RegisterCID(dcid)
                }
        }

        // Check what's in demux now
        if _, ok := pooledConn2.socket.demux[makeDCIDKey(scidA)]; ok {
                t.Fatal("demux has A — but v26.11.33 fix doesn't register A from short headers!")
        }
        if _, ok := pooledConn2.socket.demux[makeDCIDKey(scidBprime)]; !ok {
                t.Log("demux has B' (v26.11.33 fix registered it) — but server never replies with B'!")
        }
        t.Log("Step 3: v26.11.33 fix registered B' (wrong DCID). A is STILL missing from demux!")

        // 4. Server replies with DCID=A (client's SCID)
        replyDCIDKey := makeDCIDKey(scidA)
        if _, ok := pooledConn2.socket.demux[replyDCIDKey]; !ok {
                t.Log("Step 4: DEMUX MISS for server reply with DCID=A — exactly what we see in production!")
                t.Fatal("CONFIRMED: v26.11.33 fix does NOT resolve the demux miss. The server replies with DCID=A (client's SCID), but A was removed from demux when pooledConn1 closed, and short headers don't re-register A.")
        }
}

// TestDemuxLifecycleWithFix tests the ACTUAL v26.11.34 fix: Close() no
// longer removes the DCID from the demux map. The DCID stays in demux
// pointing to the (now closed) inbox. New pooledConns that register the
// same DCID will overwrite the demux entry to point to their live inbox.
//
// This test calls the actual pooledConn.Close(), not a simulated one.
func TestDemuxLifecycleWithFix(t *testing.T) {
        dcidB := []byte("serverB!")
        scidA := []byte("clientA!")

        pooledConn1 := &pooledConn{
                scidsDCID: make(map[dcidKey]bool),
                inbox:     make(chan readResult, 256),
                done:      make(chan struct{}),
                socket: &pooledSocket{
                        demux: make(map[dcidKey]chan<- readResult),
                },
        }

        pooledConn1.RegisterCID(scidA)
        pooledConn1.RegisterCID(dcidB)

        // Call the ACTUAL Close() — the v26.11.34 fix.
        if err := pooledConn1.Close(); err != nil {
                t.Fatalf("Close failed: %v", err)
        }

        // Verify demux STILL has A and B (the fix: don't remove on Close)
        if _, ok := pooledConn1.socket.demux[makeDCIDKey(scidA)]; !ok {
                t.Fatal("FIX FAILED: demux should still have A after Close (v26.11.34 fix)")
        }
        if _, ok := pooledConn1.socket.demux[makeDCIDKey(dcidB)]; !ok {
                t.Fatal("FIX FAILED: demux should still have B after Close (v26.11.34 fix)")
        }
        t.Log("FIX OK: demux still has A and B after Close()")

        // Now pooledConn2 registers A (the client's SCID that the server will reply with)
        scidBprime := []byte("srvB2000")
        pooledConn2 := &pooledConn{
                scidsDCID: make(map[dcidKey]bool),
                inbox:     make(chan readResult, 256),
                done:      make(chan struct{}),
                socket:    pooledConn1.socket,
        }
        pooledConn2.RegisterCID(scidA)    // re-register A → demux[A] = inbox2
        pooledConn2.RegisterCID(scidBprime)

        // Verify demux[A] now points to inbox2 (overwritten)
        inbox, ok := pooledConn2.socket.demux[makeDCIDKey(scidA)]
        if !ok {
                t.Fatal("demux should have A")
        }
        if inbox != pooledConn2.inbox {
                t.Fatal("demux[A] should point to inbox2 after re-registration")
        }
        t.Log("FIX OK: demux[A] now points to pooledConn2.inbox — server reply will be delivered!")

        // Verify the server's reply DCID (= A) would be delivered to inbox2
        // This is the exact scenario that was failing in production.
        replyDCIDKey := makeDCIDKey(scidA)
        targetInbox, ok := pooledConn2.socket.demux[replyDCIDKey]
        if !ok {
                t.Fatal("CONFIRMED BUG: server reply with DCID=A would be demux miss")
        }
        if targetInbox != pooledConn2.inbox {
                t.Fatal("demux[A] doesn't point to live inbox2")
        }
        t.Log("PRODUCTION SCENARIO FIXED: server reply DCID=A → demux hit → inbox2 (live)")
}

// === Helpers ===

func buildQUICInitial(t *testing.T, dcid, scid []byte) []byte {
        t.Helper()
        if len(dcid) > 20 || len(scid) > 20 {
                t.Fatalf("CID too long: dcid=%d scid=%d", len(dcid), len(scid))
        }

        var pkt []byte
        // First byte: 1100 0000 = long header, Initial type (00), 1-byte PN
        pkt = append(pkt, 0xC0)
        // Version = 1
        pkt = append(pkt, 0, 0, 0, 1)
        // DCID length + DCID
        pkt = append(pkt, byte(len(dcid)))
        pkt = append(pkt, dcid...)
        // SCID length + SCID
        pkt = append(pkt, byte(len(scid)))
        pkt = append(pkt, scid...)
        // Token length = 0 (varint 1 byte)
        pkt = append(pkt, 0)
        // Length = 2 (varint 1 byte) = PN(1) + payload(1)
        pkt = append(pkt, 2)
        // Packet number = 0
        pkt = append(pkt, 0)
        // Payload (1 byte)
        pkt = append(pkt, 0xFF)
        return pkt
}

func buildQUICShortHeader(t *testing.T, dcid []byte) []byte {
        t.Helper()
        if len(dcid) > 20 {
                t.Fatalf("CID too long: %d", len(dcid))
        }
        var pkt []byte
        // First byte: 0100 0000 = short header, fixed bit set
        pkt = append(pkt, 0x40)
        // DCID (no length prefix)
        pkt = append(pkt, dcid...)
        // Packet number (1 byte)
        pkt = append(pkt, 0)
        // Payload
        pkt = append(pkt, 0xAA)
        return pkt
}

func parseDCIDForTest(packet []byte) ([]byte, bool, error) {
        if len(packet) < 1 {
                return nil, false, nil
        }
        firstByte := packet[0]
        if firstByte&0x80 != 0 {
                // Long header
                if len(packet) < 6 {
                        return nil, true, nil
                }
                dcidLen := int(packet[5])
                if dcidLen > 20 {
                        return nil, true, nil
                }
                end := 6 + dcidLen
                if len(packet) < end {
                        return nil, true, nil
                }
                dcid := make([]byte, dcidLen)
                copy(dcid, packet[6:end])
                return dcid, true, nil
        }
        // Short header — use 8-byte DCID (default)
        if firstByte&0x40 != 0 {
                cidLen := 8
                if len(packet) < 1+cidLen {
                        return nil, false, nil
                }
                dcid := make([]byte, cidLen)
                copy(dcid, packet[1:1+cidLen])
                return dcid, false, nil
        }
        return nil, false, nil
}

func bytesEqual(a, b []byte) bool {
        if len(a) != len(b) {
                return false
        }
        for i := range a {
                if a[i] != b[i] {
                        return false
                }
        }
        return true
}

// Suppress unused import warning
var _ = binary.BigEndian
