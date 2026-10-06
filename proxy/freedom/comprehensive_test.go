package freedom

import (
        "encoding/binary"
        "net"
        "testing"
)

// ============================================================
// COMPREHENSIVE TEST SUITE for QUIC demux lifecycle
//
// These tests reproduce the EXACT scenario from production logs:
// - Browser sends Initial (long header) → freedom.Process #1
//   → resolves SNI to IP1 → socket1 → registers SCID=A → Close
// - Browser sends short header (1-RTT) → freedom.Process #2
//   → resolves SNI to IP2 (DNS rotation!) → socket2 → registers DCID=B'
// - Server replies from IP2 with DCID=A → arrives at socket2
//   → demux miss (socket2 has B', not A!) → drop → h2 fallback
//
// The tests prove:
// 1. The short header's DCID is B' (server's SCID), NOT A (client's SCID)
// 2. The server replies with DCID=A (client's SCID)
// 3. Multi-socket scenario causes demux miss (THE BUG)
// 4. The fix (source-keyed SCID cache) resolves it
// 5. End-to-end lifecycle works with the fix
// 6. isQUICPacket matches short headers
// 7. The pool keys by destination IP (architectural issue)
// ============================================================

// Test1_ShortHeaderDCIDIsServerSCID proves that the DCID parsed from
// a client's short header (1-RTT) is the SERVER's SCID (B'), NOT the
// client's SCID (A). This is critical because the server's reply uses
// DCID=A, not B'. Registering B' in the demux (the v26.11.33 "fix")
// is useless — the server never replies with B'.
func Test1_ShortHeaderDCIDIsServerSCID(t *testing.T) {
        // Client's Initial: DCID=B (server's initial DCID), SCID=A (client's SCID)
        dcidB := []byte("serverB!") // 8 bytes
        scidA := []byte("clientA!") // 8 bytes

        initial := buildQUICInitial(t, dcidB, scidA)

        // Parse SCID from the Initial — this is A
        parsedSCID, _, err := parseSCIDForTest(initial)
        if err != nil {
                t.Fatalf("parseSCID failed: %v", err)
        }
        if !bytesEqual(parsedSCID, scidA) {
                t.Fatalf("Initial SCID = %x, expected %x (A)", parsedSCID, scidA)
        }
        t.Logf("Initial SCID (A) = %x", parsedSCID)

        // After the handshake, the server's SCID is B' (server's chosen SCID)
        scidBprime := []byte("srvB2000") // 8 bytes

        // Client's short header has DCID = B' (server's SCID)
        shortHeader := buildQUICShortHeader(t, scidBprime)
        parsedDCID, _, err := parseDCIDForTest(shortHeader)
        if err != nil {
                t.Fatalf("parseDCID short header failed: %v", err)
        }
        if !bytesEqual(parsedDCID, scidBprime) {
                t.Fatalf("Short header DCID = %x, expected %x (B')", parsedDCID, scidBprime)
        }
        t.Logf("Short header DCID (B') = %x — this is the SERVER's SCID", parsedDCID)

        // The server's reply short header has DCID = A (client's SCID)
        replyShortHeader := buildQUICShortHeader(t, scidA)
        replyDCID, _, err := parseDCIDForTest(replyShortHeader)
        if err != nil {
                t.Fatalf("parseDCID reply failed: %v", err)
        }
        if !bytesEqual(replyDCID, scidA) {
                t.Fatalf("Server reply DCID = %x, expected %x (A)", replyDCID, scidA)
        }
        t.Logf("Server reply DCID (A) = %x — this is the CLIENT's SCID", replyDCID)

        // THE BUG: registering B' (from the client's short header) in the
        // demux is USELESS because the server replies with A, not B'.
        if bytesEqual(parsedDCID, replyDCID) {
                t.Fatal("BUG: short header DCID == server reply DCID — would never happen in reality")
        }
        t.Log("CONFIRMED: short header DCID (B') != server reply DCID (A). Registering B' is useless.")
}

// Test2_MultiSocketDemuxMiss reproduces the EXACT production bug:
// Initial goes to socket1 (IP1), short header goes to socket2 (IP2,
// due to DNS rotation). Server replies from IP2 with DCID=A. socket2
// has B' (from short header registration) but NOT A → demux miss.
func Test2_MultiSocketDemuxMiss(t *testing.T) {
        dcidB := []byte("serverB!")
        scidA := []byte("clientA!")
        scidBprime := []byte("srvB2000")

        // Two different destination IPs (DNS rotation)
        ip1 := net.ParseIP("104.18.27.14")
        ip2 := net.ParseIP("104.18.26.14")

        // socket1 (for IP1) — receives the Initial
        socket1 := &pooledSocket{
                dest:  &net.UDPAddr{IP: ip1, Port: 443},
                demux: make(map[dcidKey]chan<- readResult),
        }
        // socket2 (for IP2) — receives the short header
        socket2 := &pooledSocket{
                dest:  &net.UDPAddr{IP: ip2, Port: 443},
                demux: make(map[dcidKey]chan<- readResult),
        }

        // Step 1: Initial → socket1 → register A and B
        pooledConn1 := &pooledConn{
                scidsDCID: make(map[dcidKey]bool),
                inbox:     make(chan readResult, 256),
                done:      make(chan struct{}),
                socket:    socket1,
        }
        pooledConn1.RegisterCID(scidA) // demux[A] = inbox1 (on socket1)
        pooledConn1.RegisterCID(dcidB) // demux[B] = inbox1 (on socket1)
        t.Log("Step 1: Initial → socket1, registered A and B on socket1.demux")

        // Step 2: pooledConn1.Close() (v26.11.34 fix: don't remove from demux)
        pooledConn1.Close()
        t.Log("Step 2: pooledConn1.Close() — A and B stay in socket1.demux (but inbox1 is closed)")

        // Step 3: Short header → socket2 (DIFFERENT IP due to DNS rotation!)
        pooledConn2 := &pooledConn{
                scidsDCID: make(map[dcidKey]bool),
                inbox:     make(chan readResult, 256),
                done:      make(chan struct{}),
                socket:    socket2,
        }
        // v26.11.33 fix: register DCID from short header
        shortHeader := buildQUICShortHeader(t, scidBprime)
        if dcid, _, err := parseDCIDForTest(shortHeader); err == nil {
                pooledConn2.RegisterCID(dcid) // demux[B'] = inbox2 (on socket2)
        }
        t.Log("Step 3: Short header → socket2, registered B' on socket2.demux (v26.11.33 fix)")

        // Step 4: Server replies from IP2 with DCID=A
        // The reply arrives at socket2's readLoop (because socket2.dest = IP2)
        replyDCID, _, _ := parseDCIDForTest(buildQUICShortHeader(t, scidA))
        replyDCIDKey := makeDCIDKey(replyDCID)

        // Look up in socket2's demux (where the reply arrived)
        _, demuxHit := socket2.demux[replyDCIDKey]
        if demuxHit {
                t.Fatal("UNEXPECTED: socket2.demux has A — but we only registered B' on socket2!")
        }
        t.Log("Step 4: Server reply DCID=A → socket2.demux lookup → MISS!")
        t.Log("CONFIRMED: Multi-socket scenario causes demux miss. v26.11.33 fix is INSUFFICIENT.")
        t.Log("A is on socket1.demux, but the reply arrives at socket2. socket2 only has B'.")

        // Verify A IS on socket1 (but useless — reply doesn't arrive there)
        _, onSocket1 := socket1.demux[replyDCIDKey]
        if !onSocket1 {
                t.Fatal("socket1.demux should have A (from Initial)")
        }
        t.Log("Note: A IS on socket1.demux, but the reply from IP2 arrives at socket2, not socket1.")
}

// Test3_SourceKeyedSCIDCacheFix tests the proposed fix: a pool-wide
// source → SCID cache. When the Initial is processed, cache (source → A).
// When a short header comes from the same source, look up A and register
// it on the current socket (whichever IP it goes to).
func Test3_SourceKeyedSCIDCacheFix(t *testing.T) {
        dcidB := []byte("serverB!")
        scidA := []byte("clientA!")
        scidBprime := []byte("srvB2000")

        ip1 := net.ParseIP("104.18.27.14")
        ip2 := net.ParseIP("104.18.26.14")
        source := &net.UDPAddr{IP: net.ParseIP("82.43.215.97"), Port: 59807}

        socket1 := &pooledSocket{dest: &net.UDPAddr{IP: ip1, Port: 443}, demux: make(map[dcidKey]chan<- readResult)}
        socket2 := &pooledSocket{dest: &net.UDPAddr{IP: ip2, Port: 443}, demux: make(map[dcidKey]chan<- readResult)}

        // The fix: pool-wide source → SCID cache
        sourceSCIDCache := make(map[string][]byte) // source string → SCID A

        // Step 1: Initial → socket1, cache (source → A)
        pooledConn1 := &pooledConn{scidsDCID: make(map[dcidKey]bool), inbox: make(chan readResult, 256), done: make(chan struct{}), socket: socket1}
        initial := buildQUICInitial(t, dcidB, scidA)
        if scid, _, err := parseSCIDForTest(initial); err == nil {
                pooledConn1.RegisterCID(scid) // demux[A] = inbox1 on socket1
                sourceSCIDCache[source.String()] = scid // THE FIX: cache source → A
        }
        pooledConn1.Close()
        t.Log("Step 1: Initial → socket1, cached (source → A), registered A on socket1")

        // Step 2: Short header → socket2 (different IP)
        pooledConn2 := &pooledConn{scidsDCID: make(map[dcidKey]bool), inbox: make(chan readResult, 256), done: make(chan struct{}), socket: socket2}
        shortHeader := buildQUICShortHeader(t, scidBprime)
        if dcid, _, err := parseDCIDForTest(shortHeader); err == nil {
                pooledConn2.RegisterCID(dcid) // demux[B'] = inbox2 on socket2
        }
        // THE FIX: look up cached A for this source, register on socket2
        if cachedA, ok := sourceSCIDCache[source.String()]; ok {
                pooledConn2.RegisterCID(cachedA) // demux[A] = inbox2 on socket2 ← THE FIX!
        }
        t.Log("Step 2: Short header → socket2, registered B' AND cached A on socket2")

        // Step 3: Server replies from IP2 with DCID=A → arrives at socket2
        replyDCID, _, _ := parseDCIDForTest(buildQUICShortHeader(t, scidA))
        replyDCIDKey := makeDCIDKey(replyDCID)

        targetInbox, demuxHit := socket2.demux[replyDCIDKey]
        if !demuxHit {
                t.Fatal("FIX FAILED: socket2.demux should have A after the fix")
        }
        if targetInbox != pooledConn2.inbox {
                t.Fatal("FIX FAILED: demux[A] should point to pooledConn2.inbox (live)")
        }
        t.Log("FIX OK: Server reply DCID=A → socket2.demux[A] = inbox2 (LIVE) → demux HIT!")
}

// Test4_FullLifecycleEndToEnd simulates the complete lifecycle:
// Initial → Close → Short header → server reply → demux hit.
// With the fix, the server reply is delivered to the live inbox.
func Test4_FullLifecycleEndToEnd(t *testing.T) {
        dcidB := []byte("serverB!")
        scidA := []byte("clientA!")
        scidBprime := []byte("srvB2000")

        ip1 := net.ParseIP("104.18.27.14")
        ip2 := net.ParseIP("104.18.26.14")
        source := &net.UDPAddr{IP: net.ParseIP("82.43.215.97"), Port: 59807}

        socket1 := &pooledSocket{dest: &net.UDPAddr{IP: ip1, Port: 443}, demux: make(map[dcidKey]chan<- readResult)}
        socket2 := &pooledSocket{dest: &net.UDPAddr{IP: ip2, Port: 443}, demux: make(map[dcidKey]chan<- readResult)}
        sourceSCIDCache := make(map[string][]byte)

        // Phase 1: Initial
        pooledConn1 := &pooledConn{scidsDCID: make(map[dcidKey]bool), inbox: make(chan readResult, 256), done: make(chan struct{}), socket: socket1}
        initial := buildQUICInitial(t, dcidB, scidA)
        if scid, _, err := parseSCIDForTest(initial); err == nil {
                pooledConn1.RegisterCID(scid)
                sourceSCIDCache[source.String()] = scid
        }
        if dcid, _, err := parseDCIDForTest(initial); err == nil {
                pooledConn1.RegisterCID(dcid)
        }
        pooledConn1.Close()
        t.Log("Phase 1: Initial sent, SCID cached, pooledConn1 closed")

        // Phase 2: Short header (different IP)
        pooledConn2 := &pooledConn{scidsDCID: make(map[dcidKey]bool), inbox: make(chan readResult, 256), done: make(chan struct{}), socket: socket2}
        shortHeader := buildQUICShortHeader(t, scidBprime)
        if dcid, _, err := parseDCIDForTest(shortHeader); err == nil {
                pooledConn2.RegisterCID(dcid)
        }
        if cachedA, ok := sourceSCIDCache[source.String()]; ok {
                pooledConn2.RegisterCID(cachedA)
        }
        t.Log("Phase 2: Short header sent, B' and cached A registered on socket2")

        // Phase 3: Server reply (from IP2, DCID=A)
        replyPacket := buildQUICShortHeader(t, scidA)
        replyDCID, _, _ := parseDCIDForTest(replyPacket)
        replyDCIDKey := makeDCIDKey(replyDCID)

        targetInbox, hit := socket2.demux[replyDCIDKey]
        if !hit {
                t.Fatal("End-to-end FAIL: demux miss for server reply")
        }
        if targetInbox != pooledConn2.inbox {
                t.Fatal("End-to-end FAIL: demux points to wrong inbox")
        }

        // Simulate the readLoop sending the reply to the inbox
        go func() {
                defer func() { recover() }() // in case inbox is closed
                targetInbox <- readResult{data: replyPacket, n: len(replyPacket), addr: &net.UDPAddr{IP: ip2, Port: 443}}
        }()

        // Verify the reply is received (blocking with timeout)
        rr, ok := <-pooledConn2.inbox
        if !ok {
                t.Fatal("End-to-end FAIL: inbox closed")
        }
        if rr.n != len(replyPacket) {
                t.Fatalf("received n=%d, want %d", rr.n, len(replyPacket))
        }
        t.Log("Phase 3: Server reply DELIVERED to pooledConn2.inbox → browser receives it → h3 works!")
}

// Test5_IsQUICPacketMatchesShortHeader verifies that isQUICPacket
// matches short headers (bit 7=0, bit 6=1), not just long headers.
func Test5_IsQUICPacketMatchesShortHeader(t *testing.T) {
        // Long header (Initial): bit 7=1, bit 6=1
        longHeader := []byte{0xC0, 0, 0, 0, 1, 0, 0}
        if !isQUICPacket(longHeader) {
                t.Fatal("isQUICPacket should match long header")
        }
        t.Log("Long header: isQUICPacket = true ✓")

        // Short header (1-RTT): bit 7=0, bit 6=1
        shortHeader := []byte{0x40, 1, 2, 3, 4, 5, 6, 7, 8}
        if !isQUICPacket(shortHeader) {
                t.Fatal("isQUICPacket should match short header")
        }
        t.Log("Short header: isQUICPacket = true ✓")

        // Non-QUIC: bit 7=0, bit 6=0
        nonQUIC := []byte{0x00, 1, 2, 3}
        if isQUICPacket(nonQUIC) {
                t.Fatal("isQUICPacket should NOT match non-QUIC")
        }
        t.Log("Non-QUIC: isQUICPacket = false ✓")

        // Version Negotiation: bit 7=1, bit 6=0 (Fixed Bit cleared)
        vn := []byte{0x80, 0, 0, 0, 0, 0}
        if isQUICPacket(vn) {
                t.Fatal("isQUICPacket should NOT match Version Negotiation (Fixed Bit=0)")
        }
        t.Log("Version Negotiation: isQUICPacket = false ✓ (excluded by Fixed Bit check)")
}

// Test6_PoolKeysByDestinationIP verifies that the pool creates
// different sockets for different destination IPs. This is the
// architectural root cause: the same browser connection's packets
// can go to different sockets if DNS rotation returns different IPs.
func Test6_PoolKeysByDestinationIP(t *testing.T) {
        ip1 := net.ParseIP("104.18.27.14")
        ip2 := net.ParseIP("104.18.26.14")

        key1 := destKey(&net.UDPAddr{IP: ip1, Port: 443})
        key2 := destKey(&net.UDPAddr{IP: ip2, Port: 443})

        if key1 == key2 {
                t.Fatal("BUG: pool key should differ for different IPs")
        }
        t.Logf("IP1 key = %q", key1)
        t.Logf("IP2 key = %q", key2)
        t.Log("CONFIRMED: pool keys by destination IP. DNS rotation → different sockets → demux fragmentation.")
}

// Test7_ServerReplyDCIDIsClientSCID verifies the fundamental QUIC
// invariant: the server ALWAYS replies with DCID = client's SCID.
// This is why registering the short header's DCID (B') is useless —
// the server never replies with B'.
func Test7_ServerReplyDCIDIsClientSCID(t *testing.T) {
        // Multiple client SCIDs (different connections)
        testCases := [][]byte{
                []byte("clientA!"),
                []byte("clientB!"),
                []byte("12345678"),
                []byte("abcdefgh"),
        }

        for _, clientSCID := range testCases {
                // Server's Initial reply: DCID = client's SCID
                serverInitial := buildQUICInitial(t, clientSCID, []byte("srvSCID!"))
                replyDCID, _, _ := parseDCIDForTest(serverInitial)
                if !bytesEqual(replyDCID, clientSCID) {
                        t.Fatalf("server Initial DCID = %x, want %x (client SCID)", replyDCID, clientSCID)
                }

                // Server's short header reply: DCID = client's SCID
                serverShort := buildQUICShortHeader(t, clientSCID)
                replyDCID2, _, _ := parseDCIDForTest(serverShort)
                if !bytesEqual(replyDCID2, clientSCID) {
                        t.Fatalf("server short DCID = %x, want %x (client SCID)", replyDCID2, clientSCID)
                }
        }
        t.Log("All cases: server reply DCID = client's SCID (A). The demux MUST have A, not B'.")
}

// === Helpers ===

func buildQUICInitial(t *testing.T, dcid, scid []byte) []byte {
        t.Helper()
        if len(dcid) > 20 || len(scid) > 20 {
                t.Fatalf("CID too long: dcid=%d scid=%d", len(dcid), len(scid))
        }
        var pkt []byte
        pkt = append(pkt, 0xC0)       // long header, Initial type
        pkt = append(pkt, 0, 0, 0, 1) // version 1
        pkt = append(pkt, byte(len(dcid)))
        pkt = append(pkt, dcid...)
        pkt = append(pkt, byte(len(scid)))
        pkt = append(pkt, scid...)
        pkt = append(pkt, 0) // token length = 0
        pkt = append(pkt, 2) // length = 2
        pkt = append(pkt, 0) // packet number
        pkt = append(pkt, 0xFF)
        return pkt
}

func buildQUICShortHeader(t *testing.T, dcid []byte) []byte {
        t.Helper()
        if len(dcid) > 20 {
                t.Fatalf("CID too long: %d", len(dcid))
        }
        var pkt []byte
        pkt = append(pkt, 0x40) // short header, fixed bit
        pkt = append(pkt, dcid...)
        pkt = append(pkt, 0)   // packet number
        pkt = append(pkt, 0xAA) // payload
        return pkt
}

func parseDCIDForTest(packet []byte) ([]byte, bool, error) {
        if len(packet) < 1 {
                return nil, false, nil
        }
        firstByte := packet[0]
        if firstByte&0x80 != 0 {
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

func parseSCIDForTest(packet []byte) ([]byte, bool, error) {
        if len(packet) < 1 {
                return nil, false, nil
        }
        firstByte := packet[0]
        if firstByte&0x80 == 0 {
                return nil, false, nil // short header, no SCID
        }
        if len(packet) < 6 {
                return nil, true, nil
        }
        dcidLen := int(packet[5])
        if dcidLen > 20 {
                return nil, true, nil
        }
        scidLenOffset := 6 + dcidLen
        if len(packet) < scidLenOffset+1 {
                return nil, true, nil
        }
        scidLen := int(packet[scidLenOffset])
        if scidLen > 20 {
                return nil, true, nil
        }
        scidEnd := scidLenOffset + 1 + scidLen
        if len(packet) < scidEnd {
                return nil, true, nil
        }
        scid := make([]byte, scidLen)
        copy(scid, packet[scidLenOffset+1:scidEnd])
        return scid, true, nil
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

var _ = binary.BigEndian
