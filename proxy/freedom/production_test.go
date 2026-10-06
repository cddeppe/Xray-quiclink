package freedom

import (
	"net"
	"testing"
	"time"
)

// ============================================================
// PRODUCTION-PATH TESTS — use the actual UDPSocketPool.Acquire
// and pooledConn.WriteTo (real UDP sockets, real demux maps, real
// source → SCID cache). These verify the fix works end-to-end
// through the real code path, not simulated structs.
// ============================================================

// Test8_ProductionPath_SourceSCIDCachePopulated verifies that calling
// WriteTo with a QUIC Initial populates the pool's source → SCID cache.
// This is the first half of the v26.11.35 fix.
func Test8_ProductionPath_SourceSCIDCachePopulated(t *testing.T) {
	pool := NewUDPSocketPool(30*time.Second, 5*time.Minute, 10*time.Minute, nil)

	dest := &net.UDPAddr{IP: net.ParseIP("104.18.27.14"), Port: 443}
	source := &net.UDPAddr{IP: net.ParseIP("82.43.215.97"), Port: 59807}

	conn, err := pool.Acquire(dest, source)
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}
	defer conn.Close()

	// Build a QUIC Initial with SCID = A
	dcidB := []byte("serverB!")
	scidA := []byte("clientA!")
	initial := buildQUICInitial(t, dcidB, scidA)

	// WriteTo should register the SCID in the demux AND cache it in
	// the pool's sourceSCIDCache.
	_, err = conn.WriteTo(initial, dest)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}

	// Verify the source → SCID cache was populated
	pool.sourceSCIDCacheMu.RLock()
	cachedSCID, ok := pool.sourceSCIDCache[source.String()]
	pool.sourceSCIDCacheMu.RUnlock()

	if !ok {
		t.Fatal("sourceSCIDCache was NOT populated after WriteTo with Initial")
	}
	if !bytesEqual(cachedSCID, scidA) {
		t.Fatalf("cached SCID = %x, want %x (A)", cachedSCID, scidA)
	}
	t.Logf("PASS: sourceSCIDCache[%s] = %x (A) — populated by WriteTo with Initial", source.String(), cachedSCID)
}

// Test9_ProductionPath_MultiSocketDemuxHit is THE critical test. It
// verifies the full production scenario:
// 1. Initial → socket1 (IP1) → WriteTo → cache (source → A), register A on socket1
// 2. Close socket1 (simulating freedom.Process return)
// 3. Short header → socket2 (IP2, different IP) → WriteTo →
//    look up cached A, register A on socket2
// 4. Server reply from IP2 with DCID=A → arrives at socket2 → demux HIT!
//
// This is the EXACT scenario that was failing in production.
func Test9_ProductionPath_MultiSocketDemuxHit(t *testing.T) {
	pool := NewUDPSocketPool(30*time.Second, 5*time.Minute, 10*time.Minute, nil)

	dest1 := &net.UDPAddr{IP: net.ParseIP("104.18.27.14"), Port: 443}
	dest2 := &net.UDPAddr{IP: net.ParseIP("104.18.26.14"), Port: 443}
	source := &net.UDPAddr{IP: net.ParseIP("82.43.215.97"), Port: 59807}

	// Phase 1: Initial → socket1
	conn1, err := pool.Acquire(dest1, source)
	if err != nil {
		t.Fatalf("Acquire1 failed: %v", err)
	}

	dcidB := []byte("serverB!")
	scidA := []byte("clientA!")
	initial := buildQUICInitial(t, dcidB, scidA)

	_, err = conn1.WriteTo(initial, dest1)
	if err != nil {
		t.Fatalf("WriteTo1 failed: %v", err)
	}
	t.Log("Phase 1: Initial sent to socket1 (IP1), SCID A cached")

	// Close conn1 (simulating freedom.Process return + pooledConn.Close)
	conn1.Close()
	t.Log("Phase 1: conn1 closed (freedom.Process returned)")

	// Verify A is cached
	pool.sourceSCIDCacheMu.RLock()
	cachedA, cached := pool.sourceSCIDCache[source.String()]
	pool.sourceSCIDCacheMu.RUnlock()
	if !cached {
		t.Fatal("Phase 1 FAIL: sourceSCIDCache not populated")
	}
	t.Logf("Phase 1: cached A = %x", cachedA)

	// Phase 2: Short header → socket2 (DIFFERENT IP!)
	conn2, err := pool.Acquire(dest2, source) // SAME source, DIFFERENT dest
	if err != nil {
		t.Fatalf("Acquire2 failed: %v", err)
	}
	defer conn2.Close()

	// Verify conn2 is on a DIFFERENT socket than conn1
	if conn2.socket == conn1.socket {
		t.Fatal("conn2 should be on a different socket than conn1 (different dest IP)")
	}
	t.Log("Phase 2: conn2 acquired on socket2 (IP2) — DIFFERENT socket ✓")

	// Short header with DCID = B' (server's SCID)
	scidBprime := []byte("srvB2000")
	shortHeader := buildQUICShortHeader(t, scidBprime)

	_, err = conn2.WriteTo(shortHeader, dest2)
	if err != nil {
		t.Fatalf("WriteTo2 failed: %v", err)
	}
	t.Log("Phase 2: Short header sent to socket2")

	// Verify A is now registered on socket2's demux (the fix!)
	replyDCIDKey := makeDCIDKey(scidA)
	conn2.socket.mu.RLock()
	targetInbox, demuxHit := conn2.socket.demux[replyDCIDKey]
	conn2.socket.mu.RUnlock()

	if !demuxHit {
		t.Fatal("Phase 2 FAIL: socket2.demux does NOT have A — demux miss would occur!")
	}
	if targetInbox != conn2.inbox {
		t.Fatal("Phase 2 FAIL: demux[A] doesn't point to conn2.inbox (live)")
	}
	t.Log("Phase 2: socket2.demux[A] = conn2.inbox (LIVE) — demux HIT would occur!")

	// Phase 3: Simulate server reply with DCID=A arriving at socket2
	replyPacket := buildQUICShortHeader(t, scidA)

	// Send to the target inbox (simulating readLoop)
	go func() {
		defer func() { recover() }()
		targetInbox <- readResult{data: replyPacket, n: len(replyPacket), addr: dest2}
	}()

	// Verify the reply is received
	select {
	case rr := <-conn2.inbox:
		if rr.n != len(replyPacket) {
			t.Fatalf("Phase 3: received n=%d, want %d", rr.n, len(replyPacket))
		}
		t.Log("Phase 3: Server reply DELIVERED to conn2.inbox → browser gets it → h3 works!")
	case <-time.After(2 * time.Second):
		t.Fatal("Phase 3: TIMEOUT — no reply received (demux miss in production)")
	}
}

// Test10_ProductionPath_NoSourceNoCache verifies that when source is
// nil (e.g., if the inbound context doesn't have a source), the cache
// is not populated and we fall back to the old behavior. This ensures
// the fix doesn't break when source is unavailable.
func Test10_ProductionPath_NoSourceNoCache(t *testing.T) {
	pool := NewUDPSocketPool(30*time.Second, 5*time.Minute, 10*time.Minute, nil)
	dest := &net.UDPAddr{IP: net.ParseIP("104.18.27.14"), Port: 443}

	// Acquire with nil source (simulating missing inbound context)
	conn, err := pool.Acquire(dest, nil)
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}
	defer conn.Close()

	dcidB := []byte("serverB!")
	scidA := []byte("clientA!")
	initial := buildQUICInitial(t, dcidB, scidA)

	_, err = conn.WriteTo(initial, dest)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}

	// Verify the cache is empty (source was nil)
	pool.sourceSCIDCacheMu.RLock()
	cacheLen := len(pool.sourceSCIDCache)
	pool.sourceSCIDCacheMu.RUnlock()

	if cacheLen != 0 {
		t.Fatalf("sourceSCIDCache should be empty (source=nil), has %d entries", cacheLen)
	}
	t.Log("PASS: sourceSCIDCache is empty when source=nil — graceful fallback")
}

// Test11_ProductionPath_SameSocketReuse verifies that when the same
// dest IP is used, the pool reuses the same socket (refCount works).
func Test11_ProductionPath_SameSocketReuse(t *testing.T) {
	pool := NewUDPSocketPool(30*time.Second, 5*time.Minute, 10*time.Minute, nil)
	dest := &net.UDPAddr{IP: net.ParseIP("104.18.27.14"), Port: 443}
	source := &net.UDPAddr{IP: net.ParseIP("82.43.215.97"), Port: 59807}

	conn1, err := pool.Acquire(dest, source)
	if err != nil {
		t.Fatalf("Acquire1 failed: %v", err)
	}
	conn1.Close()

	conn2, err := pool.Acquire(dest, source)
	if err != nil {
		t.Fatalf("Acquire2 failed: %v", err)
	}
	defer conn2.Close()

	if conn1.socket != conn2.socket {
		t.Fatal("Same dest should reuse the same socket")
	}
	t.Log("PASS: Same dest IP → same socket reused (refCount works)")
}
