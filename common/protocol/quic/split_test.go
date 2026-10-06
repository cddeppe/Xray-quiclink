// Package quic: split_test.go
//
// v26.11.28-link: tests for SplitCoalesced — parses coalesced QUIC
// datagrams (multiple QUIC packets in one UDP datagram per RFC 9000 §12.2)
// and returns byte offsets for each individual packet.

package quic

import (
        "encoding/binary"
        "testing"
)

// makeLongHeaderPacket constructs a long-header QUIC packet with the
// given type, DCID, SCID, optional token, and payload. The packet's
// Length field is set to cover Packet Number (1 byte) + payload.
//
// pktType: 0=Initial, 1=0-RTT, 2=Handshake, 3=Retry
// (Retry handled separately — no Length field)
func makeLongHeaderPacket(pktType byte, version uint32, dcid, scid, token, payload []byte) []byte {
        // First byte: header form (1) | fixed (1) | type (2) | reserved (2) | pn_len (2)
        // pn_len = 0 → 1-byte packet number
        firstByte := byte(0xC0) | ((pktType & 0x03) << 4) | 0x00

        var pkt []byte
        pkt = append(pkt, firstByte)

        // Version (4 bytes)
        var ver [4]byte
        binary.BigEndian.PutUint32(ver[:], version)
        pkt = append(pkt, ver[:]...)

        // DCID length + DCID
        pkt = append(pkt, byte(len(dcid)))
        pkt = append(pkt, dcid...)

        // SCID length + SCID
        pkt = append(pkt, byte(len(scid)))
        pkt = append(pkt, scid...)

        // Initial: Token Length (varint) + Token
        if pktType == 0 {
                pkt = appendVarint(pkt, uint64(len(token)))
                pkt = append(pkt, token...)
        }

        // Length (varint) — covers Packet Number (1 byte) + payload
        lengthVal := uint64(1 + len(payload))
        pkt = appendVarint(pkt, lengthVal)

        // Packet Number (1 byte, value 0)
        pkt = append(pkt, 0x00)

        // Payload
        pkt = append(pkt, payload...)

        return pkt
}

// appendVarint writes a QUIC varint (RFC 9000 §16).
// Prefix encodes the length: 00=1B, 01=2B, 10=4B, 11=8B.
func appendVarint(buf []byte, v uint64) []byte {
        switch {
        case v < 64:
                return append(buf, byte(v)) // 00xx xxxx
        case v < 16384:
                return append(buf, byte(0x40|(v>>8)), byte(v&0xFF)) // 01xx xxxx + 8 bits
        case v < 1073741824:
                var b [4]byte
                // 10xx xxxx in the top byte, then 24 bits of value
                binary.BigEndian.PutUint32(b[:], uint32(0x80000000|v))
                return append(buf, b[:]...)
        default:
                var b [8]byte
                // 11xx xxxx in the top byte, then 56 bits of value
                binary.BigEndian.PutUint64(b[:], 0xC000000000000000|v)
                return append(buf, b[:]...)
        }
}

func TestSplitCoalesced_SinglePacket(t *testing.T) {
        // A single Initial packet — no coalescing.
        pkt := makeLongHeaderPacket(0, 0x00000001, []byte("dcid-1234-5678"), []byte("scid"), nil, []byte("payload"))
        offsets, err := SplitCoalesced(pkt)
        if err != nil {
                t.Fatalf("SplitCoalesced failed: %v", err)
        }
        if len(offsets) != 1 {
                t.Fatalf("expected 1 offset pair, got %d: %v", len(offsets), offsets)
        }
        if offsets[0][0] != 0 || offsets[0][1] != len(pkt) {
                t.Fatalf("offset = [%d, %d), expected [0, %d)", offsets[0][0], offsets[0][1], len(pkt))
        }
}

func TestSplitCoalesced_InitialHandshake(t *testing.T) {
        // Coalesced: Initial (no token) + Handshake, like what nginx sends.
        initial := makeLongHeaderPacket(0, 0x00000001, []byte("dcid-1234-5678"), []byte("scid"), nil, make([]byte, 1100))
        handshake := makeLongHeaderPacket(2, 0x00000001, []byte("dcid-1234-5678"), []byte("scid"), nil, []byte("handshake-payload"))
        coalesced := append(initial, handshake...)

        offsets, err := SplitCoalesced(coalesced)
        if err != nil {
                t.Fatalf("SplitCoalesced failed: %v", err)
        }
        if len(offsets) != 2 {
                t.Fatalf("expected 2 offset pairs, got %d: %v", len(offsets), offsets)
        }
        if offsets[0][0] != 0 || offsets[0][1] != len(initial) {
                t.Fatalf("initial offset = [%d, %d), expected [0, %d)", offsets[0][0], offsets[0][1], len(initial))
        }
        if offsets[1][0] != len(initial) || offsets[1][1] != len(coalesced) {
                t.Fatalf("handshake offset = [%d, %d), expected [%d, %d)",
                        offsets[1][0], offsets[1][1], len(initial), len(coalesced))
        }
        // Verify the bytes match
        if got, want := coalesced[offsets[0][0]:offsets[0][1]], initial; !bytesEqual(got, want) {
                t.Fatalf("initial bytes mismatch")
        }
        if got, want := coalesced[offsets[1][0]:offsets[1][1]], handshake; !bytesEqual(got, want) {
                t.Fatalf("handshake bytes mismatch")
        }
}

func TestSplitCoalesced_InitialWithToken(t *testing.T) {
        // Initial with a non-empty token (server response after Retry).
        token := []byte("retry-token-data-here")
        initial := makeLongHeaderPacket(0, 0x00000001, []byte("dcid"), []byte("scid"), token, make([]byte, 1000))
        offsets, err := SplitCoalesced(initial)
        if err != nil {
                t.Fatalf("SplitCoalesced failed: %v", err)
        }
        if len(offsets) != 1 {
                t.Fatalf("expected 1 offset pair, got %d", len(offsets))
        }
        if offsets[0][0] != 0 || offsets[0][1] != len(initial) {
                t.Fatalf("offset = [%d, %d), expected [0, %d)", offsets[0][0], offsets[0][1], len(initial))
        }
}

func TestSplitCoalesced_InitialHandshake1RTT(t *testing.T) {
        // Three coalesced packets: Initial + Handshake + 1-RTT (short header).
        // Short header has no length — extends to end of datagram.
        initial := makeLongHeaderPacket(0, 0x00000001, []byte("dcid-1234-5678-9"), []byte("scid"), nil, make([]byte, 1100))
        handshake := makeLongHeaderPacket(2, 0x00000001, []byte("dcid-1234-5678-9"), []byte("scid"), nil, []byte("hs-payload"))

        // Short header (1-RTT): byte 0 = 0x40 (header form 0, fixed bit 1)
        // + DCID (no length prefix). Use 8-byte DCID (Chrome default).
        shortHdr := []byte{0x40}
        shortHdr = append(shortHdr, []byte("dcid-1234-5678-9")...) // 16-byte DCID, but spec says ≤20
        // Reset to 8-byte DCID per spec convention
        shortHdr = []byte{0x40}
        shortHdr = append(shortHdr, []byte("12345678")...)        // 8-byte DCID
        shortHdr = append(shortHdr, []byte("pn-and-payload")...)

        coalesced := append(initial, handshake...)
        coalesced = append(coalesced, shortHdr...)

        offsets, err := SplitCoalesced(coalesced)
        if err != nil {
                t.Fatalf("SplitCoalesced failed: %v", err)
        }
        if len(offsets) != 3 {
                t.Fatalf("expected 3 offset pairs, got %d: %v", len(offsets), offsets)
        }
        if offsets[2][1] != len(coalesced) {
                t.Fatalf("short header should extend to end: got end=%d, want %d", offsets[2][1], len(coalesced))
        }
}

func TestSplitCoalesced_NotQUIC(t *testing.T) {
        // Random bytes that don't have the Fixed Bit set.
        buf := []byte{0x00, 0x01, 0x02, 0x03}
        if _, err := SplitCoalesced(buf); err == nil {
                t.Fatalf("expected error for non-QUIC packet, got nil")
        }
}

func TestSplitCoalesced_TooShort(t *testing.T) {
        buf := []byte{0xC0}
        if _, err := SplitCoalesced(buf); err == nil {
                t.Fatalf("expected error for too-short packet, got nil")
        }
}

func TestSplitCoalesced_VersionNegotiation(t *testing.T) {
        // Version Negotiation: version = 0, fixed bit = 0 (per spec).
        // Should be treated as a single packet (not coalesced).
        vn := []byte{0x80, 0, 0, 0, 0}
        vn = append(vn, byte(8))  // DCID len
        vn = append(vn, []byte("12345678")...)
        vn = append(vn, byte(0))  // SCID len = 0
        vn = append(vn, []byte{0, 0, 0, 1}...) // supported version 1
        vn = append(vn, []byte{0, 0, 0, 0x6b, 0x33, 0x43, 0xcf}...) // QUIC v2

        offsets, err := SplitCoalesced(vn)
        if err != nil {
                t.Fatalf("SplitCoalesced failed: %v", err)
        }
        if len(offsets) != 1 {
                t.Fatalf("expected 1 offset pair (VN is not coalesced), got %d", len(offsets))
        }
        if offsets[0][0] != 0 || offsets[0][1] != len(vn) {
                t.Fatalf("VN offset = [%d, %d), expected [0, %d)", offsets[0][0], offsets[0][1], len(vn))
        }
}

func TestSplitCoalesced_RetryPacket(t *testing.T) {
        // Retry packet: type = 3, no Length field, ends with 16-byte Retry Integrity Tag.
        // §17.2.5: "A Retry packet MUST NOT be coalesced with any other packet."
        retry := []byte{0xF0} // header form 1, fixed 1, type 11 (Retry), reserved 0, pn_len 0
        retry = append(retry, 0, 0, 0, 1) // version 1
        retry = append(retry, byte(8))    // DCID len
        retry = append(retry, []byte("12345678")...)
        retry = append(retry, byte(0))    // SCID len = 0
        retry = append(retry, []byte("retry-payload-bytes")...)
        retry = append(retry, make([]byte, 16)...) // 16-byte Retry Integrity Tag

        offsets, err := SplitCoalesced(retry)
        if err != nil {
                t.Fatalf("SplitCoalesced failed: %v", err)
        }
        if len(offsets) != 1 {
                t.Fatalf("expected 1 offset pair (Retry not coalesced), got %d", len(offsets))
        }
        if offsets[0][0] != 0 || offsets[0][1] != len(retry) {
                t.Fatalf("Retry offset = [%d, %d), expected [0, %d)", offsets[0][0], offsets[0][1], len(retry))
        }
}

func TestSplitCoalesced_2ByteVarint(t *testing.T) {
        // Initial with payload large enough to require a 2-byte Length varint.
        // 2-byte varint covers up to 16383. Use payload ~1500 bytes.
        initial := makeLongHeaderPacket(0, 0x00000001, []byte("dcid"), []byte("scid"), nil, make([]byte, 1500))
        if initial[0]&0x80 == 0 {
                t.Fatalf("expected long header")
        }
        offsets, err := SplitCoalesced(initial)
        if err != nil {
                t.Fatalf("SplitCoalesced failed: %v", err)
        }
        if len(offsets) != 1 {
                t.Fatalf("expected 1 offset, got %d", len(offsets))
        }
        if offsets[0][1] != len(initial) {
                t.Fatalf("offset end = %d, want %d", offsets[0][1], len(initial))
        }
}

func TestSplitCoalesced_4ByteVarint(t *testing.T) {
        // Initial with payload large enough to require a 4-byte Length varint.
        // 4-byte varint covers up to 1073741823. Use payload ~70000 bytes.
        // This simulates the Handshake containing a server certificate chain.
        initial := makeLongHeaderPacket(0, 0x00000001, []byte("dcid"), []byte("scid"), nil, make([]byte, 70000))
        offsets, err := SplitCoalesced(initial)
        if err != nil {
                t.Fatalf("SplitCoalesced failed: %v", err)
        }
        if len(offsets) != 1 {
                t.Fatalf("expected 1 offset, got %d", len(offsets))
        }
        if offsets[0][1] != len(initial) {
                t.Fatalf("offset end = %d, want %d", offsets[0][1], len(initial))
        }
}

func TestReadQUICVarint(t *testing.T) {
        tests := []struct {
                name string
                buf  []byte
                want uint64
                n    int
        }{
                {"1-byte max", []byte{0x3F}, 63, 1},
                {"2-byte min", []byte{0x40, 0x00}, 0, 2},
                {"2-byte mid", []byte{0x44, 0x00}, 0x0400, 2},
                {"2-byte max", []byte{0x7F, 0xFF}, 16383, 2},
                {"4-byte min", []byte{0x80, 0, 0, 0}, 0, 4},
                {"4-byte max", []byte{0xBF, 0xFF, 0xFF, 0xFF}, 1073741823, 4},
                {"8-byte min", []byte{0xC0, 0, 0, 0, 0, 0, 0, 0}, 0, 8},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got, n, err := readQUICVarint(tt.buf)
                        if err != nil {
                                t.Fatalf("readQUICVarint failed: %v", err)
                        }
                        if got != tt.want {
                                t.Errorf("value = %d, want %d", got, tt.want)
                        }
                        if n != tt.n {
                                t.Errorf("consumed = %d, want %d", n, tt.n)
                        }
                })
        }
}

// bytesEqual is a simple slice compare (avoid pulling in bytes package
// for a tiny test helper).
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
