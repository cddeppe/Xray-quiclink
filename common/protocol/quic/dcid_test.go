package quic

import (
    "bytes"
    "encoding/binary"
    "encoding/hex"
    "testing"
)

// Real QUIC v1 Initial packet from sniff_test.go.
// c9 = 1100 1001 (long header), 00000001 = v1, 08 = DCID len, 52e6d0c4f5f177b7 = DCID
func TestParseDCIDLongHeader(t *testing.T) {
    pkt, err := hex.DecodeString(
        "c9000000010852e6d0c4f5f177b700404600eae9a1449fd711efdca846f59b6c9975a2189c1430f740e0e0eb4d50be086b798a47e037ee6afe9785b45df6302cfb87d39b9c03d0712f11793adab33e74904249722c4a1544896cd650da62160bdb601194f82a98c06df2546b79b5bab9503eafdbfbcfd1128204",
    )
    if err != nil {
        t.Fatalf("hex decode failed: %v", err)
    }
    dcid, isLong, err := ParseDCID(pkt)
    if err != nil {
        t.Fatalf("ParseDCID error: %v", err)
    }
    if !isLong {
        t.Error("expected long header, got short")
    }
    expected, _ := hex.DecodeString("52e6d0c4f5f177b7")
    if !bytes.Equal(dcid, expected) {
        t.Errorf("DCID = %x, want %x", dcid, expected)
    }
}

// Synthetic short header: 0x40 = 0100 0000, then 8-byte DCID, then 1-byte PN.
func TestParseDCIDShortHeader(t *testing.T) {
    dcidBytes, _ := hex.DecodeString("1122334455667788")
    pkt := append([]byte{0x40}, dcidBytes...)
    pkt = append(pkt, 0x01)
    dcid, isLong, err := ParseDCID(pkt)
    if err != nil {
        t.Fatalf("ParseDCID error: %v", err)
    }
    if isLong {
        t.Error("expected short header, got long")
    }
    if !bytes.Equal(dcid, dcidBytes) {
        t.Errorf("DCID = %x, want %x", dcid, dcidBytes)
    }
}

func TestParseShortHeaderDCIDWithLen(t *testing.T) {
    dcidBytes, _ := hex.DecodeString("aabbccdd")
    pkt := append([]byte{0x40}, dcidBytes...)
    pkt = append(pkt, 0x01)
    dcid, isLong, err := ParseShortHeaderDCIDWithLen(pkt, 4)
    if err != nil {
        t.Fatalf("error: %v", err)
    }
    if isLong {
        t.Error("expected short header")
    }
    if !bytes.Equal(dcid, dcidBytes) {
        t.Errorf("DCID = %x, want %x", dcid, dcidBytes)
    }
}

func TestParseDCIDEdgeCases(t *testing.T) {
    // Empty packet.
    _, _, err := ParseDCID(nil)
    if err != ErrTooShort {
        t.Errorf("empty: got %v, want ErrTooShort", err)
    }
    // Non-QUIC byte.
    _, _, err = ParseDCID([]byte{0x00})
    if err != ErrNotQUIC {
        t.Errorf("non-QUIC: got %v, want ErrNotQUIC", err)
    }
    // Truncated long header.
    _, _, err = ParseDCID([]byte{0xc0, 0x00, 0x00})
    if err != ErrTooShort {
        t.Errorf("truncated long: got %v, want ErrTooShort", err)
    }
    // DCID length over MaxCIDLen.
    _, _, err = ParseDCID([]byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0x64})
    if err != ErrBadCILen {
        t.Errorf("invalid len: got %v, want ErrBadCILen", err)
    }
    // Long header claims 8-byte DCID but only has 3.
    _, _, err = ParseDCID([]byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x11, 0x22, 0x33})
    if err != ErrTooShort {
        t.Errorf("truncated DCID: got %v, want ErrTooShort", err)
    }
    // Short header truncated for default 8-byte DCID.
    _, _, err = ParseDCID([]byte{0x40, 0x11, 0x22})
    if err != ErrTooShort {
        t.Errorf("short truncated: got %v, want ErrTooShort", err)
    }
}

// TestParseDCIDVersionNegotiationRejected confirms that Version Negotiation
// packets (version = 0) are rejected up front. RFC 9000 §17.2.1 defines a
// different layout for these packets (DCID/SCID followed by a list of
// supported versions, not the rest of a long-header packet). Even if some
// future spec ever flips the 0x40 fixed bit on a VN packet, the parser
// must refuse to treat it as a regular long header.
func TestParseDCIDVersionNegotiationRejected(t *testing.T) {
    // Long header (bit 7 = 1), fixed bit set (bit 6 = 1), version = 0,
    // DCID len = 8, DCID = 8 bytes, SCID len = 0.
    pkt := make([]byte, 6+8+1)
    pkt[0] = 0xc0 | 0x40
    binary.BigEndian.PutUint32(pkt[1:5], 0)
    pkt[5] = 8
    copy(pkt[6:14], []byte("abcdefgh"))
    pkt[14] = 0
    _, isLong, err := ParseDCID(pkt)
    if err != ErrNotQUIC {
        t.Errorf("version negotiation: got err=%v isLong=%v, want ErrNotQUIC", err, isLong)
    }
}

// TestParseDCIDMultipleVersions confirms ParseDCID accepts QUIC v1, v2 and
// draft-29 long-header packets with identical DCID-extraction logic —
// documenting that the parser is intentionally version-agnostic.
func TestParseDCIDMultipleVersions(t *testing.T) {
    versions := []struct {
        name string
        ver  uint32
    }{
        {"v1", 0x00000001},
        {"v2", 0x6b3343cf},
        {"draft29", 0xff00001d},
    }

    dcid, _ := hex.DecodeString("1122334455667788")
    for _, tt := range versions {
        t.Run(tt.name, func(t *testing.T) {
            pkt := make([]byte, 6+len(dcid)+1)
            pkt[0] = 0xc0 | 0x40
            binary.BigEndian.PutUint32(pkt[1:5], tt.ver)
            pkt[5] = byte(len(dcid))
            copy(pkt[6:6+len(dcid)], dcid)
            pkt[6+len(dcid)] = 0 // SCID len
            got, isLong, err := ParseDCID(pkt)
            if err != nil {
                t.Fatalf("ParseDCID error: %v", err)
            }
            if !isLong {
                t.Error("expected long header, got short")
            }
            if !bytes.Equal(got, dcid) {
                t.Errorf("DCID = %x, want %x", got, dcid)
            }
        })
    }
}

// TestParseSCIDLongHeader builds a synthetic QUIC v1 long header with a
// known DCID and SCID, and verifies ParseSCID extracts the SCID.
func TestParseSCIDLongHeader(t *testing.T) {
    dcid, _ := hex.DecodeString("1122334455667788")
    scid, _ := hex.DecodeString("aabbccddeeff")
    pkt := make([]byte, 6+len(dcid)+1+len(scid)+4)
    pkt[0] = 0xc0 | 0x40 // long header + fixed bit
    binary.BigEndian.PutUint32(pkt[1:5], 0x00000001) // QUIC v1
    pkt[5] = byte(len(dcid))
    copy(pkt[6:6+len(dcid)], dcid)
    pkt[6+len(dcid)] = byte(len(scid))
    copy(pkt[7+len(dcid):7+len(dcid)+len(scid)], scid)

    got, isLong, err := ParseSCID(pkt)
    if err != nil {
        t.Fatalf("ParseSCID error: %v", err)
    }
    if !isLong {
        t.Error("expected long header, got short")
    }
    if !bytes.Equal(got, scid) {
        t.Errorf("SCID = %x, want %x", got, scid)
    }
}

// TestParseSCIDShortHeader confirms that short-header packets return no
// SCID (since QUIC short headers do not include a SCID).
func TestParseSCIDShortHeader(t *testing.T) {
    scidBytes, _ := hex.DecodeString("1122334455667788")
    pkt := append([]byte{0x40}, scidBytes...)
    pkt = append(pkt, 0x01)
    got, isLong, err := ParseSCID(pkt)
    if err != nil {
        t.Fatalf("ParseSCID error: %v", err)
    }
    if isLong {
        t.Error("expected short header, got long")
    }
    if got != nil {
        t.Errorf("SCID = %x, want nil (short headers have no SCID)", got)
    }
}

// TestParseSCIDEdgeCases covers the boundary conditions: empty packet,
// truncated long header, oversized DCID/SCID length fields.
func TestParseSCIDEdgeCases(t *testing.T) {
    // Empty packet.
    _, _, err := ParseSCID(nil)
    if err != ErrTooShort {
        t.Errorf("empty: got %v, want ErrTooShort", err)
    }

    // Truncated long header (need at least 6 bytes for the version + DCID len).
    _, _, err = ParseSCID([]byte{0xc0 | 0x40, 0x00, 0x00, 0x00, 0x01})
    if err != ErrTooShort {
        t.Errorf("truncated long: got %v, want ErrTooShort", err)
    }

    // Long header with DCID length > MaxCIDLen.
    bad := []byte{0xc0 | 0x40, 0x00, 0x00, 0x00, 0x01, 0x64}
    _, _, err = ParseSCID(bad)
    if err != ErrBadCILen {
        t.Errorf("bad dcid len: got %v, want ErrBadCILen", err)
    }

    // Long header with valid DCID but truncated SCID length byte.
    dcid, _ := hex.DecodeString("1122334455667788")
    truncated := []byte{0xc0 | 0x40, 0x00, 0x00, 0x00, 0x01, byte(len(dcid))}
    truncated = append(truncated, dcid...)
    // SCID len byte is missing — only have the DCID.
    _, _, err = ParseSCID(truncated)
    if err != ErrTooShort {
        t.Errorf("missing scid len: got %v, want ErrTooShort", err)
    }

    // Long header with SCID length > MaxCIDLen.
    badSCID := append(truncated, 0x64) // claim SCID len = 100
    _, _, err = ParseSCID(badSCID)
    if err != ErrBadCILen {
        t.Errorf("bad scid len: got %v, want ErrBadCILen", err)
    }

    // Non-QUIC byte (no header-form bit, no fixed bit).
    _, _, err = ParseSCID([]byte{0x00})
    if err != ErrNotQUIC {
        t.Errorf("non-QUIC: got %v, want ErrNotQUIC", err)
    }
}

// TestParseSCIDVersionNegotiationRejected confirms that ParseSCID (like
// ParseDCID) refuses Version Negotiation packets.
func TestParseSCIDVersionNegotiationRejected(t *testing.T) {
    pkt := make([]byte, 6+8+1)
    pkt[0] = 0xc0 | 0x40
    binary.BigEndian.PutUint32(pkt[1:5], 0)
    pkt[5] = 8
    copy(pkt[6:14], []byte("abcdefgh"))
    pkt[14] = 0
    _, isLong, err := ParseSCID(pkt)
    if err != ErrNotQUIC {
        t.Errorf("version negotiation: got err=%v isLong=%v, want ErrNotQUIC", err, isLong)
    }
}
