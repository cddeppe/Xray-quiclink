package quic

import (
    "bytes"
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
