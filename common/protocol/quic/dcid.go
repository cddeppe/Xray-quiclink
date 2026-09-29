package quic

import "errors"

// Errors returned by DCID parsing functions.
var (
    ErrNotQUIC  = errors.New("not a QUIC packet")
    ErrTooShort = errors.New("packet too short to parse QUIC header")
    ErrBadCILen = errors.New("invalid connection ID length")
)

// MaxCIDLen is the maximum connection ID length per RFC 9000 §17.2.
const MaxCIDLen = 20

// ParseDCID extracts the Destination Connection ID from a QUIC packet.
// Returns (dcid, isLongHeader, err).
//
// For long headers (Initial, 0-RTT, Handshake, Retry) the DCID length is
// encoded in the packet. For short headers (1-RTT) the length is not
// encoded — this function defaults to 8 bytes (Chrome/Firefox/Safari default).
// Use ParseShortHeaderDCIDWithLen to override for known connections.
//
// Reference: RFC 9000 §17.2 (long header), §17.3 (short header).
func ParseDCID(packet []byte) ([]byte, bool, error) {
    if len(packet) < 1 {
        return nil, false, ErrTooShort
    }
    firstByte := packet[0]

    // Long header: bit 7 = 1, bit 6 = 1 (fixed bit in QUIC v1/v2).
    if firstByte&0x80 != 0 {
        if firstByte&0x40 == 0 {
            return nil, true, ErrNotQUIC
        }
        return parseLongHeaderDCID(packet)
    }

    // Short header: bit 7 = 0, bit 6 = 1 (fixed bit).
    if firstByte&0x40 != 0 {
        return parseShortHeaderDCID(packet, 8)
    }

    return nil, false, ErrNotQUIC
}

// ParseShortHeaderDCIDWithLen extracts DCID from a short header (1-RTT)
// packet using a known CID length. CID length is negotiated during the
// QUIC handshake via transport parameters and is constant for a connection.
func ParseShortHeaderDCIDWithLen(packet []byte, cidLen int) ([]byte, bool, error) {
    if len(packet) < 1 {
        return nil, false, ErrTooShort
    }
    firstByte := packet[0]
    if firstByte&0xc0 != 0x40 {
        return nil, false, ErrNotQUIC
    }
    return parseShortHeaderDCID(packet, cidLen)
}

// parseLongHeaderDCID extracts DCID from a long header QUIC packet.
// Layout: byte 0 = type, bytes 1-4 = version, byte 5 = DCID len, byte 6+ = DCID.
func parseLongHeaderDCID(packet []byte) ([]byte, bool, error) {
    if len(packet) < 6 {
        return nil, true, ErrTooShort
    }
    dcidLen := int(packet[5])
    if dcidLen > MaxCIDLen {
        return nil, true, ErrBadCILen
    }
    end := 6 + dcidLen
    if len(packet) < end {
        return nil, true, ErrTooShort
    }
    dcid := make([]byte, dcidLen)
    copy(dcid, packet[6:end])
    return dcid, true, nil
}

// parseShortHeaderDCID extracts DCID from a short header QUIC packet using
// a known CID length. Layout: byte 0 = type, bytes 1..1+L = DCID (no length prefix).
func parseShortHeaderDCID(packet []byte, cidLen int) ([]byte, bool, error) {
    if cidLen < 0 || cidLen > MaxCIDLen {
        return nil, false, ErrBadCILen
    }
    if len(packet) < 1+cidLen {
        return nil, false, ErrTooShort
    }
    dcid := make([]byte, cidLen)
    copy(dcid, packet[1:1+cidLen])
    return dcid, false, nil
}
