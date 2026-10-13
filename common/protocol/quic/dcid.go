package quic

import (
        "encoding/binary"
        "errors"
)

// Errors returned by DCID parsing functions.
var (
        ErrNotQUIC  = errors.New("not a QUIC packet")
        ErrTooShort = errors.New("packet too short to parse QUIC header")
        ErrBadCILen = errors.New("invalid connection ID length")
)

// MaxCIDLen is the maximum connection ID length per RFC 9000 §17.2.
const MaxCIDLen = 20

// DefaultShortHeaderCIDLen is the assumed DCID length for short-header
// (1-RTT) packets. The length is negotiated during the QUIC handshake
// via transport parameters and is constant for a connection. All major
// QUIC implementations (Chrome, Firefox, Safari) use 8. If you're using
// a server with a non-standard CID length, you can override this.
// v26.10.43-link (audit H5 from 2-b): was hardcoded to 8.
var DefaultShortHeaderCIDLen = 8

// VersionNegotiation is the reserved version value (0) used by QUIC Version
// Negotiation packets (RFC 9000 §17.2.1). Those packets have a different
// header layout (the DCID/SCID are followed by a list of supported versions
// rather than the rest of a long-header packet) so the long-header parser
// must reject them up front.
const VersionNegotiation uint32 = 0

// ParseDCID extracts the Destination Connection ID from a QUIC packet.
// Returns (dcid, isLongHeader, err).
//
// For long headers (Initial, 0-RTT, Handshake, Retry) the DCID length is
// encoded in the packet. For short headers (1-RTT) the length is not
// encoded — this function defaults to 8 bytes (Chrome/Firefox/Safari default).
// Use ParseShortHeaderDCIDWithLen to override for known connections.
//
// Long-header parsing is intentionally version-agnostic: the DCID/SCID
// layout is identical for QUIC v1 (0x00000001), v2 (0x6b3343cf) and
// draft-29 (0xff00001d). Only Version Negotiation packets (version = 0)
// have a different layout and are rejected explicitly here. Future QUIC
// versions that keep the long-header form defined in RFC 9000 §17.2 will
// keep working without code changes.
//
// Reference: RFC 9000 §17.2 (long header), §17.3 (short header).
func ParseDCID(packet []byte) ([]byte, bool, error) {
        if len(packet) < 1 {
                return nil, false, ErrTooShort
        }
        firstByte := packet[0]

        // Long header: bit 7 = 1.
        // v26.11.214: Accept QUIC v2 (bit 6=0) as well as v1 (bit 6=1).
        if firstByte&0x80 != 0 {
                // Version Negotiation packets have version = 0 and may have bit 6 = 0.
                // Check for VN explicitly and reject.
                if len(packet) >= 5 && binary.BigEndian.Uint32(packet[1:5]) == VersionNegotiation {
                        return nil, true, ErrNotQUIC
                }
                return parseLongHeaderDCID(packet)
        }

        // Short header: bit 7 = 0.
        // v26.11.214: QUIC v1 short header has bit 6 = 1 (0x40).
        // QUIC v2 short header has bit 6 = 0 (0x00). Accept both.
        if firstByte&0x40 != 0 || firstByte&0x80 == 0 {
                // v26.10.43-link (audit H5 from 2-b): use configurable
                // default CID length. All major QUIC implementations
                // (Chrome, Firefox, Safari) use 8, but some load
                // balancers and custom servers use other lengths.
                return parseShortHeaderDCID(packet, DefaultShortHeaderCIDLen)
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
        // v26.11.214: Accept both QUIC v1 (0x40) and v2 (0x00) short headers.
        // Both have bit 7 = 0. Just check bit 7 = 0.
        firstByte := packet[0]
        if firstByte&0x80 != 0 {
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

// ParseSCID extracts the Source Connection ID from a QUIC packet.
// Returns (scid, isLongHeader, err).
//
// For long headers (Initial, 0-RTT, Handshake, Retry) the SCID length is
// encoded in the packet after the DCID. For short headers (1-RTT) the SCID
// is not present and the function returns (nil, false, nil).
//
// Note: long header format (version-independent for QUIC v1, v2 and
// draft-29): byte 0 = type, bytes 1-4 = version, byte 5 = DCID len,
// bytes 6..6+dcidLen = DCID, byte 6+dcidLen = SCID len,
// bytes 7+dcidLen..7+dcidLen+scidLen = SCID. See RFC 9000 §17.2.
// Version Negotiation packets (version = 0) have a different layout and
// are rejected explicitly.
//
// Reference: RFC 9000 §17.2 (long header), §17.3 (short header).
func ParseSCID(packet []byte) ([]byte, bool, error) {
        if len(packet) < 1 {
                return nil, false, ErrTooShort
        }
        firstByte := packet[0]

        // Long header: bit 7 = 1.
        // v26.11.214: Accept QUIC v2 (bit 6=0) as well as v1 (bit 6=1).
        if firstByte&0x80 != 0 {
                if len(packet) >= 5 && binary.BigEndian.Uint32(packet[1:5]) == VersionNegotiation {
                        return nil, true, ErrNotQUIC
                }
                return parseLongHeaderSCID(packet)
        }

        // Short header: bit 7 = 0, bit 6 = 1 (fixed bit); no SCID present.
        if firstByte&0x40 != 0 {
                return nil, false, nil
        }

        return nil, false, ErrNotQUIC
}

// parseLongHeaderSCID extracts SCID from a long header QUIC packet.
// Assumes the caller has already validated the long-header form bit.
func parseLongHeaderSCID(packet []byte) ([]byte, bool, error) {
        if len(packet) < 6 {
                return nil, true, ErrTooShort
        }
        dcidLen := int(packet[5])
        if dcidLen > MaxCIDLen {
                return nil, true, ErrBadCILen
        }
        scidLenOffset := 6 + dcidLen
        if len(packet) < scidLenOffset+1 {
                return nil, true, ErrTooShort
        }
        scidLen := int(packet[scidLenOffset])
        if scidLen > MaxCIDLen {
                return nil, true, ErrBadCILen
        }
        scidEnd := scidLenOffset + 1 + scidLen
        if len(packet) < scidEnd {
                return nil, true, ErrTooShort
        }
        scid := make([]byte, scidLen)
        copy(scid, packet[scidLenOffset+1:scidEnd])
        return scid, true, nil
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
