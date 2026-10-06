// Package quic: split.go
//
// v26.11.28-link: SplitCoalesced parses a coalesced QUIC datagram (multiple
// QUIC packets concatenated in a single UDP datagram, RFC 9000 §12.2) and
// returns the byte offsets of each individual QUIC packet so the caller
// can send each one as a separate UDP datagram.
//
// WHY THIS EXISTS
//
// QUIC servers (nginx, Cloudflare, Google, etc.) coalesce Initial +
// Handshake + 0-RTT packets into a single UDP datagram up to 65535 bytes
// via GSO. When a transparent proxy forwards this to a browser:
//
//   - Path MTU is typically 1500 (or less for PPPoE / tunnels / IPv6).
//   - IP fragmentation of a 2400-byte datagram produces 2 IP fragments.
//   - Many firewalls, NATs, and the browser's own IP fragment reassembly
//     drop or misorder these fragments, causing the QUIC handshake to
//     fail. The browser falls back to HTTP/2 over TCP.
//
// ICMP "Fragmentation Needed" (Type 3 Code 4) is sent by us to tell the
// server to send smaller packets, but the server's QUIC stack typically
// ignores it for the first handshake and continues sending coalesced
// datagrams because the Initial MUST be coalesced with Handshake per
// RFC 9000 §17.2.2.1 (anti-amplification limit).
//
// THE FIX
//
// RFC 9000 §12.2 says receivers MUST be able to receive coalesced AND
// non-coalesced packets. So the proxy can split the coalesced datagram
// into individual UDP datagrams on the outbound path to the browser.
// Each individual QUIC packet (Initial ~1250, Handshake ~200, 1-RTT
// ~1250) fits within a single IP packet — no IP fragmentation needed.
//
// The browser receives each one as a separate UDP datagram, processes
// them in order, and the QUIC handshake succeeds.
//
// LONG HEADER PARSING
//
// RFC 9000 §17.2 long header layout (version-independent for QUIC v1,
// v2, and draft-29):
//
//   Byte 0:    Header Form (1) | Fixed Bit (1) | Long Packet Type (2)
//              | Reserved (2) | Packet Number Length (2)
//   Bytes 1-4: Version (32)
//   Byte 5:    DCID Length (8)
//   Bytes 6..: DCID (0..160)
//   Next byte: SCID Length (8)
//   Next:      SCID (0..160)
//   Initial only: Token Length (varint) + Token (..)
//   Length (varint) — covers Packet Number + Payload
//   Packet Number (8..32)
//   Payload (..)
//
// SHORT HEADER PARSING
//
// RFC 9000 §17.3 short header (1-RTT) layout:
//
//   Byte 0: Header Form (0) | Fixed Bit (1) | Spin Bit (1) | Reserved (2)
//          | Key Phase (1) | Packet Number Length (2)
//   Bytes 1..1+L: DCID (length negotiated during handshake, no length prefix)
//   Bytes ...:    Packet Number (1..4) + Payload (.., to end of UDP datagram)
//
// Short headers have NO Length field. They extend to the end of the UDP
// datagram. Therefore, a short header is always the LAST packet in a
// coalesced datagram.
//
// RETRY PACKETS
//
// RFC 9000 §17.2.4: Retry packets have no Length field, no Packet Number,
// no Payload — they end with a 16-byte Retry Integrity Tag. Retry packets
// "MUST NOT be coalesced with any other packet" (§17.2.4) so we treat the
// whole remaining buffer as the Retry packet.
//
// VERSION NEGOTIATION
//
// RFC 9000 §17.2.1: Version Negotiation packets have version = 0 and a
// different layout (no Length, no SCID Length bytes — wait, they DO have
// SCID Length, but the body is a list of 4-byte versions instead of a
// standard long-header payload). Version Negotiation also MUST NOT be
// coalesced. We reject it from this parser and the caller can send it
// directly without splitting.

package quic

import (
        "encoding/binary"
        "errors"
)

// Errors returned by SplitCoalesced.
var (
        ErrSplitNotQUIC    = errors.New("not a QUIC packet (header form bits invalid)")
        ErrSplitTooShort   = errors.New("packet too short to parse")
        ErrSplitBadCILen   = errors.New("invalid connection ID length")
        ErrSplitBadVarint  = errors.New("invalid QUIC varint")
        ErrSplitBadPktType = errors.New("invalid QUIC long packet type")
)

// PacketTypeLongInitial  = 0b00 (RFC 9000 §17.2.2)
// PacketTypeLong0RTT     = 0b01 (RFC 9000 §17.2.3)
// PacketTypeLongHandshake = 0b10 (RFC 9000 §17.2.4)
// PacketTypeLongRetry    = 0b11 (RFC 9000 §17.2.5)
const (
        pktTypeLongInitial   = 0x00
        pktTypeLongHandshake = 0x02
        pktTypeLongRetry     = 0x03
)

// SplitCoalesced parses a coalesced QUIC datagram and returns the byte
// offsets [start, end) of each individual QUIC packet.
//
// If the buffer is a single QUIC packet (not coalesced) or the buffer
// can't be parsed as QUIC (returns an error), the caller should send
// the whole buffer as one UDP datagram (fallback path).
//
// The returned offsets are valid into the original buf; the caller
// should send buf[off[0]:off[1]] as one UDP datagram per offset pair.
//
// Reference: RFC 9000 §17.2 (long header), §17.3 (short header),
// §12.2 (coalescing), §16 (varint).
func SplitCoalesced(buf []byte) ([][2]int, error) {
        if len(buf) < 1 {
                return nil, ErrSplitTooShort
        }

        // Quick check: is the first byte even QUIC? Reject only if BOTH
        // the header-form bit (0x80) AND the fixed bit (0x40) are zero.
        //
        // - Long header: bit 7 = 1 (bit 6 may be 0 for Version Negotiation,
        //   which is permitted to have Fixed Bit = 0 per RFC 9000 §17.2.1).
        // - Short header: bit 7 = 0, bit 6 = 1.
        // - VN: bit 7 = 1, bit 6 = 0 → still a QUIC packet, must not reject.
        // - Random non-QUIC (e.g. all-zero byte): bit 7 = 0, bit 6 = 0 → reject.
        if buf[0]&0xC0 == 0x00 {
                return nil, ErrSplitNotQUIC
        }

        var offsets [][2]int
        offset := 0

        for offset < len(buf) {
                packetStart := offset
                firstByte := buf[offset]

                // Short header: bit 7 = 0, bit 6 = 1. Short headers have no
                // Length field — they extend to the end of the UDP datagram.
                // This is always the LAST packet in a coalesced datagram.
                if firstByte&0x80 == 0 {
                        if firstByte&0x40 == 0 {
                                return nil, ErrSplitNotQUIC
                        }
                        offsets = append(offsets, [2]int{packetStart, len(buf)})
                        return offsets, nil
                }

                // Long header: bit 7 = 1, bit 6 = 1 (fixed bit, except VN).
                if firstByte&0x40 == 0 {
                        // Fixed Bit = 0 with Header Form = 1 means Version
                        // Negotiation. VN has a different layout (no Length
                        // field, body is a list of 4-byte versions). VN MUST
                        // NOT be coalesced (§17.2.1). Treat as last packet.
                        offsets = append(offsets, [2]int{packetStart, len(buf)})
                        return offsets, nil
                }

                // Defensive: refuse to parse if version = 0 (Version Negotiation).
                if offset+5 > len(buf) {
                        return nil, ErrSplitTooShort
                }
                version := binary.BigEndian.Uint32(buf[offset+1 : offset+5])
                if version == VersionNegotiation {
                        offsets = append(offsets, [2]int{packetStart, len(buf)})
                        return offsets, nil
                }

                // Need at least 6 bytes (1 + 4 version + 1 DCID length byte).
                if offset+6 > len(buf) {
                        return nil, ErrSplitTooShort
                }

                dcidLen := int(buf[offset+5])
                if dcidLen > MaxCIDLen {
                        return nil, ErrSplitBadCILen
                }
                dcidEnd := offset + 6 + dcidLen
                if dcidEnd+1 > len(buf) {
                        return nil, ErrSplitTooShort
                }

                scidLen := int(buf[dcidEnd])
                if scidLen > MaxCIDLen {
                        return nil, ErrSplitBadCILen
                }
                scidEnd := dcidEnd + 1 + scidLen
                if scidEnd > len(buf) {
                        return nil, ErrSplitTooShort
                }

                // Long Packet Type = bits 4-5 of first byte.
                pktType := (firstByte >> 4) & 0x03

                // Retry packets have no Length field, no Packet Number, no
                // Payload — they end with a 16-byte Retry Integrity Tag.
                // §17.2.5: "A Retry packet MUST NOT be coalesced with any
                // other packet." Treat as last packet.
                if pktType == pktTypeLongRetry {
                        offsets = append(offsets, [2]int{packetStart, len(buf)})
                        return offsets, nil
                }

                bodyOffset := scidEnd

                // Initial packets have a Token Length + Token between SCID
                // and the Length field. 0-RTT and Handshake do not.
                if pktType == pktTypeLongInitial {
                        tokenLen, n, err := readQUICVarint(buf[bodyOffset:])
                        if err != nil {
                                return nil, err
                        }
                        bodyOffset += n + int(tokenLen)
                        if bodyOffset > len(buf) {
                                return nil, ErrSplitTooShort
                        }
                }

                // Length (varint) covers Packet Number + Payload.
                lengthVal, n, err := readQUICVarint(buf[bodyOffset:])
                if err != nil {
                        return nil, err
                }
                bodyOffset += n

                packetEnd := bodyOffset + int(lengthVal)
                if packetEnd > len(buf) {
                        return nil, ErrSplitTooShort
                }

                offsets = append(offsets, [2]int{packetStart, packetEnd})
                offset = packetEnd
        }

        return offsets, nil
}

// readQUICVarint reads a QUIC variable-length integer per RFC 9000 §16.
// Returns (value, bytes consumed, error).
//
// The first 2 bits indicate the encoding length:
//
//      00 = 1 byte  (6-bit value,  max 63)
//      01 = 2 bytes (14-bit value, max 16383)
//      10 = 4 bytes (30-bit value, max 1073741823)
//      11 = 8 bytes (62-bit value, max 2^62-1)
func readQUICVarint(buf []byte) (uint64, int, error) {
        if len(buf) < 1 {
                return 0, 0, ErrSplitTooShort
        }
        prefix := buf[0] >> 6
        switch prefix {
        case 0:
                return uint64(buf[0] & 0x3f), 1, nil
        case 1:
                if len(buf) < 2 {
                        return 0, 0, ErrSplitTooShort
                }
                return uint64(buf[0]&0x3f)<<8 | uint64(buf[1]), 2, nil
        case 2:
                if len(buf) < 4 {
                        return 0, 0, ErrSplitTooShort
                }
                return uint64(buf[0]&0x3f)<<24 |
                        uint64(buf[1])<<16 |
                        uint64(buf[2])<<8 |
                        uint64(buf[3]), 4, nil
        case 3:
                if len(buf) < 8 {
                        return 0, 0, ErrSplitTooShort
                }
                return uint64(buf[0]&0x3f)<<56 |
                        uint64(buf[1])<<48 |
                        uint64(buf[2])<<40 |
                        uint64(buf[3])<<32 |
                        uint64(buf[4])<<24 |
                        uint64(buf[5])<<16 |
                        uint64(buf[6])<<8 |
                        uint64(buf[7]), 8, nil
        }
        // Unreachable: prefix is 2 bits, all 4 cases handled.
        return 0, 0, ErrSplitBadVarint
}
