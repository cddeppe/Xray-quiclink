// Package quic: split.go
//
// SplitCoalesced parses a coalesced QUIC datagram (multiple QUIC packets
// concatenated in a single UDP datagram, RFC 9000 §12.2) and returns
// the byte offsets of each individual QUIC packet so the caller can
// send each one as a separate UDP datagram.

package quic

import (
	"encoding/binary"
	"errors"
)

var (
	ErrSplitNotQUIC    = errors.New("not a QUIC packet (header form bits invalid)")
	ErrSplitTooShort   = errors.New("packet too short to parse")
	ErrSplitBadCILen   = errors.New("invalid connection ID length")
	ErrSplitBadVarint  = errors.New("invalid QUIC varint")
)

const (
	pktTypeLongInitial   = 0x00
	pktTypeLongHandshake = 0x02
	pktTypeLongRetry     = 0x03
)

func SplitCoalesced(buf []byte) ([][2]int, error) {
	if len(buf) < 1 {
		return nil, ErrSplitTooShort
	}
	if buf[0]&0xC0 == 0x00 {
		return nil, ErrSplitNotQUIC
	}
	var offsets [][2]int
	offset := 0
	for offset < len(buf) {
		packetStart := offset
		firstByte := buf[offset]
		if firstByte&0x80 == 0 {
			if firstByte&0x40 == 0 {
				return nil, ErrSplitNotQUIC
			}
			offsets = append(offsets, [2]int{packetStart, len(buf)})
			return offsets, nil
		}
		if firstByte&0x40 == 0 {
			offsets = append(offsets, [2]int{packetStart, len(buf)})
			return offsets, nil
		}
		if offset+5 > len(buf) {
			return nil, ErrSplitTooShort
		}
		version := binary.BigEndian.Uint32(buf[offset+1 : offset+5])
		if version == VersionNegotiation {
			offsets = append(offsets, [2]int{packetStart, len(buf)})
			return offsets, nil
		}
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
		pktType := (firstByte >> 4) & 0x03
		if pktType == pktTypeLongRetry {
			offsets = append(offsets, [2]int{packetStart, len(buf)})
			return offsets, nil
		}
		bodyOffset := scidEnd
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
	return 0, 0, ErrSplitBadVarint
}
