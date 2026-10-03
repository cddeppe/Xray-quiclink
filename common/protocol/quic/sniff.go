package quic

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go/quicvarint"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	ptls "github.com/xtls/xray-core/common/protocol/tls"
	"golang.org/x/crypto/hkdf"
)

type SniffHeader struct {
	domain string
}

func (s SniffHeader) Protocol() string {
	return "quic"
}

func (s SniffHeader) Domain() string {
	return s.domain
}

var (
	errNotQUIC        = errors.New("not quic")
	errNotQUICInitial = errors.New("not initial packet")
)

type quicVersionSpec struct {
	ver         uint32
	typeInitial byte
	initialSalt []byte
	labelPrefix string
}

var (
	quicDraft29 = quicVersionSpec{
		ver:         0xff00001d,
		typeInitial: 0b00,
		initialSalt: []byte{0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99},
		labelPrefix: "quic",
	}
	quicV1 = quicVersionSpec{
		ver:         0x1,
		typeInitial: 0b00,
		initialSalt: []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a},
		labelPrefix: "quic",
	}
	quicV2 = quicVersionSpec{
		ver:         0x6b3343cf,
		typeInitial: 0b01,
		initialSalt: []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9},
		labelPrefix: "quicv2",
	}

	quicVersionSpecMap = map[uint32]*quicVersionSpec{
		quicDraft29.ver: &quicDraft29,
		quicV1.ver:      &quicV1,
		quicV2.ver:      &quicV2,
	}
)

// ============================================================
// Per-DCID sniffer state cache (v26.10.10-link)
//
// QUIC Initial packets retransmit heavily on lossy links (mobile,
// multi-hop). Each retransmit triggered the full ~13µs HKDF + AES
// pipeline even though the traffic secrets are a pure function of
// (dcid, version). Worse, once the SNI was extracted, subsequent
// Initial / Handshake / 1-RTT packets for the same connection still
// ran the entire sniffer even though the routing decision was
// already made.
//
// The cache stores per-DCID state: the derived keys (so retransmits
// skip HKDF + aes.NewCipher + AEADAESGCMTLS13) and the extracted SNI
// (so post-Initial packets skip the sniffer entirely).
//
// The cache is bounded at 256 entries with a 5-minute TTL. QUIC DCIDs
// are 8 random bytes (16^16 namespace), so collision is essentially
// impossible. Per-state mutexes allow different connections to be
// sniffed concurrently; same-DCID processing is serialised (which is
// correct — QUIC requires ordered Initial processing).
// ============================================================

const (
	sniffCacheMaxEntries  = 256
	sniffCacheTTLSeconds   = 300 // 5 minutes
)

// quicConnKeys holds the HKDF-derived keys and cipher instances for a
// single QUIC connection's Initial packet. The keys are a pure function
// of (dcid, version), so they can be cached and reused across Initial
// retransmits.
type quicConnKeys struct {
	hpKey []byte
	key   []byte
	iv    []byte
	block cipher.Block // *aes.Cipher
	aead  cipher.AEAD  // AEADAESGCMTLS13(key, iv)
}

// quicSniffState accumulates per-DCID state across multiple sniff calls.
// Once the SNI has been extracted, subsequent sniff calls for the same
// DCID return the cached SNI without redoing the crypto work.
type quicSniffState struct {
	mu       sync.Mutex
	keys     *quicConnKeys
	keysVer  uint32 // which version the keys were derived for (0 = none)
	sni      string // "" if not yet extracted
	lastUsed atomic.Int64
}

type sniffCache struct {
	mu     sync.Mutex
	m      map[string]*quicSniffState
	maxLen int
}

var globalSniffCache = &sniffCache{
	m:      make(map[string]*quicSniffState),
	maxLen: sniffCacheMaxEntries,
}

// sniffCacheGet returns the sniff state for dcid, creating a new entry
// if needed. Returns nil if dcid is empty.
func sniffCacheGet(dcid []byte) *quicSniffState {
	if len(dcid) == 0 {
		return nil
	}
	key := hex.EncodeToString(dcid)
	c := globalSniffCache
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.m[key]
	if !ok {
		if len(c.m) >= c.maxLen {
			c.evictLocked()
		}
		s = &quicSniffState{}
		c.m[key] = s
	}
	s.lastUsed.Store(time.Now().Unix())
	return s
}

// evictLocked removes expired and/or least-recently-used entries until
// the cache has at least one free slot. Caller must hold c.mu.
func (c *sniffCache) evictLocked() {
	// First pass: drop expired entries.
	now := time.Now().Unix()
	for k, s := range c.m {
		if now-s.lastUsed.Load() > sniffCacheTTLSeconds {
			delete(c.m, k)
		}
	}
	// If still at capacity, evict the single least-recently-used entry.
	if len(c.m) >= c.maxLen {
		var oldestKey string
		var oldestTime int64 = 1 << 62
		for k, s := range c.m {
			t := s.lastUsed.Load()
			if t < oldestTime {
				oldestTime = t
				oldestKey = k
			}
		}
		if oldestKey != "" {
			delete(c.m, oldestKey)
		}
	}
}

// cachedSNI returns the previously-extracted SNI for this DCID, or "".
// Safe for concurrent use.
func (s *quicSniffState) cachedSNI() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sni
}

// setSNI caches the extracted SNI for this DCID.
func (s *quicSniffState) setSNI(sni string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sni = sni
}

// deriveKeys returns the cached keys for (dcid, version) if available,
// otherwise derives them from the QUIC Initial salt and stores them.
// The caller must not hold s.mu.
func (s *quicSniffState) deriveKeys(dcid []byte, ver uint32, salt []byte, label string) (*quicConnKeys, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keys != nil && s.keysVer == ver {
		return s.keys, nil
	}
	initialSecret := hkdf.Extract(crypto.SHA256.New, dcid, salt)
	secret, err := hkdfExpandLabel(initialSecret, "client in", crypto.SHA256.Size())
	if err != nil {
		return nil, errNotQUIC
	}
	hpKey, err := hkdfExpandLabel(secret, label+" hp", 16)
	if err != nil {
		return nil, errNotQUIC
	}
	key, err := hkdfExpandLabel(secret, label+" key", 16)
	if err != nil {
		return nil, errNotQUIC
	}
	iv, err := hkdfExpandLabel(secret, label+" iv", 12)
	if err != nil {
		return nil, errNotQUIC
	}
	block, err := aes.NewCipher(hpKey)
	if err != nil {
		return nil, err
	}
	aead := AEADAESGCMTLS13(key, iv)
	keys := &quicConnKeys{
		hpKey: hpKey,
		key:   key,
		iv:    iv,
		block: block,
		aead:  aead,
	}
	s.keys = keys
	s.keysVer = ver
	return keys, nil
}

// ============================================================
// SniffQUIC — public entry point
// ============================================================

func SniffQUIC(b []byte) (*SniffHeader, error) {
	if len(b) == 0 {
		return nil, common.ErrNoClue
	}

	// Peek the first packet's DCID. If we've already sniffed this DCID
	// before, short-circuit the entire sniffer with the cached SNI.
	// Even if we haven't seen the SNI yet, the DCID lets us reuse
	// cached HKDF-derived keys for Initial retransmits.
	if dcid, _, err := ParseDCID(b); err == nil && len(dcid) > 0 {
		state := sniffCacheGet(dcid)
		if state != nil {
			if sni := state.cachedSNI(); sni != "" {
				return &SniffHeader{domain: sni}, nil
			}
			return sniffQUICBody(b, state)
		}
	}

	// No DCID could be extracted (short packet with non-8-byte DCID,
	// Version Negotiation, or non-QUIC). Fall through to the full
	// parser without caching; it will return the appropriate error.
	return sniffQUICBody(b, nil)
}

// sniffQUICBody is the full packet-processing pipeline. state may be
// nil (no cache entry) or a per-DCID state (used for key caching and
// SNI storage).
func sniffQUICBody(b []byte, state *quicSniffState) (*SniffHeader, error) {
	// Crypto data separated across packets
	cryptoLen := int32(0)
	cryptoDataBuf := buf.NewWithSize(32767)
	defer cryptoDataBuf.Release()
	cache := buf.New()
	defer cache.Release()

	// SniffQUIC decrypts the QUIC Initial packet in place (HP removal via XOR
	// and AEAD Open both write back into the buffer). The dispatcher hands us
	// a slice into a shared buf.Buffer; mutating it would corrupt the buffer
	// viewed by other sniffers in the chain (bittorrent UTP, fake-DNS) and
	// the cached reader that feeds downstream. Clone once up front so the
	// caller's buffer is never modified. The cost is one allocation per
	// sniffed datagram, which is negligible compared to the AES-GCM work
	// already required.
	b = bytes.Clone(b)

	// datagramDCID is the DCID of the first long-header packet in this
	// datagram. RFC 9000 §12.2 mandates that all coalesced packets in
	// a datagram share the same DCID; a mismatch indicates a malformed
	// or hostile packet and we reject the whole datagram.
	var datagramDCID []byte

	// Parse QUIC packets
	for len(b) > 0 {
		buffer := buf.FromBytes(b)
		typeByte, err := buffer.ReadByte()
		if err != nil {
			return nil, errNotQUIC
		}

		isLongHeader := typeByte&0x80 > 0
		if !isLongHeader || typeByte&0x40 == 0 {
			return nil, errNotQUICInitial
		}

		vb, err := buffer.ReadBytes(4)
		if err != nil {
			return nil, errNotQUIC
		}

		versionNumber := binary.BigEndian.Uint32(vb)
		var s *quicVersionSpec
		if v, ok := quicVersionSpecMap[versionNumber]; ok {
			s = v
		} else {
			return nil, errNotQUIC
		}

		var destConnID []byte
		if l, err := buffer.ReadByte(); err != nil {
			return nil, errNotQUIC
		} else if destConnID, err = buffer.ReadBytes(int32(l)); err != nil {
			return nil, errNotQUIC
		}

		if l, err := buffer.ReadByte(); err != nil {
			return nil, errNotQUIC
		} else if common.Error2(buffer.ReadBytes(int32(l))) != nil {
			return nil, errNotQUIC
		}

		// Coalesced DCID consistency check (RFC 9000 §12.2).
		// All coalesced long-header packets in a single datagram MUST
		// share the same DCID. A mismatch would cause CRYPTO data
		// from packet N to be decrypted with keys derived from
		// packet N-1's DCID, producing garbage that silently corrupts
		// SNI extraction.
		if datagramDCID == nil {
			datagramDCID = destConnID
		} else if !bytes.Equal(destConnID, datagramDCID) {
			return nil, errNotQUIC
		}

		packetType := (typeByte & 0x30) >> 4
		isQUICInitial := packetType == s.typeInitial

		if isQUICInitial { // Only initial packets have token, see https://datatracker.ietf.org/doc/html/rfc9000#section-17.2.2
			tokenLen, err := readShortQUICVarint(buffer)
			if err != nil || tokenLen > int32(len(b)) {
				return nil, errNotQUIC
			}

			if _, err = buffer.ReadBytes(tokenLen); err != nil {
				return nil, errNotQUIC
			}
		}

		packetLen, err := readShortQUICVarint(buffer)
		if err != nil {
			return nil, errNotQUIC
		}
		// packetLen is impossible to be shorter than this
		if packetLen < 4 {
			return nil, errNotQUIC
		}

		hdrLen := len(b) - int(buffer.Len())
		if len(b) < hdrLen+int(packetLen) {
			return nil, common.ErrNoClue // Not enough data to read as a QUIC packet. QUIC is UDP-based, so this is unlikely to happen.
		}

		restPayload := b[hdrLen+int(packetLen):]
		// cachedReader can concatenate zero-padded UDP datagrams.
		// Coalesced QUIC packets may be separated by zero-padding bytes
		// (PADDING frames filling the alignment gap before the next
		// packet); trim them so the next loop iteration sees the real
		// first byte of the following packet.
		restPayload = bytes.TrimLeft(restPayload, "\x00")
		if !isQUICInitial { // Skip this packet if it's not initial packet
			b = restPayload
			continue
		}

		// Use cached keys if we've seen this DCID before (Initial
		// retransmit), otherwise derive and cache them. The keys are
		// a pure function of (dcid, version), so caching is safe.
		var block cipher.Block
		var quicCipher cipher.AEAD
		if state != nil {
			keys, err := state.deriveKeys(destConnID, versionNumber, s.initialSalt, s.labelPrefix)
			if err != nil {
				return nil, err
			}
			block = keys.block
			quicCipher = keys.aead
		} else {
			salt := s.initialSalt
			label := s.labelPrefix
			initialSecret := hkdf.Extract(crypto.SHA256.New, destConnID, salt)
			secret, err := hkdfExpandLabel(initialSecret, "client in", crypto.SHA256.Size())
			if err != nil {
				return nil, errNotQUIC
			}
			hpKey, err := hkdfExpandLabel(secret, label+" hp", 16)
			if err != nil {
				return nil, errNotQUIC
			}
			block, err = aes.NewCipher(hpKey)
			if err != nil {
				return nil, err
			}
			key, err := hkdfExpandLabel(secret, label+" key", 16)
			if err != nil {
				return nil, errNotQUIC
			}
			iv, err := hkdfExpandLabel(secret, label+" iv", 12)
			if err != nil {
				return nil, errNotQUIC
			}
			quicCipher = AEADAESGCMTLS13(key, iv)
		}

		if len(b) < hdrLen+4+block.BlockSize() {
			return nil, errNotQUIC
		}
		cache.Clear()
		mask := cache.Extend(int32(block.BlockSize()))
		block.Encrypt(mask, b[hdrLen+4:hdrLen+4+len(mask)])
		b[0] ^= mask[0] & 0xf
		packetNumberLength := int(b[0]&0x3 + 1)
		for i := range packetNumberLength {
			b[hdrLen+i] ^= mask[i+1]
		}

		nonce := cache.Extend(int32(quicCipher.NonceSize()))
		_, err = buffer.Read(nonce[len(nonce)-packetNumberLength:])
		if err != nil {
			return nil, err
		}

		extHdrLen := hdrLen + packetNumberLength
		data := b[extHdrLen : int(packetLen)+hdrLen]
		decrypted, err := quicCipher.Open(b[extHdrLen:extHdrLen], nonce, data, b[:extHdrLen])
		if err != nil {
			return nil, err
		}
		buffer = buf.FromBytes(decrypted)
		for !buffer.IsEmpty() {
			frameType, _ := buffer.ReadByte()
			for frameType == 0x0 && !buffer.IsEmpty() {
				frameType, _ = buffer.ReadByte()
			}
			switch frameType {
			case 0x00: // PADDING frame
			case 0x01: // PING frame
			case 0x02, 0x03: // ACK frame
				if _, err = readShortQUICVarint(buffer); err != nil { // Field: Largest Acknowledged
					return nil, io.ErrUnexpectedEOF
				}
				if _, err = readShortQUICVarint(buffer); err != nil { // Field: ACK Delay
					return nil, io.ErrUnexpectedEOF
				}
				ackRangeCount, err := readShortQUICVarint(buffer) // Field: ACK Range Count
				if err != nil {
					return nil, io.ErrUnexpectedEOF
				}
				if _, err = readShortQUICVarint(buffer); err != nil { // Field: First ACK Range
					return nil, io.ErrUnexpectedEOF
				}
				for i := 0; i < int(ackRangeCount); i++ { // Field: ACK Range
					if _, err = readShortQUICVarint(buffer); err != nil { // Field: ACK Range -> Gap
						return nil, io.ErrUnexpectedEOF
					}
					if _, err = readShortQUICVarint(buffer); err != nil { // Field: ACK Range -> ACK Range Length
						return nil, io.ErrUnexpectedEOF
					}
				}
				if frameType == 0x03 {
					if _, err = readShortQUICVarint(buffer); err != nil { // Field: ECN Counts -> ECT0 Count
						return nil, io.ErrUnexpectedEOF
					}
					if _, err = readShortQUICVarint(buffer); err != nil { // Field: ECN Counts -> ECT1 Count
						return nil, io.ErrUnexpectedEOF
					}
					if _, err = readShortQUICVarint(buffer); err != nil { //nolint:misspell // Field: ECN Counts -> ECT-CE Count
						return nil, io.ErrUnexpectedEOF
					}
				}
			case 0x06: // CRYPTO frame, we will use this frame
				offset, err := readShortQUICVarint(buffer) // Field: Offset
				if err != nil {
					return nil, io.ErrUnexpectedEOF
				}
				length, err := readShortQUICVarint(buffer) // Field: Length
				if err != nil || length > buffer.Len() {
					return nil, io.ErrUnexpectedEOF
				}
				currentCryptoLen := int32(offset + length)
				if cryptoLen < currentCryptoLen {
					if cryptoDataBuf.Cap() < currentCryptoLen {
						return nil, io.ErrShortBuffer
					}
					cryptoDataBuf.Extend(currentCryptoLen - cryptoLen)
					cryptoLen = currentCryptoLen
				}
				if _, err := buffer.Read(cryptoDataBuf.BytesRange(offset, currentCryptoLen)); err != nil { // Field: Crypto Data
					return nil, io.ErrUnexpectedEOF
				}
			case 0x1c: // CONNECTION_CLOSE frame, only 0x1c is permitted in initial packet
				if _, err = readShortQUICVarint(buffer); err != nil { // Field: Error Code
					return nil, io.ErrUnexpectedEOF
				}
				if _, err = readShortQUICVarint(buffer); err != nil { // Field: Frame Type
					return nil, io.ErrUnexpectedEOF
				}
				length, err := readShortQUICVarint(buffer) // Field: Reason Phrase Length
				if err != nil {
					return nil, io.ErrUnexpectedEOF
				}
				if _, err := buffer.ReadBytes(int32(length)); err != nil { // Field: Reason Phrase
					return nil, io.ErrUnexpectedEOF
				}
			default:
				// Only above frame types are permitted in initial packet.
				// See https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.2-8
				return nil, errNotQUICInitial
			}
		}

		tlsHdr := &ptls.SniffHeader{}
		err = ptls.ReadClientHello(cryptoDataBuf.BytesRange(0, cryptoLen), tlsHdr)
		if err != nil {
			// The crypto data may have not been fully recovered in current packets,
			// So we continue to sniff rest packets.
			b = restPayload
			continue
		}
		// Cache the extracted SNI for this DCID so subsequent
		// packets (Initial retransmits, Handshake, 1-RTT) skip the
		// sniffer entirely.
		if state != nil {
			state.setSNI(tlsHdr.Domain())
		}
		return &SniffHeader{domain: tlsHdr.Domain()}, nil
	}
	// All payload is parsed as valid QUIC packets, but we need more packets for crypto data to read client hello.
	return nil, protocol.ErrProtoNeedMoreData
}

func hkdfExpandLabel(secret []byte, label string, length int) ([]byte, error) {
	b := make([]byte, 0, 2+1+6+len(label)+1)
	b = binary.BigEndian.AppendUint16(b, uint16(length))
	b = append(b, byte(6+len(label)))
	b = append(b, "tls13 "...)
	b = append(b, label...)
	b = append(b, 0) // context

	out := make([]byte, length)
	n, err := hkdf.Expand(crypto.SHA256.New, secret, b).Read(out)
	if err != nil {
		// HKDF-Expand can only fail if the reader returns an error, which
		// for HMAC-SHA256 only happens on truly broken inputs (e.g.
		// SHA256 not registered). Treat as a soft failure so a single
		// malformed QUIC packet cannot panic the whole xray process.
		return nil, errors.New("quic: HKDF-Expand failed: ", err)
	}
	if n != length {
		return nil, errors.New("quic: HKDF-Expand-Label produced ", n, " bytes, want ", length)
	}
	return out, nil
}

// readShortQUICVarint wraps quicvarint.Read with a max limit for length related fields.
// we only handle QUIC Initial so these numbers should not exceed 65535
// returns int32 to reduce type conversion
func readShortQUICVarint(reader io.ByteReader) (int32, error) {
	v, err := quicvarint.Read(reader)
	if err != nil {
		return 0, err
	}
	if v > 65535 {
		// not used(
		return 0, errNotQUICInitial
	}
	return int32(v), nil
}
