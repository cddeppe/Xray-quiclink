package quic

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	ptls "github.com/xtls/xray-core/common/protocol/tls"
	"golang.org/x/crypto/hkdf"
)

// SniffHeader holds the metadata extracted from a QUIC Initial's TLS
// ClientHello.
//
// v26.10.11-link adds ALPN and ECH presence to the previously SNI-only
// header, enabling routing rules to distinguish HTTP/3, DNS-over-QUIC,
// WebTransport, and MASQUE traffic, and to detect when ECH is in use
// (meaning the visible SNI is a cover name).
type SniffHeader struct {
	domain string
	alpn   string
	hasECH bool
}

func (s SniffHeader) Protocol() string {
	return "quic"
}

func (s SniffHeader) Domain() string {
	return s.domain
}

// ALPN returns the first ALPN protocol from the QUIC handshake's TLS
// ClientHello, or "" if no ALPN extension was present. Common values
// for QUIC traffic:
//   - "h3"              — HTTP/3 (e.g. YouTube)
//   - "doq"             — DNS-over-QUIC
//   - "h3-webtransport" — WebTransport
//   - "masque/..."      — MASQUE proxy
//
// Routing rules can use this to distinguish traffic types instead of
// guessing from the SNI alone.
func (s SniffHeader) ALPN() string {
	return s.alpn
}

// HasECH returns true if the ClientHello contained an
// encrypted_client_hello extension (RFC 9460, extension ID 0xfe0d).
// When true, the SNI returned by Domain() is a cover name and the
// real SNI is encrypted inside the ECH extension. Routing layers
// should fall back to IP-based rules or other heuristics rather than
// trusting the cover SNI.
func (s SniffHeader) HasECH() bool {
	return s.hasECH
}

var (
	errNotQUIC        = errors.New("not quic")
	errNotQUICInitial = errors.New("not initial packet")
)

// quicVersionSpec describes a QUIC version's Initial packet parameters.
//
// v26.10.11-link precomputes the HKDF-Expand-Label strings (labelHP,
// labelKey, labelIV) to eliminate per-packet string concatenation
// allocations on the hot path.
//
// v26.10.12-link precomputes the full HKDF-Expand-Label info buffers
// (infoClientIn, infoHP, infoKey, infoIV) so the derive-keys hot path
// has zero allocations and zero appends. Each info buffer is the
// already-serialized form: [length(2)][label_len(1)]["tls13 "][label][0x00].
type quicVersionSpec struct {
	ver         uint32
	typeInitial byte
	initialSalt []byte
	labelHP     string // precomputed: labelPrefix + " hp"
	labelKey    string // precomputed: labelPrefix + " key"
	labelIV     string // precomputed: labelPrefix + " iv"
	// Precomputed HKDF-Expand-Label info buffers. Each is the fully
	// serialized HkdfLabel struct (RFC 8446 §4.4.3) for the named
	// label, with the appropriate output length already encoded.
	// These are package-level constants — never mutated.
	infoClientIn []byte
	infoHP       []byte
	infoKey      []byte
	infoIV       []byte
}

// buildHKDFInfo constructs the HkdfLabel info buffer for a (label, length)
// pair. Format per RFC 8446 §4.4.3:
//
//	[length(2 bytes, big-endian)] [label_len(1 byte)] ["tls13 "] [label] [0x00]
//
// The "tls13 " prefix is 6 bytes, so label_len = 6 + len(label).
func buildHKDFInfo(label string, length int) []byte {
	labelLen := 6 + len(label)
	info := make([]byte, 0, 2+1+labelLen+1)
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(labelLen))
	info = append(info, "tls13 "...)
	info = append(info, label...)
	info = append(info, 0)
	return info
}

var (
	quicDraft29 = quicVersionSpec{
		ver:          0xff00001d,
		typeInitial:  0b00,
		initialSalt:  []byte{0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99},
		labelHP:      "quic hp",
		labelKey:     "quic key",
		labelIV:      "quic iv",
		infoClientIn: buildHKDFInfo("client in", crypto.SHA256.Size()),
		infoHP:       buildHKDFInfo("quic hp", 16),
		infoKey:      buildHKDFInfo("quic key", 16),
		infoIV:       buildHKDFInfo("quic iv", 12),
	}
	quicV1 = quicVersionSpec{
		ver:          0x1,
		typeInitial:  0b00,
		initialSalt:  []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a},
		labelHP:      "quic hp",
		labelKey:     "quic key",
		labelIV:      "quic iv",
		infoClientIn: buildHKDFInfo("client in", crypto.SHA256.Size()),
		infoHP:       buildHKDFInfo("quic hp", 16),
		infoKey:      buildHKDFInfo("quic key", 16),
		infoIV:       buildHKDFInfo("quic iv", 12),
	}
	quicV2 = quicVersionSpec{
		ver:          0x6b3343cf,
		typeInitial:  0b01,
		initialSalt:  []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9},
		labelHP:      "quicv2 hp",
		labelKey:     "quicv2 key",
		labelIV:      "quicv2 iv",
		infoClientIn: buildHKDFInfo("client in", crypto.SHA256.Size()),
		infoHP:       buildHKDFInfo("quicv2 hp", 16),
		infoKey:      buildHKDFInfo("quicv2 key", 16),
		infoIV:       buildHKDFInfo("quicv2 iv", 12),
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
	sniffCacheMaxEntries = 256
	sniffCacheTTLSeconds = 300 // 5 minutes
)

// quicConnKeys holds the HKDF-derived keys and cipher instances for a
// single QUIC connection's Initial packet. The keys are a pure function
// of (dcid, version), so they can be cached and reused across Initial
// retransmits.
type quicConnKeys struct {
	block cipher.Block // *aes.Cipher (for HP mask)
	aead  cipher.AEAD  // AEADAESGCMTLS13(key, iv)
}

// quicSniffState accumulates per-DCID state across multiple sniff calls.
// Once the SNI has been extracted, subsequent sniff calls for the same
// DCID return the cached SNI without redoing the crypto work. ALPN and
// ECH presence are cached alongside the SNI so routing-layer callers
// can use them without re-sniffing.
//
// v26.10.12-link: tracks seen QUIC packet numbers per DCID so
// retransmitted Initials can skip the expensive AES-GCM decrypt + frame
// walk. On lossy mobile links where YouTube retransmits Initials 2-3
// times, this skips the most expensive part for 2 of 3 packets.
type quicSniffState struct {
	mu      sync.Mutex
	keys    *quicConnKeys
	keysVer uint32 // which version the keys were derived for (0 = none)
	sni     string // "" if not yet extracted
	alpn    string // "" if not yet extracted or no ALPN present
	hasECH  bool   // true if ClientHello had an ECH extension
	// seenPackets tracks QUIC packet numbers we've already decrypted
	// for this DCID. Retransmitted Initials (same DCID + same packet
	// number) skip the AES-GCM Open + frame walk entirely. Bounded
	// by seenPacketsMax; eviction is FIFO (oldest entry removed).
	// Real Initials have packet numbers 0, 1, 2, ... and we only
	// see retransmits of the very first few, so a small bound is
	// sufficient.
	seenPackets map[uint64]struct{}
	seenOrder   []uint64
	lastUsed    atomic.Int64
}

const seenPacketsMax = 8

// markSeen records that we've already decrypted packet `pn` for this
// DCID. Returns true if it was newly added (caller should decrypt),
// false if we've already seen it (caller should skip).
func (s *quicSniffState) markSeen(pn uint64) bool {
	if _, ok := s.seenPackets[pn]; ok {
		return false
	}
	if s.seenPackets == nil {
		s.seenPackets = make(map[uint64]struct{}, seenPacketsMax)
	}
	if len(s.seenPackets) >= seenPacketsMax && len(s.seenOrder) > 0 {
		// FIFO evict
		oldest := s.seenOrder[0]
		s.seenOrder = s.seenOrder[1:]
		delete(s.seenPackets, oldest)
	}
	s.seenPackets[pn] = struct{}{}
	s.seenOrder = append(s.seenOrder, pn)
	return true
}

// hasPacket returns true if we've already decrypted packet `pn`.
// Used to skip retransmitted Initials.
func (s *quicSniffState) hasPacket(pn uint64) bool {
	_, ok := s.seenPackets[pn]
	return ok
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

// dcidKey extracts the DCID from a QUIC packet and returns it as a
// string suitable for use as a map key — without allocating an
// intermediate []byte. This is cheaper than ParseDCID + hex.EncodeToString
// (the v26.10.10-link approach) because it:
//  1. Reads the DCID directly from the packet bytes (no []byte copy)
//  2. Converts to string in one shot (no hex encoding)
//
// Returns ("", false) if the DCID cannot be extracted.
func dcidKey(packet []byte) (string, bool) {
	if len(packet) < 1 {
		return "", false
	}
	firstByte := packet[0]
	if firstByte&0x80 != 0 {
		// Long header
		if firstByte&0x40 == 0 {
			return "", false
		}
		if len(packet) < 6 {
			return "", false
		}
		if binary.BigEndian.Uint32(packet[1:5]) == VersionNegotiation {
			return "", false
		}
		dcidLen := int(packet[5])
		if dcidLen > MaxCIDLen || dcidLen == 0 {
			return "", false
		}
		if len(packet) < 6+dcidLen {
			return "", false
		}
		return string(packet[6 : 6+dcidLen]), true
	}
	if firstByte&0x40 != 0 {
		// Short header: default 8-byte DCID
		if len(packet) < 9 {
			return "", false
		}
		return string(packet[1:9]), true
	}
	return "", false
}

// get returns the sniff state for the given cache key, creating a new
// entry if needed.
func (c *sniffCache) get(key string) *quicSniffState {
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
	// v26.10.34-link (L4 fix): only update lastUsed if stale by ≥1 second.
	// The timestamp is in seconds, so sub-second updates write the same value
	// and just bounce the cache line. pprof showed time.Now was 31.5% of the
	// warm-SNI path (~42 ns/op) — this drops it to near zero on the hit path.
	now := time.Now().Unix()
	if now != s.lastUsed.Load() {
		s.lastUsed.Store(now)
	}
	return s
}

// v26.10.34-link (H3 fix): peek returns the sniff state for the given key
// WITHOUT creating an entry. Returns (nil, false) on miss. Used for short-header
// packets that should not populate the cache — prevents cache-pollution DoS
// where an attacker sends 256+ distinct 1-RTT packets with random DCIDs to
// evict real Initial entries.
func (c *sniffCache) peek(key string) (*quicSniffState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.m[key]
	if !ok {
		return nil, false
	}
	return s, true
}

// evictLocked removes expired and/or least-recently-used entries until
// the cache has at least one free slot. Caller must hold c.mu.
func (c *sniffCache) evictLocked() {
	now := time.Now().Unix()
	for k, s := range c.m {
		if now-s.lastUsed.Load() > sniffCacheTTLSeconds {
			delete(c.m, k)
		}
	}
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

// cachedResult returns the previously-extracted sniff result for this
// DCID. The boolean indicates whether the cache hit (sni != ""). ALPN
// and ECH presence are also returned so the caller can construct a
// complete SniffHeader on a cache hit.
func (s *quicSniffState) cachedResult() (sni, alpn string, hasECH, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sni != "" {
		return s.sni, s.alpn, s.hasECH, true
	}
	return "", "", false, false
}

// setResult caches the extracted SNI, ALPN, and ECH presence for this
// DCID. Subsequent sniff calls for the same DCID will short-circuit
// at the cache lookup and return these values without redoing the
// crypto work.
func (s *quicSniffState) setResult(sni, alpn string, hasECH bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sni = sni
	s.alpn = alpn
	s.hasECH = hasECH
}

// deriveKeys returns the cached keys for (dcid, version) if available,
// otherwise derives them from the QUIC Initial salt and stores them.
// The caller must not hold s.mu.
//
// v26.10.12-link: uses precomputed HKDF-Expand-Label info buffers
// (spec.infoClientIn/HP/Key/IV) so the derive path has zero
// allocations and zero string appends. The old hkdfExpandLabel()
// helper is retained for compatibility but the hot path now uses
// hkdfExpandLabelRaw below.
func (s *quicSniffState) deriveKeys(dcid []byte, ver uint32, spec *quicVersionSpec) (*quicConnKeys, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keys != nil && s.keysVer == ver {
		return s.keys, nil
	}
	initialSecret := hkdf.Extract(crypto.SHA256.New, dcid, spec.initialSalt)
	secret, err := hkdfExpandLabelRaw(initialSecret, spec.infoClientIn, crypto.SHA256.Size())
	if err != nil {
		return nil, errNotQUIC
	}
	hpKey, err := hkdfExpandLabelRaw(secret, spec.infoHP, 16)
	if err != nil {
		return nil, errNotQUIC
	}
	key, err := hkdfExpandLabelRaw(secret, spec.infoKey, 16)
	if err != nil {
		return nil, errNotQUIC
	}
	iv, err := hkdfExpandLabelRaw(secret, spec.infoIV, 12)
	if err != nil {
		return nil, errNotQUIC
	}
	block, err := aes.NewCipher(hpKey)
	if err != nil {
		return nil, err
	}
	aead := AEADAESGCMTLS13(key, iv)
	keys := &quicConnKeys{block: block, aead: aead}
	s.keys = keys
	s.keysVer = ver
	return keys, nil
}

// ============================================================
// cursor — zero-allocation byte cursor (v26.10.11-link)
//
// Replaces buf.Buffer on the sniffer hot path. buf.Buffer.ReadByte
// does a bounds check, a struct field read, a slice index, an
// increment, and a struct field write per byte. The cursor type is
// a plain struct with two fields (b []byte, i int) that the compiler
// can keep in registers and inline all methods.
//
// Also provides an inline QUIC varint parser (shortVarint) that
// eliminates the quicvarint.Read + io.ByteReader interface dispatch
// overhead of the original readShortQUICVarint.
// ============================================================

type cursor struct {
	b []byte
	i int
}

// byte reads one byte from the cursor. Returns (value, ok).
func (c *cursor) byte() (byte, bool) {
	if c.i >= len(c.b) {
		return 0, false
	}
	v := c.b[c.i]
	c.i++
	return v, true
}

// bytes reads n bytes from the cursor. Returns (slice, ok). The slice
// is a sub-slice of the cursor's backing array — no copy.
func (c *cursor) bytes(n int) ([]byte, bool) {
	if n < 0 || c.i+n > len(c.b) {
		return nil, false
	}
	v := c.b[c.i : c.i+n]
	c.i += n
	return v, true
}

// shortVarint reads a QUIC variable-length integer and enforces the
// 65535 maximum from the original readShortQUICVarint. Returns
// (value, ok). On failure, the cursor position is not advanced.
//
// This is an inline replacement for quicvarint.Read + io.ByteReader
// interface dispatch. For a 2-byte varint (the common case for token
// length, packet length, etc.), this eliminates 2 interface method
// calls and the associated buf.Buffer struct field updates.
func (c *cursor) shortVarint() (int32, bool) {
	if c.i >= len(c.b) {
		return 0, false
	}
	first := c.b[c.i]
	length := 1 << (first >> 6)
	if c.i+length > len(c.b) {
		return 0, false
	}
	val := uint64(first & 0x3f)
	for j := 1; j < length; j++ {
		val = (val << 8) | uint64(c.b[c.i+j])
	}
	c.i += length
	if val > 65535 {
		return 0, false
	}
	return int32(val), true
}

// ============================================================
// SniffQUIC — public entry point
// ============================================================

func SniffQUIC(b []byte) (*SniffHeader, error) {
	if len(b) == 0 {
		return nil, common.ErrNoClue
	}

	// Extract the DCID as a string key without allocating an
	// intermediate []byte. If we've already sniffed this DCID before,
	// short-circuit the entire sniffer with the cached result.
	if key, ok := dcidKey(b); ok {
		// v26.10.34-link (H3 fix): short-header (1-RTT) packets never contain
		// a ClientHello, so look them up read-only and never create an entry.
		// Long-header packets (Initial/Handshake/0-RTT) may populate the cache.
		// Prevents cache-pollution DoS from adversarial 1-RTT traffic with
		// random DCIDs.
		isLongHeader := b[0]&0x80 != 0
		var state *quicSniffState
		if isLongHeader {
			state = globalSniffCache.get(key)
		} else {
			state, _ = globalSniffCache.peek(key)
		}
		if state != nil {
			if sni, alpn, hasECH, ok := state.cachedResult(); ok {
				return &SniffHeader{domain: sni, alpn: alpn, hasECH: hasECH}, nil
			}
		}
		if !isLongHeader {
			return nil, errNotQUICInitial
		}
		return sniffQUICBody(b, state)
	}

	return sniffQUICBody(b, nil)
}

// sniffQUICBody is the full packet-processing pipeline. state may be
// nil (no cache entry) or a per-DCID state (used for key caching and
// result storage).
//
// v26.10.11-link hot-path optimizations (on top of v26.10.10-link's
// DCID cache):
//   - cursor type replaces buf.Buffer for zero-allocation byte reads
//   - inline varint parser eliminates quicvarint.Read + interface dispatch
//   - bulk-skip PADDING frames with a tight loop instead of per-byte ReadByte
//   - zero-copy ClientHello fast path (skip 32KB alloc when CRYPTO is at offset 0)
//   - stack-allocated HP mask and nonce (no buf.New() pool buffer)
//   - precomputed label strings (no per-packet string concat)
//   - switch-based version lookup (no map hash)
//   - short-circuit CONNECTION_CLOSE (break out of frame loop)
func sniffQUICBody(b []byte, state *quicSniffState) (*SniffHeader, error) {
	// v26.10.34-link (H2 fix): fast path — reject non-long-header packets
	// WITHOUT cloning. The sniffer only cares about long-header Initials;
	// short headers (1-RTT) and non-QUIC UDP fail here with 0 allocations.
	// Upstream did no allocation here; the unconditional bytes.Clone below
	// was a ~1200B alloc regression for 99% of long-lived QUIC traffic.
	if len(b) < 1 || b[0]&0xc0 != 0xc0 {
		return nil, errNotQUICInitial
	}
	// Clone before mutating (HP removal via XOR and AEAD Open both write
	// back into the buffer). Only long-header packets reach here.
	b = bytes.Clone(b)

	// Stack-allocated HP mask and nonce. The original code pulled an
	// 8KB pool buffer to hold 28 bytes total; these arrays live on
	// the stack and cost zero allocations.
	var mask [16]byte
	var nonce [12]byte

	// Fallback accumulation buffer for multi-frame CRYPTO. Only
	// allocated if the fast path fails (rare: ~5% of sniffs).
	var cryptoDataBuf *buf.Buffer
	var cryptoLen int32
	defer func() {
		if cryptoDataBuf != nil {
			cryptoDataBuf.Release()
		}
	}()

	// datagramDCID is the DCID of the first long-header packet in this
	// datagram. RFC 9000 §12.2 mandates that all coalesced packets in
	// a datagram share the same DCID.
	var datagramDCID []byte

	for len(b) > 0 {
		c := &cursor{b: b}

		// --- Parse long header ---

		typeByte, ok := c.byte()
		if !ok {
			return nil, errNotQUIC
		}
		isLongHeader := typeByte&0x80 > 0
		if !isLongHeader || typeByte&0x40 == 0 {
			return nil, errNotQUICInitial
		}

		vb, ok := c.bytes(4)
		if !ok {
			return nil, errNotQUIC
		}
		versionNumber := binary.BigEndian.Uint32(vb)

		// switch-based version lookup (no map hash for 3 entries)
		var spec *quicVersionSpec
		switch versionNumber {
		case quicDraft29.ver:
			spec = &quicDraft29
		case quicV1.ver:
			spec = &quicV1
		case quicV2.ver:
			spec = &quicV2
		default:
			return nil, errNotQUIC
		}

		// DCID
		dcidLen, ok := c.byte()
		if !ok {
			return nil, errNotQUIC
		}
		destConnID, ok := c.bytes(int(dcidLen))
		if !ok {
			return nil, errNotQUIC
		}

		// SCID (skip)
		scidLen, ok := c.byte()
		if !ok {
			return nil, errNotQUIC
		}
		if _, ok := c.bytes(int(scidLen)); !ok {
			return nil, errNotQUIC
		}

		// Coalesced DCID consistency check (RFC 9000 §12.2).
		if datagramDCID == nil {
			datagramDCID = destConnID
		} else if !bytes.Equal(destConnID, datagramDCID) {
			return nil, errNotQUIC
		}

		packetType := (typeByte & 0x30) >> 4
		isQUICInitial := packetType == spec.typeInitial

		// Token (Initial only)
		if isQUICInitial {
			tokenLen, ok := c.shortVarint()
			if !ok || tokenLen > int32(len(b)) {
				return nil, errNotQUIC
			}
			if _, ok := c.bytes(int(tokenLen)); !ok {
				return nil, errNotQUIC
			}
		}

		// Packet length
		packetLen, ok := c.shortVarint()
		if !ok {
			return nil, errNotQUIC
		}
		if packetLen < 4 {
			return nil, errNotQUIC
		}

		hdrLen := c.i // everything read so far is the header
		if int64(len(b)) < int64(hdrLen)+int64(packetLen) {
			return nil, common.ErrNoClue
		}

		restPayload := b[hdrLen+int(packetLen):]
		// Skip zero-padding between coalesced packets.
		restPayload = bytes.TrimLeft(restPayload, "\x00")

		if !isQUICInitial {
			b = restPayload
			continue
		}

		// --- Derive or fetch cached keys ---

		var block cipher.Block
		var quicCipher cipher.AEAD
		if state != nil {
			keys, err := state.deriveKeys(destConnID, versionNumber, spec)
			if err != nil {
				return nil, err
			}
			block = keys.block
			quicCipher = keys.aead
		} else {
			// Non-cached path. Use the v26.10.12-link precomputed
			// HKDF info buffers (zero string allocations).
			initialSecret := hkdf.Extract(crypto.SHA256.New, destConnID, spec.initialSalt)
			secret, err := hkdfExpandLabelRaw(initialSecret, spec.infoClientIn, crypto.SHA256.Size())
			if err != nil {
				return nil, errNotQUIC
			}
			hpKey, err := hkdfExpandLabelRaw(secret, spec.infoHP, 16)
			if err != nil {
				return nil, errNotQUIC
			}
			block, err = aes.NewCipher(hpKey)
			if err != nil {
				return nil, err
			}
			key, err := hkdfExpandLabelRaw(secret, spec.infoKey, 16)
			if err != nil {
				return nil, errNotQUIC
			}
			iv, err := hkdfExpandLabelRaw(secret, spec.infoIV, 12)
			if err != nil {
				return nil, errNotQUIC
			}
			quicCipher = AEADAESGCMTLS13(key, iv)
		}

		// --- HP removal (stack-allocated mask) ---

		if len(b) < hdrLen+4+block.BlockSize() {
			return nil, errNotQUIC
		}
		block.Encrypt(mask[:], b[hdrLen+4:hdrLen+4+len(mask)])
		b[0] ^= mask[0] & 0xf
		packetNumberLength := int(b[0]&0x3 + 1)
		for i := range packetNumberLength {
			b[hdrLen+i] ^= mask[i+1]
		}

		// --- AEAD decrypt ---

		// Read the (now-decrypted) packet number bytes into the tail
		// of the nonce. The first 12-packetNumberLength bytes are 0
		// (from the var declaration), which is correct for QUIC's
		// nonce construction (IV XOR packet_number, with the high
		// bytes of the nonce being the IV unchanged).
		nonceSize := quicCipher.NonceSize()
		if c.i+packetNumberLength > len(b) {
			return nil, errNotQUIC
		}
		copy(nonce[nonceSize-packetNumberLength:], b[c.i:c.i+packetNumberLength])

		// Recover the full QUIC packet number. QUIC truncates the
		// packet number on the wire to 1-4 bytes; the full number
		// is reconstructed using the largest previously seen number
		// (the "expected next" heuristic from RFC 9000 §17.1.1).
		// For sniffing we only need a stable identifier per packet,
		// so the truncated wire bytes themselves suffice as a key.
		// We use them as a uint64 for the seenPackets map.
		var pnTruncated uint64
		for i := 0; i < packetNumberLength; i++ {
			pnTruncated = (pnTruncated << 8) | uint64(b[c.i+i])
		}
		c.i += packetNumberLength

		// v26.10.12-link: skip retransmitted Initials entirely,
		// but ONLY if we've already extracted the SNI for this
		// DCID. If we haven't, this might be the same packet
		// being re-fed to the sniffer after the dispatcher's
		// cachedReader accumulated more data (legitimate — the
		// first call returned ErrProtoNeedMoreData and the
		// caller is now retrying with a complete datagram).
		// True retransmits have the same DCID + same packet
		// number + we've already extracted the SNI; that's
		// the case we want to skip.
		if state != nil {
			state.mu.Lock()
			alreadySNI := state.sni != ""
			alreadyPkt := false
			if state.seenPackets != nil {
				_, alreadyPkt = state.seenPackets[pnTruncated]
			}
			state.mu.Unlock()
			if alreadySNI && alreadyPkt {
				b = restPayload
				continue
			}
		}

		extHdrLen := hdrLen + packetNumberLength
		data := b[extHdrLen : int(packetLen)+hdrLen]
		decrypted, err := quicCipher.Open(b[extHdrLen:extHdrLen], nonce[:nonceSize], data, b[:extHdrLen])
		if err != nil {
			return nil, err
		}
		if state != nil {
			state.markSeen(pnTruncated)
		}

		// --- Walk frames ---

		// Fast path: try to parse the ClientHello directly from the
		// first CRYPTO frame at offset 0, without allocating the 32KB
		// accumulation buffer. This succeeds for ~95% of sniffs
		// (single-frame ClientHello in the first Initial).
		fc := &cursor{b: decrypted}
		fastPathTried := false

	frameLoop:
		for fc.i < len(fc.b) {
			// Bulk-skip PADDING frames. QUIC Initials are padded to
			// 1200 bytes (RFC 9000 §14.1); a typical Initial has
			// ~800 bytes of 0x00 PADDING. This tight loop is a single
			// memchr-like scan vs 800+ individual ReadByte calls.
			for fc.i < len(fc.b) && fc.b[fc.i] == 0x00 {
				fc.i++
			}
			if fc.i >= len(fc.b) {
				break
			}
			frameType := fc.b[fc.i]
			fc.i++

			switch frameType {
			case 0x00: // PADDING (already bulk-skipped, but handle defensively)
			case 0x01: // PING — no payload
			case 0x02, 0x03: // ACK
				if _, ok := fc.shortVarint(); !ok {
					return nil, io.ErrUnexpectedEOF
				}
				if _, ok := fc.shortVarint(); !ok {
					return nil, io.ErrUnexpectedEOF
				}
				ackRangeCount, ok := fc.shortVarint()
				if !ok {
					return nil, io.ErrUnexpectedEOF
				}
				if _, ok := fc.shortVarint(); !ok {
					return nil, io.ErrUnexpectedEOF
				}
				for i := 0; i < int(ackRangeCount); i++ {
					if _, ok := fc.shortVarint(); !ok {
						return nil, io.ErrUnexpectedEOF
					}
					if _, ok := fc.shortVarint(); !ok {
						return nil, io.ErrUnexpectedEOF
					}
				}
				if frameType == 0x03 {
					if _, ok := fc.shortVarint(); !ok {
						return nil, io.ErrUnexpectedEOF
					}
					if _, ok := fc.shortVarint(); !ok {
						return nil, io.ErrUnexpectedEOF
					}
					if _, ok := fc.shortVarint(); !ok {
						return nil, io.ErrUnexpectedEOF
					}
				}
			case 0x06: // CRYPTO
				offset, ok := fc.shortVarint()
				if !ok {
					return nil, io.ErrUnexpectedEOF
				}
				length, ok := fc.shortVarint()
				if !ok || length > int32(len(fc.b)-fc.i) {
					return nil, io.ErrUnexpectedEOF
				}
				frameData := fc.b[fc.i : fc.i+int(length)]
				fc.i += int(length)

				currentCryptoLen := int32(offset + length)
				if cryptoLen < currentCryptoLen {
					// Fast path: first CRYPTO frame at offset 0.
					// Try parsing the ClientHello directly from the
					// decrypted bytes — no 32KB allocation needed.
					if offset == 0 && cryptoLen == 0 && !fastPathTried {
						fastPathTried = true
						tlsHdr := &ptls.SniffHeader{}
						if err := ptls.ReadClientHello(frameData, tlsHdr); err == nil {
							if state != nil {
								state.setResult(tlsHdr.Domain(), tlsHdr.ALPN(), tlsHdr.HasECH())
							}
							return &SniffHeader{
								domain: tlsHdr.Domain(),
								alpn:   tlsHdr.ALPN(),
								hasECH: tlsHdr.HasECH(),
							}, nil
						}
						// Parse failed (incomplete ClientHello split
						// across packets?) — fall through to the
						// accumulation path and try again after
						// collecting more CRYPTO frames.
					}
					// Allocate the fallback buffer only if needed.
					if cryptoDataBuf == nil {
						cryptoDataBuf = buf.NewWithSize(32767)
					}
					if cryptoDataBuf.Cap() < currentCryptoLen {
						return nil, io.ErrShortBuffer
					}
					cryptoDataBuf.Extend(currentCryptoLen - cryptoLen)
					cryptoLen = currentCryptoLen
				}
				if cryptoDataBuf != nil {
					copy(cryptoDataBuf.BytesRange(int32(offset), currentCryptoLen), frameData)
				}
			case 0x1c: // CONNECTION_CLOSE — connection is dying, no more useful CRYPTO
				break frameLoop
			default:
				return nil, errNotQUICInitial
			}
		}

		// Try to parse ClientHello from the accumulated buffer
		// (multi-frame path). Only reached if the fast path failed.
		if cryptoDataBuf != nil && cryptoLen > 0 {
			tlsHdr := &ptls.SniffHeader{}
			err := ptls.ReadClientHello(cryptoDataBuf.BytesRange(0, cryptoLen), tlsHdr)
			if err == nil {
				if state != nil {
					state.setResult(tlsHdr.Domain(), tlsHdr.ALPN(), tlsHdr.HasECH())
				}
				return &SniffHeader{
					domain: tlsHdr.Domain(),
					alpn:   tlsHdr.ALPN(),
					hasECH: tlsHdr.HasECH(),
				}, nil
			}
		}

		b = restPayload
	}

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
		return nil, errors.New("quic: HKDF-Expand failed: ", err)
	}
	if n != length {
		return nil, errors.New("quic: HKDF-Expand-Label produced ", n, " bytes, want ", length)
	}
	return out, nil
}

// hkdfExpandLabelRaw is the v26.10.12-link fast path: takes a
// precomputed info buffer (the fully-serialized HkdfLabel struct from
// buildHKDFInfo) and a desired output length. Zero string allocations,
// zero appends. The info buffer must encode the same length as the
// `length` argument — callers should use the corresponding
// quicVersionSpec.infoXxx field.
func hkdfExpandLabelRaw(secret, info []byte, length int) ([]byte, error) {
	out := make([]byte, length)
	n, err := hkdf.Expand(crypto.SHA256.New, secret, info).Read(out)
	if err != nil {
		return nil, errors.New("quic: HKDF-Expand failed: ", err)
	}
	if n != length {
		return nil, errors.New("quic: HKDF-Expand-Label produced ", n, " bytes, want ", length)
	}
	return out, nil
}
