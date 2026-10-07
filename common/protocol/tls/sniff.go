package tls

import (
        "encoding/binary"
        "errors"

        "github.com/xtls/xray-core/common"
        "github.com/xtls/xray-core/common/protocol"
)

// SniffHeader holds the metadata extracted from a TLS ClientHello.
//
// In addition to the SNI (Domain), v26.10.11-link adds:
//   - alpn:   the first ALPN protocol from extension 0x10 (e.g. "h3",
//     "doq", "h3-webtransport", "masque"). Empty if no ALPN extension
//     was present.
//   - hasECH: true if extension 0xfe0d (encrypted_client_hello, RFC
//     9460) was present. When ECH is in use, the visible SNI is a
//     cover name and the real SNI is encrypted inside the ECH
//     extension. Routing layers should fall back to IP-based rules
//     when HasECH() returns true rather than trusting the (cover) SNI.
type SniffHeader struct {
        domain string
        alpn   string
        hasECH bool
}

func (h *SniffHeader) Protocol() string {
        return "tls"
}

func (h *SniffHeader) Domain() string {
        return h.domain
}

// ALPN returns the first ALPN protocol from the ClientHello, or "" if
// no ALPN extension was present. Multiple ALPN entries are common in
// practice (clients offer several); only the first is returned for
// simplicity. Routing rules can use this to distinguish HTTP/3 ("h3"),
// DNS-over-QUIC ("doq"), WebTransport ("h3-webtransport"), or MASQUE
// ("masque/...") traffic.
func (h *SniffHeader) ALPN() string {
        return h.alpn
}

// HasECH returns true if the ClientHello contained an
// encrypted_client_hello extension (RFC 9460, extension ID 0xfe0d).
// When true, the SNI returned by Domain() is a cover name and the
// real SNI is encrypted inside the ECH extension. Routing layers
// should fall back to IP-based rules or other heuristics rather than
// trusting the cover SNI.
//
// We cannot decrypt the inner SNI without the server's ECH private
// key, but knowing ECH is in use is enough to avoid misrouting.
func (h *SniffHeader) HasECH() bool {
        return h.hasECH
}

var (
        errNotTLS         = errors.New("not TLS header")
        errNotClientHello = errors.New("not client hello")
)

func IsValidTLSVersion(major, minor byte) bool {
        return major == 3
}

// Extension IDs we recognise.
const (
        extServerName           uint16 = 0x00
        extALPN                 uint16 = 0x10
        extEncryptedClientHello uint16 = 0xfe0d
)

// ReadClientHello parses a TLS ClientHello message and populates h
// with the SNI, ALPN, and ECH presence. Returns nil on success.
//
// If the SNI appears to be split across multiple QUIC packets (a byte
// <= ' ' is found inside the SNI), returns protocol.ErrProtoNeedMoreData
// so the caller can wait for more data before re-trying.
//
// Otherwise returns errNotClientHello on parse failures, or errNotTLS
// if no SNI was found at all.
//
// v26.10.11-link change: previously ReadClientHello returned as soon
// as it found the SNI, so ALPN and ECH extensions after SNI in the
// extension list were never observed. Now we walk the entire
// extension list to collect all three signals. The truncation check
// (ErrProtoNeedMoreData) still fires immediately when a suspect byte
// is seen inside the SNI, since in that case the rest of the
// extensions cannot be trusted either.
//
// v26.11.75-link: CRITICAL FIX for ECH ClientHello split across QUIC
// packets. Chrome's ECH ClientHello is ~2400 bytes, split across 2
// QUIC Initial packets. The SNI extension is at offset ~138 (right
// after version+random+sessionID+cipherSuites+compression), so it is
// ALWAYS in the first packet. But the old code had:
//
//      if extensionsLength != len(data) {
//          return errNotClientHello  // hard fail on truncated ClientHello!
//      }
//
// This rejected the partial ClientHello even though SNI was available.
// The QUIC sniffer's accumulation path retried with just the 1st
// packet's CRYPTO data and got errNotClientHello again (not
// ErrProtoNeedMoreData). The dispatcher waited 200ms for the 2nd
// packet, but the 2nd packet only arrives after the server responds —
// and the server can't respond until the proxy forwards the 1st packet
// (which it won't do without SNI). Chicken-and-egg deadlock.
//
// Fix: when extensionsLength > len(data), treat the ClientHello as
// truncated and walk only the available extensions. If SNI is found,
// return success immediately. If SNI is not found in the available
// data, return ErrProtoNeedMoreData (not errNotClientHello) so the
// caller knows to wait for more data.
func ReadClientHello(data []byte, h *SniffHeader) error {
        if len(data) < 42 {
                return common.ErrNoClue
        }
        sessionIDLen := int(data[38])
        if sessionIDLen > 32 || len(data) < 39+sessionIDLen {
                return common.ErrNoClue
        }
        data = data[39+sessionIDLen:]
        if len(data) < 2 {
                return common.ErrNoClue
        }
        // cipherSuiteLen is the number of bytes of cipher suite numbers. Since
        // they are uint16s, the number must be even.
        cipherSuiteLen := int(data[0])<<8 | int(data[1])
        if cipherSuiteLen%2 == 1 || len(data) < 2+cipherSuiteLen {
                return errNotClientHello
        }
        data = data[2+cipherSuiteLen:]
        if len(data) < 1 {
                return common.ErrNoClue
        }
        compressionMethodsLen := int(data[0])
        if len(data) < 1+compressionMethodsLen {
                return common.ErrNoClue
        }
        data = data[1+compressionMethodsLen:]

        if len(data) < 2 {
                return errNotClientHello
        }

        extensionsLength := int(data[0])<<8 | int(data[1])
        data = data[2:]

        // v26.11.75-link: Handle truncated ClientHello (ECH split across
        // QUIC packets). SNI is the first extension (~offset 138), so it
        // is always in the first packet's CRYPTO frame. Walk only the
        // available extension data and extract SNI if present.
        truncated := false
        if extensionsLength > len(data) {
                // ClientHello is split across QUIC packets. Walk only the
                // available extensions — SNI is early and should be present.
                truncated = true
        } else if extensionsLength < len(data) {
                // Trailing data after extensions (unusual). Walk only
                // extensionsLength bytes.
                data = data[:extensionsLength]
        }

        // Walk all extensions collecting SNI / ALPN / ECH. The SNI
        // truncation check fires immediately (returns ErrProtoNeedMoreData)
        // so the caller can wait for more QUIC packets; in that case we
        // discard any ALPN/ECH we may have already seen since the rest of
        // the extensions cannot be trusted.
        foundSNI := false
        for len(data) != 0 {
                if len(data) < 4 {
                        // v26.11.75-link: truncated mid-extension header.
                        // If we already found SNI, return success.
                        // Otherwise need more data.
                        break
                }
                extension := uint16(data[0])<<8 | uint16(data[1])
                length := int(data[2])<<8 | int(data[3])
                data = data[4:]
                if len(data) < length {
                        // v26.11.75-link: extension data is truncated.
                        // We've walked as far as we can. If SNI was
                        // found in a prior extension, return success.
                        // Otherwise need more data.
                        truncated = true
                        break
                }

                switch extension {
                case extServerName:
                        d := data[:length]
                        if len(d) < 2 {
                                return errNotClientHello
                        }
                        namesLen := int(d[0])<<8 | int(d[1])
                        d = d[2:]
                        if len(d) != namesLen {
                                return errNotClientHello
                        }
                        for len(d) > 0 {
                                if len(d) < 3 {
                                        return errNotClientHello
                                }
                                nameType := d[0]
                                nameLen := int(d[1])<<8 | int(d[2])
                                d = d[3:]
                                if len(d) < nameLen {
                                        return errNotClientHello
                                }
                                if nameType == 0 {
                                        // QUIC separated across packets
                                        // May cause the serverName to be incomplete
                                        b := byte(0)
                                        for _, b = range d[:nameLen] {
                                                if b <= ' ' {
                                                        return protocol.ErrProtoNeedMoreData
                                                }
                                        }
                                        // An SNI value may not include a
                                        // trailing dot. See
                                        // https://tools.ietf.org/html/rfc6066#section-3.
                                        if b == '.' {
                                                return errNotClientHello
                                        }
                                        // v26.10.15-link: SNI is case-insensitive
                                        // per RFC 6066 §3. Lowercase the SNI so
                                        // downstream routers don't need to call
                                        // strings.ToLower per-rule per-connection.
                                        //
                                        // We do NOT mutate the caller's buffer
                                        // in-place (the TLS path doesn't clone
                                        // the buffer, unlike the QUIC path).
                                        // Instead we copy to a local buffer,
                                        // lowercase it, and convert to string.
                                        // The QUIC path also benefits because
                                        // it clones once at the start of
                                        // SniffQUIC, so the SNI bytes are
                                        // already in our private buffer.
                                        sniBytes := make([]byte, nameLen)
                                        copy(sniBytes, d[:nameLen])
                                        for i := range sniBytes {
                                                if sniBytes[i] >= 'A' && sniBytes[i] <= 'Z' {
                                                        sniBytes[i] += 'a' - 'A'
                                                }
                                        }
                                        h.domain = string(sniBytes)
                                        foundSNI = true
                                }
                                d = d[nameLen:]
                        }
                case extALPN:
                        d := data[:length]
                        if len(d) < 2 {
                                return errNotClientHello
                        }
                        listLen := int(d[0])<<8 | int(d[1])
                        d = d[2:]
                        if len(d) != listLen {
                                return errNotClientHello
                        }
                        // Take the first ALPN entry. Format per RFC 7301:
                        //   1 byte: protocol name length
                        //   N bytes: protocol name
                        // Repeated for each offered protocol.
                        if len(d) > 0 {
                                nameLen := int(d[0])
                                if 1+nameLen > len(d) {
                                        return errNotClientHello
                                }
                                if h.alpn == "" {
                                        h.alpn = string(d[1 : 1+nameLen])
                                }
                        }
                case extEncryptedClientHello:
                        // We can't decrypt the inner SNI without the server's
                        // ECH private key, but we can record that ECH is in use
                        // so routing can fall back to IP-based rules instead of
                        // trusting the (cover) SNI.
                        h.hasECH = true
                }
                data = data[length:]
        }

        if !foundSNI {
                // No SNI extension found in the available data.
                if truncated {
                        // v26.11.75-link: ClientHello is truncated and SNI
                        // was not in the available portion. Request more data.
                        return protocol.ErrProtoNeedMoreData
                }
                // Complete ClientHello with no SNI. If ECH was present the
                // SNI may legitimately be absent (or a cover); otherwise the
                // ClientHello is not parseable.
                if h.hasECH {
                        // ECH present without an outer SNI is valid — return
                        // success with hasECH=true and domain="". The routing
                        // layer should fall back to IP rules.
                        return nil
                }
                return errNotTLS
        }
        return nil
}

func SniffTLS(b []byte) (*SniffHeader, error) {
        if len(b) < 5 {
                return nil, common.ErrNoClue
        }

        if b[0] != 0x16 /* TLS Handshake */ {
                return nil, errNotTLS
        }
        if !IsValidTLSVersion(b[1], b[2]) {
                return nil, errNotTLS
        }
        headerLen := int(binary.BigEndian.Uint16(b[3:5]))
        if 5+headerLen > len(b) {
                return nil, common.ErrNoClue
        }

        h := &SniffHeader{}
        err := ReadClientHello(b[5:5+headerLen], h)
        if err == nil {
                return h, nil
        }
        return nil, err
}
