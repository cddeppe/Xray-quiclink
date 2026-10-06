package buf

import (
	"github.com/xtls/xray-core/common/net"
)

type EndpointOverrideReader struct {
	Reader
	Dest         net.Address
	OriginalDest net.Address
}

func (r *EndpointOverrideReader) ReadMultiBuffer() (MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	if err == nil {
		for _, b := range mb {
			if b.UDP != nil && b.UDP.Address == r.OriginalDest {
				b.UDP.Address = r.Dest
			}
		}
	}
	return mb, err
}

type EndpointOverrideWriter struct {
	Writer
	Dest         net.Address
	OriginalDest net.Address
}

// v26.10.74-link: rewrite UDP response source address unconditionally.
//
// The previous conditional `b.UDP.Address == w.Dest` was structurally
// broken: w.Dest is set at handler.go:204-205 to ob.Target.Address,
// which after QUIC sniffing override (default.go:378,390) is a
// domainAddress (the sniffed SNI like "youtube.com"). Meanwhile
// PacketReader/PooledPacketReader set b.UDP.Address to an
// ipv4Address/ipv6Address (the server's reply source IP). Go's
// interface == requires both the same concrete type AND value, so
// an ipv4Address == domainAddress comparison is ALWAYS false. The
// rewrite never fired, the dokodemo FakeUDP socket bound to the
// server's reply IP instead of the original IP the client expected,
// and the client's kernel silently dropped the response (UDP
// source-IP mismatch security feature). The QUIC handshake never
// completed; clients fell back to TCP/HTTP2.
//
// Why unconditional rewrite is correct:
//   1. The writer is only created at handler.go:203-205 when
//      `ob.OriginalTarget.Address != ob.Target.Address` — i.e., only
//      when the destination was actually overridden by sniffing.
//      If override didn't happen, no rewrite is needed and the
//      writer isn't created.
//   2. When override DID happen, ALL response packets must have
//      their source address rewritten back to OriginalDest (the IP
//      the client expected). The client's QUIC socket was connect()ed
//      to OriginalDest, so any other source IP gets dropped by the
//      kernel.
//   3. The unconditional rewrite also handles QUIC connection
//      migration, where the server may reply from a different IP
//      than the one freedom originally dialed. The conditional
//      version would have missed these; unconditional rewrite covers
//      them correctly.
func (w *EndpointOverrideWriter) WriteMultiBuffer(mb MultiBuffer) error {
	for _, b := range mb {
		if b.UDP != nil {
			b.UDP.Address = w.OriginalDest
		}
	}
	return w.Writer.WriteMultiBuffer(mb)
}
