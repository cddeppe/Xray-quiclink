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

func (w *EndpointOverrideWriter) WriteMultiBuffer(mb MultiBuffer) error {
        for _, b := range mb {
                if b.UDP != nil {
                        // v26.10.74-link: unconditional rewrite. The comparison
                        // b.UDP.Address == w.Dest compares an ipv4Address (from
                        // the server reply) to a domainAddress (from SNI sniffing).
                        // In Go, interface == requires both the same concrete type
                        // AND value — different types are always false. So the
                        // rewrite never fired. Unconditional is safe because the
                        // writer only exists when override happened.
                        b.UDP.Address = w.OriginalDest
                }
        }
        return w.Writer.WriteMultiBuffer(mb)
}
