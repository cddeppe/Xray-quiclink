package internet

import (
        "context"
        stdnet "net"
        "sync"
        "syscall"
        "time"

        "github.com/xtls/xray-core/common/errors"
        "github.com/xtls/xray-core/common/net"
        "github.com/xtls/xray-core/features/dns"
        "github.com/xtls/xray-core/features/outbound"
)

var (
        Controllers           []func(network, address string, c syscall.RawConn) error
        ControllersLock       sync.Mutex
        effectiveSystemDialer SystemDialer = &DefaultSystemDialer{}
)

type SystemDialer interface {
        Dial(ctx context.Context, source net.Address, destination net.Destination, sockopt *SocketConfig) (net.Conn, error)
        DestIpAddress() net.IP
}

type DefaultSystemDialer struct {
        dns dns.Client
        obm outbound.Manager
}

// resolveSrcAddr builds the local address to bind for the outbound dial.
// Returns nil (let the kernel choose) when an explicit bind would fail:
//   - src is nil or a wildcard (AnyIP/AnyIPv6);
//   - dest is a loopback IP and src is a non-loopback IP (EADDRNOTAVAIL);
//   - src and dest are IPs of different families (EADDRNOTAVAIL).
// This guard is what makes sendThrough:"origin" safe for multi-IP servers:
// the listen IP is used whenever possible, and the kernel is allowed to
// pick a valid source for loopback or cross-family destinations.
func resolveSrcAddr(network net.Network, src net.Address, dest net.Destination) net.Addr {
        if src == nil || src == net.AnyIP || src == net.AnyIPv6 {
                return nil
        }
        if dest.Address.Family().IsIP() {
                if dest.Address.IP().IsLoopback() {
                        return nil
                }
                if src.Family() != dest.Address.Family() {
                        return nil
                }
        }
        if network == net.Network_TCP {
                return &net.TCPAddr{
                        IP:   src.IP(),
                        Port: 0,
                }
        }
        return &net.UDPAddr{
                IP:   src.IP(),
                        Port: 0,
        }
}

// v26.11.286: lookupKernelSource does a dummy UDP dial to the destination
// to discover the kernel's chosen source address for that route. This is
// used when resolveSrcAddr returns nil due to cross-family mismatch
// (e.g., sendThrough:"origin" is IPv4 but destination is IPv6).
//
// Without this, the socket binds to wildcard [::] and the kernel may pick
// a different source for each socket (IPv6 privacy extensions, multiple
// global IPv6 addresses). Google's replies then go to a source that doesn't
// match the socket, and the connection fails.
//
// By doing a dummy dial and binding to the discovered source, we ensure
// the socket always uses the same, correct source address that the kernel
// would route through for that destination.
func lookupKernelSource(destAddr *stdnet.UDPAddr) *stdnet.UDPAddr {
        // Use a dummy UDP dial (no actual packet sent) to find the kernel's
        // chosen source for this destination.
        conn, err := stdnet.Dial("udp", destAddr.String())
        if err != nil {
                return nil
        }
        defer conn.Close()
        localAddr, ok := conn.LocalAddr().(*stdnet.UDPAddr)
        if !ok {
                return nil
        }
        // Return a copy with port 0 (let the kernel pick the source port)
        return &stdnet.UDPAddr{
                IP:   localAddr.IP,
                Port: 0,
                Zone: localAddr.Zone,
        }
}

func (d *DefaultSystemDialer) Dial(ctx context.Context, src net.Address, dest net.Destination, sockopt *SocketConfig) (net.Conn, error) {
        errors.LogDebug(ctx, "dialing to "+dest.String())

        if dest.Network == net.Network_UDP {
                destAddr, err := net.ResolveUDPAddr("udp", dest.NetAddr())
                if err != nil {
                        return nil, err
                }
                srcAddr := resolveSrcAddr(net.Network_UDP, src, dest)
                if srcAddr == nil {
                        // v26.11.286: Before falling back to wildcard, try to discover
                        // the kernel's chosen source for this destination via a dummy
                        // dial. This fixes the IPv6 wildcard bind bug where
                        // sendThrough:"origin" is IPv4 but the destination is IPv6.
                        // Without this, the socket binds to [::] and the kernel may
                        // pick a different IPv6 source for each socket → Google's
                        // replies go to the wrong address.
                        if kernelSrc := lookupKernelSource(destAddr); kernelSrc != nil {
                                srcAddr = kernelSrc
                        } else {
                                // Fallback: wildcard bind
                                wildcard := net.AnyIP.IP()
                                if destAddr.IP.To4() == nil {
                                        wildcard = net.AnyIPv6.IP()
                                }
                                srcAddr = &net.UDPAddr{
                                        IP:   wildcard,
                                        Port: 0,
                                }
                        }
                }
                var lc net.ListenConfig
                lc.Control = func(network, address string, c syscall.RawConn) error {
                        for _, ctl := range Controllers {
                                if err := ctl(network, address, c); err != nil {
                                        errors.LogInfoInner(ctx, err, "failed to apply external controller")
                                }
                        }
                        return c.Control(func(fd uintptr) {
                                if sockopt != nil {
                                        if err := applyOutboundSocketOptions(network, destAddr.String(), fd, sockopt); err != nil {
                                                errors.LogInfo(ctx, err, "failed to apply socket options")
                                        }
                                }
                        })
                }
                packetConn, err := lc.ListenPacket(ctx, srcAddr.Network(), srcAddr.String())
                if err != nil {
                        return nil, err
                }
                return &PacketConnWrapper{
                        PacketConn: packetConn,
                        Dest:       destAddr,
                }, nil
        }
        // Chrome defaults
        keepAliveConfig := net.KeepAliveConfig{
                Enable:   true,
                Idle:     45 * time.Second,
                Interval: 45 * time.Second,
                Count:    -1,
        }
        keepAlive := time.Duration(0)
        if sockopt != nil {
                if sockopt.TcpKeepAliveIdle*sockopt.TcpKeepAliveInterval < 0 {
                        return nil, errors.New("invalid TcpKeepAliveIdle or TcpKeepAliveInterval value: ", sockopt.TcpKeepAliveIdle, " ", sockopt.TcpKeepAliveInterval)
                }
                if sockopt.TcpKeepAliveIdle < 0 || sockopt.TcpKeepAliveInterval < 0 {
                        keepAlive = -1
                        keepAliveConfig.Enable = false
                }
                if sockopt.TcpKeepAliveIdle > 0 {
                        keepAliveConfig.Idle = time.Duration(sockopt.TcpKeepAliveIdle) * time.Second
                }
                if sockopt.TcpKeepAliveInterval > 0 {
                        keepAliveConfig.Interval = time.Duration(sockopt.TcpKeepAliveInterval) * time.Second
                }
        }
        dialer := &net.Dialer{
                Timeout:         time.Second * 16,
                LocalAddr:       resolveSrcAddr(dest.Network, src, dest),
                KeepAlive:       keepAlive,
                KeepAliveConfig: keepAliveConfig,
        }

        if sockopt != nil || len(Controllers) > 0 {
                if sockopt != nil && sockopt.TcpMptcp {
                        dialer.SetMultipathTCP(true)
                }
                dialer.Control = func(network, address string, c syscall.RawConn) error {
                        for _, ctl := range Controllers {
                                if err := ctl(network, address, c); err != nil {
                                        errors.LogInfoInner(ctx, err, "failed to apply external controller")
                                }
                        }
                        return c.Control(func(fd uintptr) {
                                if sockopt != nil {
                                        if err := applyOutboundSocketOptions(network, address, fd, sockopt); err != nil {
                                                errors.LogInfoInner(ctx, err, "failed to apply socket options")
                                        }
                                }
                        })
                }
        }

        return dialer.DialContext(ctx, dest.Network.SystemString(), dest.NetAddr())
}

func (d *DefaultSystemDialer) DestIpAddress() net.IP {
        return nil
}

type PacketConnWrapper struct {
        net.PacketConn
        Dest net.Addr
}

func (c *PacketConnWrapper) Read(p []byte) (int, error) {
        n, _, err := c.PacketConn.ReadFrom(p)
        return n, err
}

func (c *PacketConnWrapper) Write(p []byte) (int, error) {
        return c.PacketConn.WriteTo(p, c.Dest)
}

func (c *PacketConnWrapper) RemoteAddr() net.Addr {
        return c.Dest
}

type SystemDialerAdapter interface {
        Dial(network string, address string) (net.Conn, error)
}

type SimpleSystemDialer struct {
        adapter SystemDialerAdapter
}

func WithAdapter(dialer SystemDialerAdapter) SystemDialer {
        return &SimpleSystemDialer{
                adapter: dialer,
        }
}

func (v *SimpleSystemDialer) Dial(ctx context.Context, src net.Address, dest net.Destination, sockopt *SocketConfig) (net.Conn, error) {
        return v.adapter.Dial(dest.Network.SystemString(), dest.NetAddr())
}

func (d *SimpleSystemDialer) DestIpAddress() net.IP {
        return nil
}

// UseAlternativeSystemDialer replaces the current system dialer with a given one.
// Caller must ensure there is no race condition.
//
// xray:api:stable
func UseAlternativeSystemDialer(dialer SystemDialer) {
        if dialer == nil {
                dialer = &DefaultSystemDialer{}
        }
        effectiveSystemDialer = dialer
}

// RegisterDialerController adds a controller to the effective system dialer.
// The controller can be used to operate on file descriptors before they are put into use.
// It only works when effective dialer is the default dialer.
//
// xray:api:beta
func RegisterDialerController(ctl func(network, address string, c syscall.RawConn) error) error {
        if ctl == nil {
                return errors.New("nil listener controller")
        }

        ControllersLock.Lock()
        Controllers = append(Controllers, ctl)
        ControllersLock.Unlock()

        _, ok := effectiveSystemDialer.(*DefaultSystemDialer)
        if !ok {
                return errors.New("RegisterListenerController not supported in custom dialer")
        }

        return nil
}

type FakePacketConn struct {
        net.Conn
}

func (c *FakePacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
        n, err = c.Read(p)
        return n, &net.UDPAddr{IP: c.Conn.RemoteAddr().(*net.TCPAddr).IP, Port: c.Conn.RemoteAddr().(*net.TCPAddr).Port}, err
}

func (c *FakePacketConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
        return c.Write(p)
}

func (c *FakePacketConn) LocalAddr() net.Addr {
        return &net.UDPAddr{IP: []byte{0, 0, 0, 0}}
}
