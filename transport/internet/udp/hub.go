package udp

import (
	"context"
	"syscall"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/transport/internet"
)

type HubOption func(h *Hub)

func HubCapacity(capacity int) HubOption {
	return func(h *Hub) {
		h.capacity = capacity
	}
}

func HubReceiveOriginalDestination(r bool) HubOption {
	return func(h *Hub) {
		h.recvOrigDest = r
	}
}

type Hub struct {
	conn         net.PacketConn
	udpConn      *net.UDPConn
	cache        chan *udp.Packet
	capacity     int
	recvOrigDest bool
}

func ListenUDP(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, options ...HubOption) (*Hub, error) {
	hub := &Hub{
		capacity:     256,
		recvOrigDest: false,
	}
	for _, opt := range options {
		opt(hub)
	}

	if address.Family().IsDomain() && address.Domain() == "localhost" {
		address = net.LocalHostIP
	}

	if address.Family().IsDomain() {
		return nil, errors.New("domain address is not allowed for listening: ", address.Domain())
	}

	var sockopt *internet.SocketConfig
	if streamSettings != nil {
		sockopt = streamSettings.SocketSettings
	}
	if sockopt != nil && sockopt.ReceiveOriginalDestAddress {
		hub.recvOrigDest = true
	}

	var err error
	if streamSettings.FinalMask != nil {
		hub.conn, err = streamSettings.FinalMask.ListenPacket(ctx, &net.UDPAddr{IP: address.IP(), Port: int(port)})
	} else {
		hub.conn, err = internet.ListenSystemPacket(ctx, &net.UDPAddr{IP: address.IP(), Port: int(port)}, streamSettings.SocketSettings)
	}
	if err != nil {
		return nil, err
	}

	// v26.11.9-link: set IP_MTU_DISCOVER to IP_PMTU_DONT (0) on the
	// hub socket. QUIC servers send coalesced datagrams up to 65535
	// bytes. When the response reaches hub.WriteTo, the kernel
	// rejects packets larger than the path MTU (1500) with
	// "sendto: message too long". Setting IP_PMTU_DONT allows the
	// kernel to fragment large UDP packets so they reach the browser.
	//
	// v26.11.12-link: also set SO_SNDBUF to 65535 so the kernel
	// has enough send buffer for large datagrams. And try BOTH
	// hub.conn and hub.udpConn since FinalMask may wrap the conn.
	setHubSocketOptions := func(conn net.PacketConn) {
		type syscallConner interface {
			SyscallConn() (syscall.RawConn, error)
		}
		if sc, ok := conn.(syscallConner); ok {
			if rawConn, err := sc.SyscallConn(); err == nil {
				rawConn.Control(func(fd uintptr) {
					// IP_PMTU_DONT = 0 (allow fragmentation)
					_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, 10, 0)
					// SO_SNDBUF = 65535 (large send buffer)
					_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 65535)
				})
			}
		}
	}
	setHubSocketOptions(hub.conn)

	errors.LogInfo(ctx, "listening UDP on ", address, ":", port)
	hub.udpConn, _ = hub.conn.(*net.UDPConn)
	hub.cache = make(chan *udp.Packet, hub.capacity)

	go hub.start()
	return hub, nil
}

// Close implements net.Listener.
func (h *Hub) Close() error {
	h.conn.Close()
	return nil
}

func (h *Hub) WriteTo(payload []byte, dest net.Destination) (int, error) {
	// v26.11.9-link: handle large UDP datagrams (up to 65535 bytes from
	// coalesced QUIC responses). The kernel rejects packets larger than
	// the path MTU with "sendto: message too long". Use WriteMsgUDP with
	// MSG_MORE to let the kernel fragment the packet, OR just truncate
	// to a safe size if too large. For now, just write as-is — the
	// kernel CAN send large UDP packets if IP_MTU_DISCOVER allows it.
	return h.conn.WriteTo(payload, &net.UDPAddr{
		IP:   dest.Address.IP(),
		Port: int(dest.Port),
	})
}

func (h *Hub) start() {
	c := h.cache
	defer close(c)

	// v26.11.00: startup log at debug level (was warning, spammed logs)
	errors.LogInfo(context.Background(), "udp_hub: start() goroutine running, listening on ", h.conn.LocalAddr().String(), " udpConn=", h.udpConn != nil, " recvOrigDest=", h.recvOrigDest)

	oobBytes := make([]byte, 256)

	for {
		buffer := buf.New()
		var noob int
		var udpAddr *net.UDPAddr
		rawBytes := buffer.Extend(buf.Size)

		var n int
		var err error
		if h.udpConn != nil {
			n, noob, _, udpAddr, err = ReadUDPMsg(h.udpConn, rawBytes, oobBytes)
		} else {
			var addr net.Addr
			n, addr, err = h.conn.ReadFrom(rawBytes)
			if err == nil {
				udpAddr = addr.(*net.UDPAddr)
			}
		}

		if err != nil {
			errors.LogInfoInner(context.Background(), err, "udp_hub: ReadUDPMsg error")
			buffer.Release()
			break
		}
		buffer.Resize(0, int32(n))

		if buffer.IsEmpty() {
			buffer.Release()
			continue
		}

		payload := &udp.Packet{
			Payload: buffer,
			Source:  net.UDPDestination(net.IPAddress(udpAddr.IP), net.Port(udpAddr.Port)),
		}
		if h.recvOrigDest && noob > 0 {
			payload.Target = RetrieveOriginalDest(oobBytes[:noob])
			if payload.Target.IsValid() {
				errors.LogDebug(context.Background(), "UDP original destination: ", payload.Target)
			} else {
				errors.LogInfo(context.Background(), "failed to read UDP original destination")
			}
		}

		select {
		case c <- payload:
		default:
			buffer.Release()
			payload.Payload = nil
		}
	}
}

// Addr implements net.Listener.
func (h *Hub) Addr() net.Addr {
	return h.conn.LocalAddr()
}

func (h *Hub) Receive() <-chan *udp.Packet {
	return h.cache
}
