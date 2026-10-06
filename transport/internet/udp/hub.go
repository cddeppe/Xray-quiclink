package udp

import (
	"context"
	"fmt"
	stdnet "net"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/sys/unix"
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

	// v26.11.12-link: set IP_MTU_DISCOVER=IP_PMTUDISC_DONT and
	// SO_SNDBUF=65535 on the hub socket. QUIC servers coalesce
	// Initial+Handshake+0-RTT into one UDP datagram up to 65535
	// bytes. Without these options, the kernel rejects the send
	// with "sendto: message too long" because the packet is larger
	// than the path MTU (1500).
	//
	// IP_PMTUDISC_DONT (0) = don't set DF flag, allow IP fragmentation.
	// SO_SNDBUF (65535) = large send buffer for big datagrams.
	//
	// Previous attempt (v26.11.9) used syscall package constants
	// which may not have matched. This version uses golang.org/x/sys/unix
	// which is guaranteed correct for the platform.
	if udpConn, ok := hub.conn.(*stdnet.UDPConn); ok {
		errors.LogWarning(context.Background(), "udp_hub: setting IP_MTU_DISCOVER and SO_SNDBUF on hub socket")
		if rawConn, err := udpConn.SyscallConn(); err == nil {
			rawConn.Control(func(fd uintptr) {
				// IP_MTU_DISCOVER = IP_PMTUDISC_DONT (0) = allow fragmentation
				if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, 0); err != nil {
					errors.LogWarning(context.Background(), "udp_hub: failed to set IP_MTU_DISCOVER: ", err)
				}
				// SO_SNDBUF = 65535
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, 65535); err != nil {
					errors.LogWarning(context.Background(), "udp_hub: failed to set SO_SNDBUF: ", err)
				}
			})
		} else {
			errors.LogWarning(context.Background(), "udp_hub: failed to get SyscallConn: ", err)
		}
	} else {
		errors.LogWarning(context.Background(), "udp_hub: conn is not *net.UDPConn, type=", fmt.Sprintf("%T", hub.conn))
	}

	errors.LogInfo(ctx, "listening UDP on ", address, ":", port)
	hub.udpConn, _ = hub.conn.(*stdnet.UDPConn)
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
