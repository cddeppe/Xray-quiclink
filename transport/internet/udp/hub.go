package udp

import (
	"context"

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
	return h.conn.WriteTo(payload, &net.UDPAddr{
		IP:   dest.Address.IP(),
		Port: int(dest.Port),
	})
}

func (h *Hub) start() {
	c := h.cache
	defer close(c)

	// v26.10.77-link: confirm the hub.start() goroutine is actually
	// running. If this line doesn't fire on startup, the goroutine
	// never started (ListenUDP returned nil, or the channel was
	// never created).
	errors.LogWarning(context.Background(), "udp_hub: start() goroutine running, listening on ", h.conn.LocalAddr().String(), " udpConn=", h.udpConn != nil, " recvOrigDest=", h.recvOrigDest)

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
			errors.LogWarning(context.Background(), "udp_hub: ReadUDPMsg returned err=", err, " udpConn=", h.udpConn != nil)
			buffer.Release()
			break
		}
		buffer.Resize(0, int32(n))

		if buffer.IsEmpty() {
			buffer.Release()
			continue
		}

		// v26.10.76-link: diagnostic — confirm the UDP socket is actually
		// receiving packets. This fires inside the hub's start() loop,
		// BEFORE the channel send. If this fires but udp_worker: callback
		// doesn't, the channel is dropping packets or handlePackets isn't
		// running. If this doesn't fire, the socket isn't receiving.
		errors.LogWarning(context.Background(), "udp_hub: received src=", udpAddr.String(), " len=", n, " recvOrigDest=", h.recvOrigDest)

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
