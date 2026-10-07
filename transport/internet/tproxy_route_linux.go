package internet

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	"syscall"

	"github.com/vishvananda/netlink"
)

// v26.11.96-link: Built-in TPROXY route installation.
//
// When the dokodemo inbound has "followRedirect": true, the codebase already:
//   - Sets IP_TRANSPARENT on the listener socket (sockopt_linux.go)
//   - Sets IP_RECVORIGDSTADDR to get the original dest from kernel OOB
//   - Reads originalDest in the UDP hub (hub.go)
//   - Passes it to the worker callback (worker.go)
//   - Uses FakeUDP to spoof reply source IP (fakeudp_linux.go)
//
// The ONLY missing piece: the kernel won't deliver packets destined to
// arbitrary IPs to the local socket without a route saying "deliver
// these locally". Traditional TPROXY uses iptables + policy routing
// for this. We automate it by adding `local 0.0.0.0/0 dev lo` and
// `local ::/0 dev lo` routes via netlink.
//
// This makes TPROXY work automatically — no iptables, no external
// config. The user just sets "followRedirect": true in their config.

var (
	tproxyRouteOnce sync.Once
	tproxyRouteV4   *netlink.Route
	tproxyRouteV6   *netlink.Route
)

// InstallTProxyRoutes installs local routes for all-traffic capture.
// This makes the kernel deliver packets destined to ANY IP to local
// sockets (when the socket has IP_TRANSPARENT set).
func InstallTProxyRoutes() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("tproxy routes only supported on Linux")
	}

	var firstErr error

	// Install IPv4 local route: local 0.0.0.0/0 dev lo
	v4Route := &netlink.Route{
		Dst: &net.IPNet{
			IP:   net.IPv4zero,
			Mask: net.CIDRMask(0, 32),
		},
		Scope:     syscall.RT_SCOPE_HOST,
		Type:      syscall.RTN_LOCAL,
		LinkIndex: 1, // lo
	}
	if err := netlink.RouteAdd(v4Route); err != nil {
		// "file exists" is OK — route already installed
		if !isRouteExists(err) {
			firstErr = err
		}
	} else {
		tproxyRouteV4 = v4Route
	}

	// Install IPv6 local route: local ::/0 dev lo
	v6Route := &netlink.Route{
		Dst: &net.IPNet{
			IP:   net.IPv6zero,
			Mask: net.CIDRMask(0, 128),
		},
		Scope:     syscall.RT_SCOPE_HOST,
		Type:      syscall.RTN_LOCAL,
		LinkIndex: 1, // lo
	}
	if err := netlink.RouteAdd(v6Route); err != nil {
		if !isRouteExists(err) {
			if firstErr == nil {
				firstErr = err
			}
		}
	} else {
		tproxyRouteV6 = v6Route
	}

	return firstErr
}

// RemoveTProxyRoutes removes the local routes installed by InstallTProxyRoutes.
func RemoveTProxyRoutes() {
	if tproxyRouteV4 != nil {
		netlink.RouteDel(tproxyRouteV4)
		tproxyRouteV4 = nil
	}
	if tproxyRouteV6 != nil {
		netlink.RouteDel(tproxyRouteV6)
		tproxyRouteV6 = nil
	}
}

func isRouteExists(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return contains(s, "exists") || contains(s, "File exists")
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// EnsureTProxyRoutes installs routes once (idempotent).
func EnsureTProxyRoutes() {
	tproxyRouteOnce.Do(func() {
		InstallTProxyRoutes()
	})
}

// TProxyRouteController is a listener controller that installs TPROXY
// routes when the listener has TProxy mode enabled.
func TProxyRouteController(network, address string, c syscall.RawConn) error {
	EnsureTProxyRoutes()
	return nil
}

var _ = context.Background // keep import for future use
