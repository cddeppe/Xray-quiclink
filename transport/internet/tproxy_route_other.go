//go:build !linux

package internet

// InstallTProxyRoutes is a no-op on non-Linux.
func InstallTProxyRoutes() error { return nil }

// RemoveTProxyRoutes is a no-op on non-Linux.
func RemoveTProxyRoutes() {}

// EnsureTProxyRoutes is a no-op on non-Linux.
func EnsureTProxyRoutes() {}

// TProxyRouteController is a no-op on non-Linux.
func TProxyRouteController(network, address string, c interface{}) error { return nil }
