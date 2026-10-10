package freedom

import (
        "context"
        "crypto/rand"
        stderrors "errors"
        "fmt"
        "io"
        stdnet "net"
        "strings"
        "sync/atomic"
        "syscall"
        "time"

        "github.com/pires/go-proxyproto"
        "github.com/xtls/xray-core/common"
        "github.com/xtls/xray-core/common/buf"
        "github.com/xtls/xray-core/common/crypto"
        "github.com/xtls/xray-core/common/dice"
        "github.com/xtls/xray-core/common/errors"
        "github.com/xtls/xray-core/common/geodata"
        "github.com/xtls/xray-core/common/net"
        "github.com/xtls/xray-core/common/platform"
        "github.com/xtls/xray-core/common/protocol/quic"
        "github.com/xtls/xray-core/common/retry"
        "github.com/xtls/xray-core/common/session"
        "github.com/xtls/xray-core/common/signal"
        "github.com/xtls/xray-core/common/task"
        "github.com/xtls/xray-core/common/utils"
        "github.com/xtls/xray-core/core"
        "github.com/xtls/xray-core/features/policy"
        "github.com/xtls/xray-core/features/stats"
        "github.com/xtls/xray-core/proxy"
        "github.com/xtls/xray-core/proxy/freedom/udptimeout"
        "github.com/xtls/xray-core/transport"
        "github.com/xtls/xray-core/transport/internet"
        "github.com/xtls/xray-core/transport/internet/stat"
)

var (
        useSplice               atomic.Bool
        allNetworks             [8]bool
        defaultBlockPrivateRule *FinalRule
        defaultBlockAllRule     *FinalRule
)

func secondsOrDefault(v, def uint32) uint32 {
        if v > 0 {
                return v
        }
        return def
}

func reloadEnvSettings() error {
        const defaultFlagValue = "NOT_DEFINED_AT_ALL"
        value := platform.NewEnvFlag(platform.UseFreedomSplice).GetValue(func() string { return defaultFlagValue })
        enabled := false
        switch value {
        case defaultFlagValue, "auto", "enable":
                enabled = true
        }
        useSplice.Store(enabled)
        return nil
}

func init() {
        common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
                h := new(Handler)
                if streamSettings, ok := session.StreamSettingsFromContext(ctx).(*internet.MemoryStreamConfig); ok && streamSettings.SocketSettings != nil {
                        h.resolveStrategy = streamSettings.SocketSettings.DomainStrategy
                        h.usesDialerProxy = len(streamSettings.SocketSettings.DialerProxy) > 0
                        h.socketConfig = streamSettings.SocketSettings // v26.10.17-link
                }
                if err := core.RequireFeatures(ctx, func(pm policy.Manager) error {
                        return h.Init(config.(*Config), pm)
                }); err != nil {
                        return nil, err
                }
                return h, nil
        }))

        platform.RegisterEnvReload(reloadEnvSettings)

        for i := range allNetworks {
                allNetworks[i] = true
        }

        defaultBlockPrivateRule = &FinalRule{
                action:  RuleAction_Block,
                network: allNetworks,
                ip:      geodata.GetPrivateIPMatcher(),
        }

        defaultBlockAllRule = &FinalRule{
                action:  RuleAction_Block,
                network: allNetworks,
        }
}

type FinalRule struct {
        action     RuleAction
        network    [8]bool
        port       net.MemoryPortList
        ip         geodata.IPMatcher
        blockDelay *Range
}

// Handler handles Freedom connections.
type Handler struct {
        policyManager   policy.Manager
        config          *Config
        finalRules      []*FinalRule
        resolveStrategy internet.DomainStrategy
        usesDialerProxy bool
        socketPool      *UDPSocketPool
        stickyResolver  *StickyResolver
        // v26.10.44-link: TCP warm-pool for connection reuse.
        tcpWarmPool     *TCPSocketPool
        // v26.10.17-link: sockopt config from freedom outbound's streamSettings.
        socketConfig *internet.SocketConfig
}

func buildFinalRule(config *FinalRuleConfig) (*FinalRule, error) {
        rule := &FinalRule{
                action:     config.GetAction(),
                blockDelay: config.GetBlockDelay(),
        }

        if len(config.Networks) == 0 {
                rule.network = allNetworks
        } else {
                for _, network := range config.Networks {
                        rule.network[int(network)] = true
                }
        }

        if config.PortList != nil {
                rule.port = net.PortListFromProto(config.PortList)
        }

        if len(config.Ip) > 0 {
                matcher, err := geodata.IPReg.BuildIPMatcher(config.Ip)
                if err != nil {
                        return nil, err
                }
                rule.ip = matcher
        }

        return rule, nil
}

func (r *FinalRule) matchNetwork(network net.Network) bool {
        return r.network[int(network)]
}

func (r *FinalRule) matchPort(port net.Port) bool {
        if len(r.port) == 0 {
                return true
        }
        return r.port.Contains(port)
}

func (r *FinalRule) matchIP(addr net.Address) bool {
        if r.ip == nil {
                return true
        }
        return addr != nil && addr.Family().IsIP() && r.ip.Match(addr.IP())
}

func (r *FinalRule) Apply(network net.Network, address net.Address, port net.Port) bool {
        if !r.matchNetwork(network) {
                return false
        }
        if !r.matchPort(port) {
                return false
        }
        return r.matchIP(address)
}

func getDefaultFinalRule(inbound *session.Inbound) *FinalRule {
        if inbound == nil {
                return nil
        }
        switch inbound.Name {
        case "vless-reverse":
                return defaultBlockAllRule
        case "vless", "vmess", "trojan", "hysteria", "wireguard":
                return defaultBlockPrivateRule
        default:
                if strings.HasPrefix(inbound.Name, "shadowsocks") {
                        return defaultBlockPrivateRule
                }
        }
        return nil
}

func (h *Handler) matchFinalRule(network net.Network, address net.Address, port net.Port, defaultRule *FinalRule) *FinalRule {
        for _, rule := range h.finalRules {
                if rule.Apply(network, address, port) {
                        return rule
                }
        }
        if defaultRule != nil && defaultRule.Apply(network, address, port) {
                return defaultRule
        }
        return nil
}

// Init initializes the Handler with necessary parameters.
func (h *Handler) Init(config *Config, pm policy.Manager) error {
        h.config = config
        h.policyManager = pm

        // Initialize UDP features from config
        if config.UdpConfig != nil {
                // v26.10.34-link (M4 fix): close old instances before replacing.
                // Without this, every SIGHUP reload leaks one reaper goroutine +
                // one time.Ticker per outbound (StickyResolver.reaper,
                // UDPSocketPool.reaper). Over weeks of daily reloads this
                // accumulates hundreds of zombie reapers.
                if h.socketPool != nil {
                        h.socketPool.Close()
                        h.socketPool = nil
                }
                if h.stickyResolver != nil {
                        h.stickyResolver.Close()
                        h.stickyResolver = nil
                }
                if h.tcpWarmPool != nil {
                        h.tcpWarmPool.Close()
                        h.tcpWarmPool = nil
                }

                // v26.10.34-link (M8 fix): gate the global udptimeout mutation
                // behind EnableSocketPool. Without this, multiple freedom
                // outbounds (e.g. direct + wg) fight over the global — last
                // Init wins, silently overriding the others.
                if config.UdpConfig.EnableSocketPool {
                        udptimeout.SetSessionIdleSeconds(int64(config.UdpConfig.GetSessionIdleTimeout()))
                }

                if config.UdpConfig.EnableSocketPool {
                        staleness := secondsOrDefault(config.UdpConfig.GetPoolStalenessTimeout(), 300)
                        idle := secondsOrDefault(config.UdpConfig.GetPoolIdleTimeout(), 600)
                        unused := secondsOrDefault(config.UdpConfig.GetPoolUnusedTimeout(), 300)
                        h.socketPool = NewUDPSocketPool(
                                time.Duration(staleness)*time.Second,
                                time.Duration(idle)*time.Second,
                                time.Duration(unused)*time.Second,
                                h.socketConfig, // v26.10.17-link: pass sockopt for interface binding
                        )
                        errors.LogWarning(context.Background(), "freedom: UDP socket pool enabled (staleness=", staleness, "s idle=", idle, "s unused=", unused, "s)")
                } else {
                        // v26.11.198: Explicitly log when the pool is NOT enabled.
                        // This helps diagnose why video stalls — without the pool,
                        // each QUIC connection gets its own outbound socket.
                        errors.LogWarning(context.Background(), "freedom: UDP socket pool DISABLED (enableSocketPool=false)")
                }
                if config.UdpConfig.EnableStickyResolver {
                        // v26.10.23-link: configurable sticky resolver TTL.
                        stickyTtl := secondsOrDefault(config.UdpConfig.GetStickyResolverTtl(), 300)
                        h.stickyResolver = NewStickyResolver(time.Duration(stickyTtl) * time.Second)
                        h.stickyResolver.PreferIPv4 = config.UdpConfig.PreferIpv4
                        h.stickyResolver.PreferIPv6 = config.UdpConfig.PreferIpv6
                        // v26.10.27-link: when resolver gets a new IP, invalidate
                        // pool sockets to the old IP so new connections use the
                        // fresh IP immediately (closes the TTL/staleness gap).
                        if h.socketPool != nil {
                                pool := h.socketPool
                                h.stickyResolver.onIPChanged = func(oldIP, _ string) {
                                        pool.InvalidateByIP(oldIP)
                                }
                        }
                        errors.LogWarning(context.Background(), "freedom: UDP sticky resolver enabled (TTL=", stickyTtl, "s PreferIPv4:", config.UdpConfig.PreferIpv4, "PreferIPv6:", config.UdpConfig.PreferIpv6, ")")
                }

                // v26.10.44-link: TCP warm-pool initialization
                if config.UdpConfig.GetEnableTcpWarmPool() {
                        warmTimeout := secondsOrDefault(config.UdpConfig.GetTcpWarmPoolTimeout(), 5)
                        preWarmN := int(config.UdpConfig.GetPreWarmCount())
                        preWarmFirstN := int(config.UdpConfig.GetPreWarmFirstN())
                        learnVisits := int(config.UdpConfig.GetPreWarmLearnVisits())
                        if learnVisits == 0 {
                                learnVisits = 3 // default: 3 visits to stabilize
                        }
                        h.tcpWarmPool = NewTCPSocketPool(time.Duration(warmTimeout)*time.Second, preWarmN, preWarmFirstN, learnVisits)
                        if preWarmFirstN > 0 {
                                errors.LogWarning(context.Background(), "freedom: TCP warm pool enabled (timeout=", warmTimeout, "s firstN=", preWarmFirstN, " learnVisits=", learnVisits, ")")
                        } else if preWarmN > 0 {
                                errors.LogWarning(context.Background(), "freedom: TCP warm pool enabled (timeout=", warmTimeout, "s preWarm=", preWarmN, ")")
                        } else {
                                errors.LogWarning(context.Background(), "freedom: TCP warm pool enabled (timeout=", warmTimeout, "s)")
                        }
                }
        }

        if h.usesDialerProxy { // freedom is not the final outbound, final rules do not apply
                if len(config.FinalRules) > 0 {
                        errors.LogWarning(context.Background(), `The "finalRules" setting is ignored when "sockopt.dialerProxy" is set, since freedom is not the final outbound.`)
                }
                return nil
        }
        h.finalRules = make([]*FinalRule, 0, len(config.FinalRules))
        for _, rc := range config.FinalRules {
                rule, err := buildFinalRule(rc)
                if err != nil {
                        return errors.New("failed to build final rule").Base(err)
                }
                h.finalRules = append(h.finalRules, rule)
        }

        return nil
}

func (h *Handler) policy() policy.Session {
        p := h.policyManager.ForLevel(h.config.UserLevel)
        return p
}

func (h *Handler) blockDelay(rule *FinalRule) time.Duration {
        min := uint64(30)
        max := uint64(90)
        if rule.blockDelay != nil {
                min = rule.blockDelay.Min
                max = rule.blockDelay.Max
        }
        span := max - min
        if max < min {
                span = min - max
        }
        return time.Duration(min+uint64(dice.Roll(int(span+1)))) * time.Second
}

func (h *Handler) blackhole(ctx context.Context, input buf.Reader, output buf.Writer, rule *FinalRule, dest *net.Destination) error {
        delay := h.blockDelay(rule)
        errors.LogInfo(ctx, "blocked target: ", *dest, ", blackholing connection for ", delay)
        timer := time.AfterFunc(delay, func() {
                common.Interrupt(input)
                common.Interrupt(output)
                errors.LogInfo(ctx, "closed blackholed connection to blocked target: ", *dest)
        })
        defer timer.Stop()
        defer common.Close(output)
        _ = buf.Copy(input, buf.Discard)
        return nil
}

func isValidAddress(addr *net.IPOrDomain) bool {
        if addr == nil {
                return false
        }

        a := addr.AsAddress()
        return a != net.AnyIP && a != net.AnyIPv6
}

// isNetworkUnreachable returns true if the error indicates the
// network is unreachable (ENETUNREACH). This covers both connect
// failures (IPv6 gateway down) and write failures (gateway can't
// route). Used for automatic IPv6 to IPv4 fallback.
//
// v26.10.31-link: simplified from v26.10.30's isNetworkUnreachableOnV6
// to not require checking the destination — just the error.
func isNetworkUnreachable(err error) bool {
        if err == nil {
                return false
        }
        var errno syscall.Errno
        if stderrors.As(err, &errno) {
                return errno == syscall.ENETUNREACH
        }
        return strings.Contains(err.Error(), "network is unreachable")
}

// Process implements proxy.Outbound.
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
        outbounds := session.OutboundsFromContext(ctx)
        ob := outbounds[len(outbounds)-1]
        if !ob.Target.IsValid() {
                return errors.New("target not specified.")
        }
        ob.Name = "freedom"
        ob.CanSpliceCopy = 1
        inbound := session.InboundFromContext(ctx)
        var defaultRule *FinalRule
        if !h.usesDialerProxy { // freedom is not the final outbound, final rules do not apply (and the domain is not resolved)
                defaultRule = getDefaultFinalRule(inbound)
        }

        destination := ob.Target
        origTargetAddr := ob.OriginalTarget.Address
        if origTargetAddr == nil {
                origTargetAddr = ob.Target.Address
        }
        // Always call SetOutboundGateway so sendThrough is honored for TCP and
        // for non-QUIC UDP fallback. For QUIC UDP that uses the pool, outGateway
        // is cleared after the pool peek (see below) so the pool's wildcard-bound
        // sockets are used (DCID demuxing requires a single socket per destination).
        dialer.SetOutboundGateway(ctx, ob)
        outGateway := ob.Gateway
        UDPOverride := net.UDPDestination(nil, 0)
        if h.config.DestinationOverride != nil {
                server := h.config.DestinationOverride.Server
                if isValidAddress(server.Address) {
                        destination.Address = server.Address.AsAddress()
                        UDPOverride.Address = destination.Address
                }
                if server.Port != 0 {
                        destination.Port = net.Port(server.Port)
                        UDPOverride.Port = destination.Port
                }
        }

        input := link.Reader
        output := link.Writer

        // v26.10.37-link: inputCloser propagates EOF from outbound→inbound.
        // When the remote peer (e.g. YouTube) closes the outbound TCP, we
        // must close the inbound input pipe too — otherwise requestDone's
        // buf.Copy(input, writer) waits forever for an EOF that never comes,
        // the inbound TCP socket sits in CLOSE-WAIT for up to connIdle (30 min),
        // and the phone's HTTP/2 pool keeps trying to use the dead connection,
        // causing "every 20th swipe" stalls on YouTube Shorts.
        //
        // OnSuccess(responseDone, task.Close(output)) already closes the
        // inbound pipe's writer (so the phone eventually gets EOF on its
        // response side), but the reader side (input) is what requestDone
        // blocks on. We close input here so requestDone also unblocks and
        // task.Run returns, which then lets the inbound worker call
        // conn.Close() and tear down the TCP socket cleanly.
        inputCloser := make(chan struct{})
        go func() {
                <-inputCloser
                common.Interrupt(input)
        }()

        // Sticky UDP DNS: if enabled and destination is a domain, pre-resolve to
        // a consistent IP for this hostname. This prevents IPv4/IPv6 flipping
        // across flows to the same hostname, which can cause destination servers
        // (e.g., YouTube CDN) to reject requests due to source IP mismatch in
        // their validated URLs.
        //
        // v26.10.39-link: reverted the v26.10.37 extension to TCP. Empirically,
        // sticky-TCP caused YouTube 400 Bad Request on video segment fetches
        // after a video finished playing. The v26.10.38 ErrClosedPipe swallow
        // (which fixed the data-loss race) was not sufficient — there is
        // another failure path that we could not pinpoint. Reverting to
        // UDP-only sticky restores v26.10.36's working behavior. The CLOSE-WAIT
        // fix (inputCloser) and tcpKeepAlive alias are kept; both are
        // independent of the sticky-TCP change.
        if destination.Network != net.Network_TCP && destination.Address.Family().IsDomain() && h.stickyResolver != nil {
                if stickyIP, err := h.stickyResolver.Resolve(ctx, destination.Address.Domain()); err == nil {
                        destination.Address = stickyIP
                        if UDPOverride.Address != nil && UDPOverride.Address.Family().IsDomain() {
                                UDPOverride.Address = stickyIP
                        }
                } else {
                        errors.LogInfoInner(ctx, err, "sticky: pre-resolve failed, falling back to normal resolution")
                }
        }

        var conn stat.Connection
        var warmAcquired bool // v26.10.44-link: track if conn came from warm pool
        // v26.10.44-link: try the TCP warm pool before dialing. Only for TCP
        // destinations. The destination address has already been resolved by
        // the sticky resolver (if enabled), so the warm pool key matches the
        // actual IP:port the dialer would have used.
        if destination.Network == net.Network_TCP && h.tcpWarmPool != nil {
                // v26.10.45-link: provide the dialer to the warm pool for
                // pre-warming. Set once — the dialer is the same for all
                // Process calls on this handler.
                h.tcpWarmPool.SetDialFunc(func(ctx context.Context, dest net.Destination) (stat.Connection, error) {
                        return dialer.Dial(ctx, dest)
                })
                if warmConn := h.tcpWarmPool.Acquire(destination); warmConn != nil {
                        if warmConn.RemoteAddr() != nil {
                                conn = warmConn
                                warmAcquired = true
                                errors.LogInfo(ctx, "tcp warm pool: reused connection to ", destination)
                        } else {
                                warmConn.Close()
                        }
                }
        }
        var blockedDest *net.Destination
        var blockedRule *FinalRule
        err := retry.ExponentialBackoff(5, 100).On(func() error {
                if destination.Address.Family().IsDomain() {
                        if defaultRule != nil || len(h.finalRules) > 0 {
                                if strategy := h.resolveStrategy; strategy.HasStrategy() {
                                        ips, err := internet.LookupForIP(destination.Address.Domain(), strategy, outGateway)
                                        if err != nil { // non-force may still dial with system DNS
                                                errors.LogInfoInner(ctx, err, "failed to get IP address for domain ", destination.Address.Domain())
                                                if strategy.ForceIP() {
                                                        return err // retry
                                                }
                                        }
                                        for _, ip := range ips {
                                                if addr := net.IPAddress(ip); addr != nil {
                                                        if rule := h.matchFinalRule(destination.Network, addr, destination.Port, defaultRule); rule != nil && rule.action == RuleAction_Block {
                                                                blockedDest = &destination
                                                                blockedDest.Address = addr
                                                                blockedRule = rule
                                                                return nil
                                                        }
                                                }
                                        }
                                } else {
                                        addrs, err := net.DefaultResolver.LookupIPAddr(ctx, destination.Address.Domain())
                                        if err != nil { // dialer may retry DNS
                                                errors.LogInfoInner(ctx, err, "failed to get IP address for domain ", destination.Address.Domain())
                                        }
                                        for _, addr := range addrs {
                                                if ipAddr := net.IPAddress(addr.IP); ipAddr != nil {
                                                        if rule := h.matchFinalRule(destination.Network, ipAddr, destination.Port, defaultRule); rule != nil && rule.action == RuleAction_Block {
                                                                blockedDest = &destination
                                                                blockedDest.Address = ipAddr
                                                                blockedRule = rule
                                                                return nil
                                                        }
                                                }
                                        }
                                }
                        }
                } else {
                        if rule := h.matchFinalRule(destination.Network, destination.Address, destination.Port, defaultRule); rule != nil && rule.action == RuleAction_Block {
                                blockedDest = &destination
                                blockedRule = rule
                                return nil
                        }
                }

                // v26.11.196: For UDP, check if the udpConn already has a persistent
                // outbound conn from a previous Process call. If so, reuse it — this
                // keeps the source port stable so Google doesn't trigger path validation.
                if destination.Network != net.Network_TCP {
                        if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.Conn != nil {
                                type outboundConnHolder interface {
                                        GetOutboundConn() stdnet.Conn
                                }
                                if holder, ok := inbound.Conn.(outboundConnHolder); ok {
                                        if existingConn := holder.GetOutboundConn(); existingConn != nil {
                                                conn = existingConn
                                                // v26.11.197: Diagnostic — verify the reuse path is taken.
                                                // If we see "REUSING outbound conn" in logs, the persistent
                                                // socket is working. If we see "dialing to udp:" instead,
                                                // the reuse path failed (GetOutboundConn returned nil).
                                                errors.LogInfo(ctx, "NPDIAG: REUSING outbound conn, local endpoint ", existingConn.LocalAddr(), ", remote endpoint ", existingConn.RemoteAddr())
                                                return nil
                                        }
                                }
                        }
                }

                rawConn, err := dialer.Dial(ctx, destination)
                // v26.11.132: warmAcquired conns are now liveness-checked in
                // Acquire (getsockopt SO_ERROR), so a dead warm conn is
                // detected before reaching here. If we did get a warm conn,
                // skip the dial — the conn is already set.
                if warmAcquired {
                        return nil // conn is already set from the warm pool
                }
                if err != nil {
                        // v26.10.31-link: if the dial fails with network
                        // unreachable (broken IPv6 — connect or write fails
                        // because the gateway can't route), retry with IPv4.
                        if isNetworkUnreachable(err) && destination.Address.Family().IsDomain() {
                                errors.LogWarning(ctx, "freedom: dial to ", destination, " failed, retrying with IPv4 only")
                                if ips, e := internet.LookupForIP(destination.Address.Domain(), internet.DomainStrategy_USE_IP4, outGateway); e == nil && len(ips) > 0 {
                                        // v26.10.34-link (M7 fix): iterate all IPv4 candidates,
                                        // not just ips[0]. CDN edge pools often return multiple
                                        // IPs; trying only the first is a needless availability
                                        // reduction. Log each failure so operators can see the
                                        // real second failure (was previously swallowed).
                                        for i, ip := range ips {
                                                v4Dest := destination
                                                v4Dest.Address = net.IPAddress(ip)
                                                if rawConn2, derr := dialer.Dial(ctx, v4Dest); derr == nil {
                                                        conn = rawConn2
                                                        return nil
                                                } else {
                                                        errors.LogInfoInner(ctx, derr, "freedom: IPv4 fallback dial failed for ", destination.Address.Domain(), " candidate #", i)
                                                }
                                        }
                                }
                        }
                        return err
                }

                // v26.10.44-link: only set conn from rawConn if we actually dialed
                if !warmAcquired {
                        conn = rawConn
                }
                // v26.11.196: Store the outbound conn in udpConn for reuse on
                // subsequent Process calls. This keeps the source port stable.
                if destination.Network != net.Network_TCP {
                        if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.Conn != nil {
                                type outboundConnSetter interface {
                                        SetOutboundConn(stdnet.Conn)
                                }
                                if setter, ok := inbound.Conn.(outboundConnSetter); ok {
                                        setter.SetOutboundConn(conn)
                                }
                        }
                }
                return nil
        })
        if err != nil {
                return errors.New("failed to open connection to ", destination).Base(err)
        }
        if blockedDest != nil {
                return h.blackhole(ctx, input, output, blockedRule, blockedDest)
        }
        if destination.Address.Family().IsDomain() && (defaultRule != nil || len(h.finalRules) > 0) {
                // pre-check may fail or dialer may select another IP
                remoteDest := net.DestinationFromAddr(conn.RemoteAddr())
                if rule := h.matchFinalRule(remoteDest.Network, remoteDest.Address, remoteDest.Port, defaultRule); rule != nil && rule.action == RuleAction_Block {
                        conn.Close()
                        return h.blackhole(ctx, input, output, rule, &remoteDest)
                }
        }

        if h.config.ProxyProtocol > 0 && h.config.ProxyProtocol <= 2 {
                version := byte(h.config.ProxyProtocol)
                srcAddr := inbound.Source.RawNetAddr()
                dstAddr := conn.RemoteAddr()
                header := proxyproto.HeaderProxyFromAddrs(version, srcAddr, dstAddr)
                if _, err = header.WriteTo(conn); err != nil {
                        conn.Close()
                        return errors.New("failed to set PROXY protocol v", version).Base(err)
                }
        }
        // v26.10.44-link: for TCP connections with warm pool enabled, release
        // to the warm pool instead of closing. The warm pool will close the
        // conn when it expires (default 5s) or when a new inbound reuses it.
        // For non-warm-pool paths, close normally.
        // v26.11.196: For UDP, do NOT close the outbound conn when Process
        // returns. The conn is stored in udpConn.outboundConn and reused on
        // the next Process call to maintain a stable source port for Google's
        // QUIC path validation. clean() in worker.go will close it after idle.
        if destination.Network == net.Network_TCP && h.tcpWarmPool != nil {
                defer h.tcpWarmPool.Release(conn, destination)
        } else if destination.Network == net.Network_TCP {
                defer conn.Close()
        }
        // For UDP: no defer conn.Close() — the caller manages the lifecycle
        errors.LogInfo(ctx, "connection opened to ", destination, ", local endpoint ", conn.LocalAddr(), ", remote endpoint ", conn.RemoteAddr())

        // For UDP pool: peek at the first packet to determine if it's QUIC.
        // Only QUIC traffic can be demuxed by DCID in the pool's readLoop, so
        // non-QUIC UDP (e.g. WireGuard, DNS, games) falls back to the existing
        // per-session socket path. This prevents the pool from breaking non-QUIC UDP.
        var pooledConn *pooledConn
        var peekedPackets buf.MultiBuffer
        if destination.Network != net.Network_TCP && h.socketPool != nil {
                // Peek at the first packet(s) to check if this is QUIC traffic.
                mb, peekErr := input.ReadMultiBuffer()
                if peekErr == nil && len(mb) > 0 {
                        peekedPackets = mb
                        if isQUICLongHeader(mb[0].Bytes()) {
                                remoteAddr := conn.RemoteAddr()
                                var udpRemote *net.UDPAddr
                                if u, ok := remoteAddr.(*net.UDPAddr); ok {
                                        udpRemote = u
                                } else {
                                        udpRemote, _ = net.ResolveUDPAddr("udp", remoteAddr.String())
                                }
                                if udpRemote != nil {
                                        pooledConn, err = h.socketPool.Acquire(udpRemote)
                                        errors.LogWarning(context.Background(), "DIAG: pool ACQUIRE dest=", destination, " pool=", pooledConn != nil, " err=", err)
                                        if err != nil {
                                                // v26.10.34-link (C3 fix): release peeked packets
                                                // before returning. Without this, every Acquire
                                                // failure leaks one MultiBuffer (up to 8KB+ per
                                                // failure) — unbounded growth under flapping dest.
                                                buf.ReleaseMulti(peekedPackets)
                                                peekedPackets = nil
                                                return errors.New("failed to acquire pooled UDP conn").Base(err)
                                        }
                                        // v26.11.52-link (Solution B): bind the pooled socket's
                                        // source to the inbound client's source IP:port so that
                                        // pool reply packets (read via wildcard listen) are
                                        // demuxed back to the originating client. Without this,
                                        // all QUIC sessions sharing a pooled socket collapse to
                                        // the socket's local (kernel-chosen) source and the
                                        // 4-tuple-based reply routing breaks under NAT.
                                        if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.Source.IsValid() {
                                                pooledConn.source = &stdnet.UDPAddr{
                                                        IP:   inbound.Source.Address.IP(),
                                                        Port: int(inbound.Source.Port),
                                                }
                                        }
                                        defer pooledConn.Close()
                                        // Pool uses wildcard socket; clear outGateway for QUIC path.
                                        // Non-QUIC UDP keeps outGateway (sendThrough honored).
                                        outGateway = nil
                                        // v26.11.156: Set up pool CID registration callback.
                                        // When the inbound worker detects CID rotation in a
                                        // 1-RTT short header, it calls this to register the
                                        // new DCID in the pool's demux. Without this, Google's
                                        // replies with the rotated DCID get dropped.
                                        if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.Conn != nil {
                                                if uc, ok := inbound.Conn.(interface{ SetRegisterPoolCID(func([]byte)) }); ok {
                                                        pc := pooledConn
                                                        uc.SetRegisterPoolCID(func(newDCID []byte) {
                                                                pc.RegisterCID(newDCID)
                                                        })
                                                }
                                        }
                                }
                        }
                        // If not QUIC, pooledConn stays nil — existing per-session path is used.
                }
                // If peek failed, proceed with existing path (pooledConn stays nil).
        }

        var newCtx context.Context
        var newCancel context.CancelFunc
        if session.TimeoutOnlyFromContext(ctx) {
                newCtx, newCancel = context.WithCancel(context.Background())
        }

        plcy := h.policy()
        ctx, cancel := context.WithCancel(ctx)
        timer := signal.CancelAfterInactivity(ctx, func() {
                cancel()
                if newCancel != nil {
                        newCancel()
                }
        }, plcy.Timeouts.ConnectionIdle)

        requestDone := func() error {
                defer timer.SetTimeout(plcy.Timeouts.DownlinkOnly)
                errors.LogWarning(context.Background(), "DIAG: requestDone START dest=", destination, " pool=", pooledConn != nil)

                var writer buf.Writer
                if destination.Network == net.Network_TCP {
                        if h.config.Fragment != nil {
                                errors.LogDebug(ctx, "FRAGMENT", h.config.Fragment.PacketsFrom, h.config.Fragment.PacketsTo, h.config.Fragment.LengthMin, h.config.Fragment.LengthMax,
                                        h.config.Fragment.IntervalMin, h.config.Fragment.IntervalMax, h.config.Fragment.MaxSplitMin, h.config.Fragment.MaxSplitMax)
                                writer = buf.NewWriter(&FragmentWriter{
                                        fragment: h.config.Fragment,
                                        writer:   conn,
                                })
                        } else {
                                writer = buf.NewWriter(conn)
                        }
                } else if pooledConn != nil {
                        var statWrite stats.Counter
                        if statConn, ok := conn.(*stat.CounterConnection); ok {
                                statWrite = statConn.WriteCounter
                        }
                        writer = NewPooledPacketWriter(pooledConn, statWrite)
                } else {
                        writer = NewPacketWriter(conn, h, defaultRule, UDPOverride, destination, outGateway)
                        if h.config.Noises != nil {
                                errors.LogDebug(ctx, "NOISE", h.config.Noises)
                                writer = &NoisePacketWriter{
                                        Writer:      writer,
                                        noises:      h.config.Noises,
                                        firstWrite:  true,
                                        UDPOverride: UDPOverride,
                                        remoteAddr:  net.DestinationFromAddr(conn.RemoteAddr()).Address,
                                }
                        }
                }

                // Write any packets we peeked during the pool decision (before buf.Copy).
                if len(peekedPackets) > 0 {
                        if err := writer.WriteMultiBuffer(peekedPackets); err != nil {
                                return errors.New("failed to write peeked UDP packets").Base(err)
                        }
                }

                // NPDIAG 3: requestDone starting buf.Copy
                if err := buf.Copy(input, writer, buf.UpdateActivity(timer)); err != nil {
                        // v26.10.38-link: swallow ErrClosedPipe when inputCloser has
                        // fired (responseDone returned, so YouTube closed the outbound).
                        select {
                        case <-inputCloser:
                                errors.LogWarning(context.Background(), "DIAG: requestDone EXIT (inputCloser) dest=", destination)
                                return nil // graceful — let Dispatch Close(link.Writer)
                        default:
                                errors.LogWarning(context.Background(), "DIAG: requestDone EXIT (error) dest=", destination, " err=", err)
                                return errors.New("failed to process request").Base(err)
                        }
                }
                errors.LogWarning(context.Background(), "DIAG: requestDone EXIT (copy done) dest=", destination)
                return nil
        }

        responseDone := func() error {
                defer timer.SetTimeout(plcy.Timeouts.UplinkOnly)
                errors.LogWarning(context.Background(), "DIAG: responseDone START dest=", destination, " pool=", pooledConn != nil, " socketPool=", h.socketPool != nil)
                // v26.10.37-link: signal the inputCloser goroutine to interrupt
                // the inbound input pipe when responseDone returns — whether
                // the outbound closed cleanly (EOF) or with an error. This
                // unblocks requestDone (which is reading from input) so
                // task.Run returns and the inbound worker can call conn.Close(),
                // preventing the CLOSE-WAIT accumulation that causes the
                // "every 20th swipe" YouTube Shorts stall.
                defer close(inputCloser)
                if destination.Network == net.Network_TCP && useSplice.Load() && proxy.IsRAWTransportWithoutSecurity(conn) { // it would be tls conn in special use case of MITM, we need to let link handle traffic
                        var writeConn net.Conn
                        var inTimer *signal.ActivityTimer
                        if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.Conn != nil {
                                writeConn = inbound.Conn
                                inTimer = inbound.Timer
                        }
                        return proxy.CopyRawConnIfExist(ctx, conn, writeConn, link.Writer, timer, inTimer)
                }
                var reader buf.Reader
                if destination.Network == net.Network_TCP {
                        reader = buf.NewReader(conn)
                } else if pooledConn != nil {
                        reader = NewPooledPacketReader(pooledConn)
                } else {
                        reader = NewPacketReader(conn, h, defaultRule, UDPOverride, destination)
                        // v26.11.117: Wrap reader to detect server SCID from
                        // long-header replies. When Google's Initial reply
                        // arrives, extract the SCID and register it in the
                        // worker's dcidIndex via RegisterServerSCID.
                        if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.Conn != nil {
                                if reg, ok := inbound.Conn.(interface{ RegisterServerSCID([]byte) }); ok {
                                        var scidRegistered bool
                                        baseReader := reader
                                        reader = &serverSCIDReader{
                                                base:       baseReader,
                                                register:   reg.RegisterServerSCID,
                                                registered: &scidRegistered,
                                        }
                                }
                        }
                        // v26.11.205: Re-enable BufferedPacketReader. This is what
                        // makes the POOL work better — the pool has a dedicated
                        // readLoop that always drains the socket, even when the
                        // pipe to Chrome is blocked. Without this, buf.Copy
                        // couples read+write: when the pipe write blocks, the
                        // socket read stalls, the kernel UDP buffer overflows,
                        // and Google's replies are dropped at the kernel level.
                        //
                        // The readLoop uses non-blocking send (drops when inbox
                        // is full) so it NEVER blocks. The socket is always
                        // drained. This matches the pool's architecture.
                        reader = NewBufferedPacketReader(reader)
                }
                if err := buf.Copy(reader, output, buf.UpdateActivity(timer)); err != nil {
                        errors.LogWarning(context.Background(), "DIAG: responseDone EXIT (error) dest=", destination, " err=", err)
                        return errors.New("failed to process response").Base(err)
                }
                errors.LogWarning(context.Background(), "DIAG: responseDone EXIT (copy done — Google closed socket) dest=", destination)
                return nil
        }

        if newCtx != nil {
                ctx = newCtx
        }

        if err := task.Run(ctx, requestDone, task.OnSuccess(responseDone, task.Close(output))); err != nil {
                return errors.New("connection ends").Base(err)
        }

        return nil
}

func NewPacketReader(conn net.Conn, h *Handler, defaultRule *FinalRule, UDPOverride net.Destination, DialDest net.Destination) buf.Reader {
        iConn := conn
        statConn, ok := iConn.(*stat.CounterConnection)
        if ok {
                iConn = statConn.Connection
        }
        var counter stats.Counter
        if statConn != nil {
                counter = statConn.ReadCounter
        }
        if c, ok := iConn.(*internet.PacketConnWrapper); ok {
                isOverridden := false
                if UDPOverride.Address != nil || UDPOverride.Port != 0 {
                        isOverridden = true
                }

                return &PacketReader{
                        PacketConnWrapper: c,
                        Counter:           counter,
                        Handler:           h,
                        DefaultRule:       defaultRule,
                        IsOverridden:      isOverridden,
                        InitUnchangedAddr: DialDest.Address,
                        InitChangedAddr:   net.DestinationFromAddr(conn.RemoteAddr()).Address,
                }
        }
        // v26.11.203: Reverted finalmask.PacketConnWrapper detection (v194).
        // Pre-v194, finalmask.PacketConnWrapper fell through to buf.PacketReader
        // (the simple reader that calls readOneUDP). v166 used this path.
        return &buf.PacketReader{Reader: conn}
}

type PacketReader struct {
        *internet.PacketConnWrapper
        stats.Counter
        Handler           *Handler
        DefaultRule       *FinalRule
        IsOverridden      bool
        InitUnchangedAddr net.Address
        InitChangedAddr   net.Address
}

func (r *PacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
        b := buf.New()
        b.Resize(0, buf.Size)
        for {
                n, d, err := r.PacketConnWrapper.ReadFrom(b.Bytes())
                if err != nil {
                        b.Release()
                        return nil, err
                }
                // NPDIAG 1: Google reply received by outbound socket
                // v26.11.201: REMOVED per-packet log — was causing the stall.
                // 3 log lines per packet × 500+ packets/burst = logger mutex
                // serialized all packet processing, pipe filled up, ACKs dropped.
                udpAddr := d.(*net.UDPAddr)
                sourceAddr := net.IPAddress(udpAddr.IP)
                if rule := r.Handler.matchFinalRule(net.Network_UDP, sourceAddr, net.Port(udpAddr.Port), r.DefaultRule); rule != nil && rule.action == RuleAction_Block {
                        continue
                }
                b.Resize(0, int32(n))

                // if udp dest addr is changed, we are unable to get the correct src addr
                // so we don't attach src info to udp packet, break cone behavior, assuming the dial dest is the expected scr addr
                if !r.IsOverridden {
                        if r.InitChangedAddr == sourceAddr {
                                sourceAddr = r.InitUnchangedAddr
                        }
                        b.UDP = &net.Destination{
                                Address: sourceAddr,
                                Port:    net.Port(udpAddr.Port),
                                Network: net.Network_UDP,
                        }
                }
                if r.Counter != nil {
                        r.Counter.Add(int64(n))
                }
                return buf.MultiBuffer{b}, nil
        }
}

// DialDest means the dial target used in the dialer when creating conn
func NewPacketWriter(conn net.Conn, h *Handler, defaultRule *FinalRule, UDPOverride net.Destination, DialDest net.Destination, outGateway net.Address) buf.Writer {
        iConn := conn
        statConn, ok := iConn.(*stat.CounterConnection)
        if ok {
                iConn = statConn.Connection
        }
        var counter stats.Counter
        if statConn != nil {
                counter = statConn.WriteCounter
        }
        if c, ok := iConn.(*internet.PacketConnWrapper); ok {
                errors.LogWarning(context.Background(), "NPDIAG: PacketWriter created (internet.PacketConnWrapper)")
                // If DialDest is a domain, it will be resolved in dialer
                // check this behavior and add it to map
                resolvedUDPAddr := utils.NewTypedSyncMap[string, net.Address]()
                if DialDest.Address.Family().IsDomain() {
                        resolvedUDPAddr.Store(DialDest.Address.Domain(), net.DestinationFromAddr(conn.RemoteAddr()).Address)
                }
                return &PacketWriter{
                        PacketConnWrapper: c,
                        Counter:           counter,
                        Handler:           h,
                        DefaultRule:       defaultRule,
                        UDPOverride:       UDPOverride,
                        ResolvedUDPAddr:   resolvedUDPAddr,
                        OutGateway:        outGateway,
                }
        }
        // v26.11.203: Reverted finalmask.PacketConnWrapper detection (v194).
        // Pre-v194, finalmask.PacketConnWrapper fell through to SequentialWriter.
        // v166 (which worked for 5+ min videos) used SequentialWriter for this type.
        // The v194 change to use PacketReader/PacketWriter may have introduced a subtle
        // bug in the non-pool path. Reverting to SequentialWriter to match v166.
        errors.LogWarning(context.Background(), "NPDIAG: SequentialWriter fallback! conn type=", fmt.Sprintf("%T", iConn))
        return &buf.SequentialWriter{Writer: conn}
}

type PacketWriter struct {
        *internet.PacketConnWrapper
        stats.Counter
        *Handler
        DefaultRule *FinalRule
        UDPOverride net.Destination

        // Dest of udp packets might be a domain, we will resolve them to IP
        // But resolver will return a random one if the domain has many IPs
        // Resulting in these packets being sent to many different IPs randomly
        // So, cache and keep the resolve result
        ResolvedUDPAddr *utils.TypedSyncMap[string, net.Address]
        OutGateway      net.Address
}

func (w *PacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
        for {
                mb2, b := buf.SplitFirst(mb)
                mb = mb2
                if b == nil {
                        break
                }
                var n int
                var err error
                if b.UDP != nil {
                        if w.UDPOverride.Address != nil {
                                b.UDP.Address = w.UDPOverride.Address
                        }
                        if w.UDPOverride.Port != 0 {
                                b.UDP.Port = w.UDPOverride.Port
                        }
                        if b.UDP.Address.Family().IsDomain() {
                                if ip, ok := w.ResolvedUDPAddr.Load(b.UDP.Address.Domain()); ok {
                                        b.UDP.Address = ip
                                } else {
                                        shouldUseSystemResolver := true
                                        if strategy := w.Handler.resolveStrategy; strategy.HasStrategy() {
                                                ips, err := internet.LookupForIP(b.UDP.Address.Domain(), strategy, w.OutGateway)
                                                if err != nil {
                                                        // drop packet if resolve failed when forceIP
                                                        if strategy.ForceIP() {
                                                                b.Release()
                                                                continue
                                                        }
                                                } else {
                                                        ip = net.IPAddress(ips[dice.Roll(len(ips))])
                                                        shouldUseSystemResolver = false
                                                }
                                        }
                                        if shouldUseSystemResolver {
                                                udpAddr, err := net.ResolveUDPAddr("udp", b.UDP.NetAddr())
                                                if err != nil {
                                                        b.Release()
                                                        continue
                                                } else {
                                                        ip = net.IPAddress(udpAddr.IP)
                                                }
                                        }
                                        if ip != nil {
                                                b.UDP.Address, _ = w.ResolvedUDPAddr.LoadOrStore(b.UDP.Address.Domain(), ip)
                                        }
                                }
                        }
                        if rule := w.matchFinalRule(net.Network_UDP, b.UDP.Address, b.UDP.Port, w.DefaultRule); rule != nil && rule.action == RuleAction_Block {
                                b.Release()
                                continue
                        }
                        destAddr := b.UDP.RawNetAddr()
                        if destAddr == nil {
                                b.Release()
                                continue
                        }
                        n, err = w.PacketConnWrapper.WriteTo(b.Bytes(), destAddr)
                        // NPDIAG 4: REMOVED per-packet log (v26.11.201) — was causing stalls
                } else {
                        n, err = w.PacketConnWrapper.Write(b.Bytes())
                }
                b.Release()
                if err != nil {
                        buf.ReleaseMulti(mb)
                        return err
                }
                if w.Counter != nil {
                        w.Counter.Add(int64(n))
                }
        }
        return nil
}

type NoisePacketWriter struct {
        buf.Writer
        noises      []*Noise
        firstWrite  bool
        UDPOverride net.Destination
        remoteAddr  net.Address
}

// MultiBuffer writer with Noise before first packet
func (w *NoisePacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
        if w.firstWrite {
                w.firstWrite = false
                // Do not send Noise for dns requests(just to be safe)
                if w.UDPOverride.Port == 53 {
                        return w.Writer.WriteMultiBuffer(mb)
                }
                var noise []byte
                var err error
                if w.remoteAddr.Family().IsDomain() {
                        panic("impossible, remoteAddr is always IP")
                }
                for _, n := range w.noises {
                        switch n.ApplyTo {
                        case "ipv4":
                                if w.remoteAddr.Family().IsIPv6() {
                                        continue
                                }
                        case "ipv6":
                                if w.remoteAddr.Family().IsIPv4() {
                                        continue
                                }
                        case "ip":
                        default:
                                panic("unreachable, applyTo is ip/ipv4/ipv6")
                        }
                        // User input string or base64 encoded string or hex string
                        if n.Packet != nil {
                                noise = n.Packet
                        } else {
                                // Random noise
                                noise, err = GenerateRandomBytes(crypto.RandBetween(int64(n.LengthMin),
                                        int64(n.LengthMax)))
                        }
                        if err != nil {
                                return err
                        }
                        err = w.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(noise)})
                        if err != nil {
                                return err
                        }

                        if n.DelayMin != 0 || n.DelayMax != 0 {
                                time.Sleep(time.Duration(crypto.RandBetween(int64(n.DelayMin), int64(n.DelayMax))) * time.Millisecond)
                        }
                }

        }
        return w.Writer.WriteMultiBuffer(mb)
}

type FragmentWriter struct {
        fragment *Fragment
        writer   io.Writer
        count    uint64
}

func (f *FragmentWriter) Write(b []byte) (int, error) {
        f.count++

        if f.fragment.PacketsFrom == 0 && f.fragment.PacketsTo == 1 {
                if f.count != 1 || len(b) <= 5 || b[0] != 22 {
                        return f.writer.Write(b)
                }
                recordLen := 5 + ((int(b[3]) << 8) | int(b[4]))
                if len(b) < recordLen { // maybe already fragmented somehow
                        return f.writer.Write(b)
                }
                data := b[5:recordLen]
                buff := make([]byte, 2048)
                var hello []byte
                maxSplit := crypto.RandBetween(int64(f.fragment.MaxSplitMin), int64(f.fragment.MaxSplitMax))
                var splitNum int64
                for from := 0; ; {
                        to := from + int(crypto.RandBetween(int64(f.fragment.LengthMin), int64(f.fragment.LengthMax)))
                        splitNum++
                        if to > len(data) || (maxSplit > 0 && splitNum >= maxSplit) {
                                to = len(data)
                        }
                        l := to - from
                        if 5+l > len(buff) {
                                buff = make([]byte, 5+l)
                        }
                        copy(buff[:3], b)
                        copy(buff[5:], data[from:to])
                        from = to
                        buff[3] = byte(l >> 8)
                        buff[4] = byte(l)
                        if f.fragment.IntervalMax == 0 { // combine fragmented tlshello if interval is 0
                                hello = append(hello, buff[:5+l]...)
                        } else {
                                _, err := f.writer.Write(buff[:5+l])
                                time.Sleep(time.Duration(crypto.RandBetween(int64(f.fragment.IntervalMin), int64(f.fragment.IntervalMax))) * time.Millisecond)
                                if err != nil {
                                        return 0, err
                                }
                        }
                        if from == len(data) {
                                if len(hello) > 0 {
                                        _, err := f.writer.Write(hello)
                                        if err != nil {
                                                return 0, err
                                        }
                                }
                                if len(b) > recordLen {
                                        n, err := f.writer.Write(b[recordLen:])
                                        if err != nil {
                                                return recordLen + n, err
                                        }
                                }
                                return len(b), nil
                        }
                }
        }

        if f.fragment.PacketsFrom != 0 && (f.count < f.fragment.PacketsFrom || f.count > f.fragment.PacketsTo) {
                return f.writer.Write(b)
        }
        maxSplit := crypto.RandBetween(int64(f.fragment.MaxSplitMin), int64(f.fragment.MaxSplitMax))
        var splitNum int64
        for from := 0; ; {
                to := from + int(crypto.RandBetween(int64(f.fragment.LengthMin), int64(f.fragment.LengthMax)))
                splitNum++
                if to > len(b) || (maxSplit > 0 && splitNum >= maxSplit) {
                        to = len(b)
                }
                n, err := f.writer.Write(b[from:to])
                from += n
                if err != nil {
                        return from, err
                }
                time.Sleep(time.Duration(crypto.RandBetween(int64(f.fragment.IntervalMin), int64(f.fragment.IntervalMax))) * time.Millisecond)
                if from >= len(b) {
                        return from, nil
                }
        }
}

func GenerateRandomBytes(n int64) ([]byte, error) {
        b := make([]byte, n)
        _, err := rand.Read(b)
        // Note that err == nil only if we read len(b) bytes.
        if err != nil {
                return nil, err
        }

        return b, nil
}

// v26.11.117: serverSCIDReader wraps a buf.Reader to detect the server's
// SCID from long-header QUIC replies. When Google's Initial reply arrives,
// the SCID is extracted and registered via RegisterServerSCID, so the
// worker's dcidIndex can route subsequent 1-RTT short headers (which
// carry DCID=server_SCID) to the correct conn.
type serverSCIDReader struct {
        base       buf.Reader
        register   func([]byte) // RegisterServerSCID method
        registered *bool
}

func (r *serverSCIDReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
        mb, err := r.base.ReadMultiBuffer()
        if err != nil {
                return mb, err
        }

        // Only scan once — after the first long header is seen, no need to
        // check again (the SCID is registered).
        if !*r.registered {
                for _, b := range mb {
                        data := b.Bytes()
                        if len(data) > 0 && data[0]&0x80 != 0 {
                                // Long header — try to parse SCID
                                if scid, _, perr := quic.ParseSCID(data); perr == nil && len(scid) > 0 {
                                        r.register(scid)
                                        *r.registered = true
                                        break
                                }
                        }
                }
        }

        return mb, nil
}

// v26.11.195: BufferedPacketReader wraps a buf.Reader with a dedicated
// readLoop goroutine. This decouples the read from the write — the
// readLoop always reads from the socket, even when the write path
// (pipe to Chrome) is blocked. This prevents Google's replies from
// being dropped when the pipe is full.
//
// This is the same architecture as the pool's readLoop, but for
// single (non-pooled) connections. Without this, buf.Copy serializes
// read and write — when output.WriteMultiBuffer blocks, the next
// reader.ReadMultiBuffer doesn't happen, the socket buffer fills up,
// and Google's replies are dropped by the kernel.
type BufferedPacketReader struct {
        base   buf.Reader
        inbox  chan buf.MultiBuffer
        done   chan struct{}
}

func NewBufferedPacketReader(base buf.Reader) *BufferedPacketReader {
        r := &BufferedPacketReader{
                base:  base,
                inbox: make(chan buf.MultiBuffer, 256), // same as pool's inbox
                done:  make(chan struct{}),
        }
        go r.readLoop()
        return r
}

func (r *BufferedPacketReader) readLoop() {
        for {
                mb, err := r.base.ReadMultiBuffer()
                if err != nil {
                        buf.ReleaseMulti(mb)
                        // Send EOF to unblock ReadMultiBuffer
                        select {
                        case r.inbox <- nil:
                        case <-r.done:
                        }
                        return
                }
                // v26.11.202: NON-BLOCKING send. Never block the readLoop —
                // if the inbox is full (consumer can't keep up), drop the
                // packet. QUIC retransmission handles loss gracefully.
                // Blocking here would cause the same bug as buf.Copy:
                // socket reads stall, kernel buffer overflows, Google
                // kills the connection.
                select {
                case r.inbox <- mb:
                default:
                        buf.ReleaseMulti(mb) // inbox full — drop packet
                }
                // Check if we should exit
                select {
                case <-r.done:
                        return
                default:
                }
        }
}

func (r *BufferedPacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
        select {
        case mb, ok := <-r.inbox:
                if !ok || mb == nil {
                        return nil, io.EOF
                }
                return mb, nil
        case <-r.done:
                return nil, io.EOF
        }
}

func (r *BufferedPacketReader) Close() error {
        select {
        case <-r.done:
        default:
                close(r.done)
        }
        return nil
}
