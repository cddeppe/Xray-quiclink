# Xray-quiclink

A fork of [Xray-core](https://github.com/XTLS/Xray-core) focused on **transparent proxying of YouTube/Google traffic** via a VPS using DNS hijacking.

## Current Status (v26.12.79)

### What Works

| Feature | Status | Notes |
|---------|--------|-------|
| YouTube over TCP (splice) | ✅ Working | Kernel-level zero-copy splice. TCP_NODELAY + TCP_QUICKACK enabled. |
| h3 test sites (quic.nginx.org, cloudflare-quic.com) | ✅ Working | Per-session UDP socket with persistent reader. |
| DNS hijacking mode (no WireGuard/TPROXY needed) | ✅ Working | Uses ctrld or any local DNS resolver. |
| Multi-IP inbound listen (IPv4 + IPv6) | ✅ Working | Dual-stack with sendThrough: origin. |
| Deterministic source-IP binding | ✅ Working | sendThrough: origin ensures outbound uses the same IP as inbound. |
| QUIC handshake relay | ✅ Working | SNI sniffing from QUIC Initial, persistent session socket, server SCID registration. |
| QUIC 1-RTT routing | ✅ Working | 5-tuple (srcIndex) primary, DCID as exception for NAT rebind. RFC 9312 §4.2 compliant. |
| Happy Eyeballs (IPv6/IPv4 racing) | ✅ Working | Configurable via sockopt.happyEyeballs. |

### What Does Not Work (Yet)

| Feature | Status | Reason |
|---------|--------|--------|
| YouTube video playback over QUIC | ⚠️ Partial | QUIC handshake completes and data flows, but throughput is throttled (~80-200 kbit/s vs 1-8 Mbit/s needed). QUIC's congestion control sees the userspace relay's added RTT and keeps the congestion window small. TCP doesn't have this problem because splice is kernel-level zero-copy. RFC 9312 §4.3 warns that transparent relays suppress congestion-control resets, which is the likely mechanism. |

### Removed Features (were in earlier versions, now deleted)

| Feature | Why Removed |
|---------|-------------|
| TCP warm pool | Caused FD leaks (dial before warmAcquired check), goroutine leaks (Release without close), stale-connection reuse, and periodic throughput drops (preWarmLoop dialed 10 connections every 60s). YouTube uses unique `rr*.googlevideo.com` subdomains per video — pre-warmed connections to old IPs were never reused. |
| UDP socket pool | Added complexity and bugs (buffer leaks, stale socket reuse, goroutine leaks on reload). The per-session socket path with persistent reader handles QUIC demux correctly without it. |
| Sticky DNS resolver | Served stale IPs for CDN-rotated googlevideo subdomains. ctrld's own cache with proper TTLs is better. The sticky resolver's 60s hardcoded TTL was worse than Google's actual 300s TTL. |
| SplitCoalesced | Split coalesced QUIC packets into separate UDP datagrams, violating RFC 9000 §12.2. Coalesced packets must be delivered as a single datagram. |
| DIAG counter system | Extensive diagnostic counters (sockRead, chDrop, shortDrop, pipeDrop, nilAddr, writeErr, etc.) added during debugging. Stripped in v26.12.70 for clean production builds. Can be re-added from v26.12.69 tag if needed. |

---

## Architecture

### TCP Path (Working, Optimized)

```
Chrome → DNS hijack → VPS:443 (dokodemo-door)
  → SNI sniff (TLS ClientHello)
  → freedom outbound dials Google IP
  → splice (kernel zero-copy, no userspace copy)
  → data flows bidirectionally
```

TCP uses Go's `ReadFrom` → kernel `splice(2)` syscall. Zero userspace copies, zero per-packet allocations. TCP_NODELAY eliminates 40ms Nagle delay. TCP_QUICKACK eliminates 40ms delayed ACK on the first packet exchange. Splice timeout is 10 minutes (backstop for stalled connections; TCP keepalive detects dead peers in ~90-135s).

### UDP/QUIC Path (Functional, Throughput-Limited)

```
Chrome → DNS hijack → VPS:443 (dokodemo-door, network: tcp,udp)
  → QUIC Initial (long header) → SNI sniff
  → freedom dials Google IP on per-session UDP socket
  → SetOutboundConn stores socket for reuse
  → EnsureSessionReader starts persistent reader goroutine
  → Reader goroutine reads Google's replies, registers server SCID
  → Replies delivered to Chrome via direct write (c.output → hub.WriteTo)
  → Subsequent 1-RTT short headers routed by srcIndex (5-tuple)
  → CID rotation handled by tryQUICMigration
  → NAT rebind handled by DCID lookup (exception path)
```

The per-session socket path gives each QUIC connection its own outbound UDP socket with a permanent reader goroutine. The reader uses a 1-second `SetReadDeadline` to prevent blocking on stale sockets. Replies are written directly to the client via `c.output` (bypassing the channel/pipe/Process path). Request packets use direct write to the outbound socket when available (bypassing the pipe/Process/PacketWriter path).

### Why QUIC Throughput Is Limited

QUIC implements its own congestion control in userspace (Chrome's QUIC stack). The congestion window (cwnd) determines how much data can be in flight. The cwnd is calibrated based on measured RTT. A userspace relay adds latency to every packet's round-trip:

- TCP splice: kernel-to-kernel, ~0µs added per packet
- QUIC relay: Hub → channel → callback → pipe/Process → PacketWriter → socket → reader → c.output → hub, ~100-300µs added per direction

This inflated RTT keeps QUIC's cwnd small, limiting throughput to ~80-200 kbit/s. TCP doesn't have this problem because splice adds near-zero latency.

RFC 9312 §4.3 explicitly warns: "Applying address translation at a middlebox to maintain a stable address-port mapping for flows based on connection ID conceals important and security-relevant information from QUIC endpoints... suppresses the reset of congestion-control state on path change."

### RFC 9312 Compliance

This fork follows RFC 9312 (Manageability of the QUIC Transport Protocol) guidance:

- **§4.2**: 5-tuple (srcIndex) is the primary routing key, not CID. CID is used only as an exception for NAT rebind association.
- **§2.1**: Uses only the invariant Header Form bit (bit 7) for long/short header discrimination. Does not rely on the fixed bit (0x40), which is not invariant per RFC 9287.
- **§2.2/§2.4**: Coalesced packets are delivered intact (SplitCoalesced removed).
- **§4.5**: No mid-connection packet drops to force TCP fallback.
- **§4.10**: No application-level MTU guessing (let DPLPMTUD handle it).
- **§1**: Transparent relay is out of scope for the RFC; the supported approach is to terminate QUIC (be an endpoint), which this fork does not do.

---

## Configuration

### Minimal Config (TCP-only, recommended for YouTube)

```json
{
  "log": {
    "loglevel": "warning",
    "error": "/var/log/xray/error.log"
  },
  "dns": {
    "cacheSize": 5000,
    "serveStale": false,
    "servers": ["127.0.0.1", "[::1]"]
  },
  "inbounds": [
    {
      "listen": ["YOUR_VPS_IPV4", "YOUR_VPS_IPV6"],
      "port": 443,
      "protocol": "dokodemo-door",
      "tag": "in-443",
      "settings": { "network": "tcp,udp" },
      "sniffing": { "enabled": true, "destOverride": ["tls"] },
      "streamSettings": {
        "sockopt": {
          "tcpFastOpen": true,
          "tcpNoDelay": true,
          "tcpKeepAlive": 15,
          "tcpMptcp": true
        }
      }
    },
    {
      "listen": ["YOUR_VPS_IPV4", "YOUR_VPS_IPV6"],
      "port": 80,
      "protocol": "dokodemo-door",
      "tag": "in-80",
      "settings": { "network": "tcp" },
      "sniffing": { "enabled": true, "destOverride": ["http"] },
      "streamSettings": {
        "sockopt": {
          "tcpFastOpen": true,
          "tcpNoDelay": true,
          "tcpKeepAlive": 15,
          "tcpMptcp": true
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct",
      "sendThrough": "origin",
      "streamSettings": {
        "sockopt": {
          "domainStrategy": "UseIPv6v4",
          "happyEyeballs": {
            "prioritizeIpv6": true,
            "interleave": 0,
            "tryDelayMs": 50,
            "maxConcurrentTry": 3
          },
          "tcpFastOpen": true,
          "tcpNoDelay": true,
          "tcpKeepAlive": 15,
          "tcpMptcp": true
        }
      },
      "settings": {
        "udpConfig": {
          "preferIpv6": true,
          "sessionIdleTimeout": 1800
        }
      }
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": []
  },
  "policy": {
    "levels": {
      "0": {
        "connIdle": 1800,
        "uplinkOnly": 1800,
        "downlinkOnly": 1800,
        "handshake": 4
      }
    }
  }
}
```

### Key Config Notes

- **`serveStale: false`** — Do NOT enable. Serving stale DNS entries for 5 minutes causes connections to dead CDN IPs. ctrld's own cache with proper TTLs is better.
- **`prefetchInterval: 0`** (omit or set to 0) — Do NOT enable prefetch. YouTube's googlevideo subdomains are unique per video session; prefetching wastes DNS queries on one-time-use domains.
- **`enableTcpWarmPool: false`** (omit) — Warm pool removed from code. Setting is ignored.
- **`enableStickyResolver: false`** (omit) — Sticky resolver is harmful for CDN-rotated domains. ctrld handles caching.
- **`enableSocketPool: false`** (omit) — Socket pool not needed. Per-session path handles QUIC demux.
- **`tryDelayMs: 50`** — 50ms instead of 150ms default. Reduces latency on IPv6-fail connections.
- **`network: "tcp,udp"`** — Enable UDP on :443 inbound for QUIC. Leave :80 as TCP-only.

---

## Installation

### From Release

```bash
# AMD64
cd /tmp && wget -q https://github.com/cddeppe/Xray-quiclink/releases/download/v26.12.79/xray-linux-amd64 && chmod +x xray-linux-amd64 && mv xray-linux-amd64 /usr/local/bin/xray && systemctl restart xray

# ARM64
cd /tmp && wget -q https://github.com/cddeppe/Xray-quiclink/releases/download/v26.12.79/xray-linux-arm64 && chmod +x xray-linux-arm64 && mv xray-linux-arm64 /usr/local/bin/xray && systemctl restart xray
```

### From Source

```bash
git clone -b v191-prefetch https://github.com/cddeppe/Xray-quiclink.git
cd Xray-quiclink
CGO_ENABLED=0 go build -o xray -trimpath -ldflags="-s -w" ./main
```

---

## Changes From Upstream Xray-core

### Key Modified Files

| File | What Changed |
|------|--------------|
| `proxy/freedom/freedom.go` | UDP per-session socket path, direct write bypass, self-dial guard (UDP only), nil conn guard, defer-based pipe cleanup, context leak fix, DNS retry 5→2 |
| `app/proxyman/inbound/worker.go` | 5-tuple primary routing (RFC 9312 §4.2), DCID exception path for NAT rebind, persistent session reader, server SCID registration, shared socket map, Hub buffer enlargement (4MB), cache channel enlargement (8192), self-dial guard, atomic reply destination (no per-packet mutex) |
| `proxy/proxy.go` | Splice timeout 24h→10min |
| `transport/internet/sockopt_linux.go` | TCP_NODELAY + TCP_QUICKACK on all sockets |
| `transport/internet/udp/hub.go` | SetReadBuffer(4MB) + SetWriteBuffer(4MB), cache channel 256→8192, removed silent `default:` drop |
| `transport/internet/system_dialer.go` | FakePacketConn safe type assertion |
| `transport/internet/happy_eyeballs.go` | Panics replaced with error returns |
| `transport/pipe/impl.go` | (Cleaned — overflow counter removed) |
| `common/protocol/quic/dcid.go` | QUIC DCID/SCID parser |
| `common/protocol/quic/sniff.go` | QUIC SNI sniffer with ECH support |
| `core/core.go` | Version tracking (v26.12.79) |

### Bug Fixes Applied (v26.12.73–v26.12.79)

1. **Self-dial guard restricted to UDP only** — was dropping TCP connections where sniffer hadn't extracted SNI yet
2. **DNS retry 5→2** — 5 retries on NXDOMAIN wasted ~3 seconds per dead domain
3. **Goroutine leak fix** — `inputCloser` goroutine leaked on every failed dial
4. **Splice timeout 24h→10min** — stalled splice shouldn't hang for 24 hours
5. **TCP_NODELAY + TCP_QUICKACK** — eliminates 40ms Nagle delay and 40ms delayed ACK
6. **Nil conn guard** — blocked finalRule left conn=nil, causing panic on Close()
7. **Context leak fix** — missing `defer cancel()` leaked contexts on long-lived connections
8. **FakePacketConn safe assertion** — unchecked `*net.TCPAddr` type assertion could panic
9. **happy_eyeballs panics→errors** — two `panic()` calls replaced with error returns
10. **Defer-based pipe cleanup** — `defer common.Interrupt(input)` + `defer common.Close(output)` prevents pipe/buffer leak on error paths
11. **Warm pool removed** — FD leaks, goroutine leaks, stale-connection reuse, preWarmLoop sawtooth
12. **SplitCoalesced removed** — violated RFC 9000 §12.2, broke QUIC coalesced packets
13. **Hub buffer enlargement** — 4MB receive + send buffers, 8192-slot cache channel, no silent drops
14. **SO_SNDBUF/SO_RCVBUF removed** — manual buffer sizing disabled TCP auto-tuning, capping throughput
15. **Per-packet mutex removed** — atomic.Pointer for reply destination, atomic.Value for outbound conn

---

## Kernel Tuning

```bash
# /etc/sysctl.d/99-quic.conf
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.core.rmem_default=3276800
net.core.wmem_default=3276800
```

Verify:
```bash
sysctl net.core.rmem_max net.core.wmem_max
```

---

## Branches

- `v191-prefetch` — active development branch (latest: v26.12.79)
- `main` — stable base (v26.11.132)

## License

Same as [Xray-core](https://github.com/XTLS/Xray-core) (MIT/Apache-2.0).
