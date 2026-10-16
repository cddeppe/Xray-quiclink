# Xray-quiclink

A fork of [Xray-core](https://github.com/XTLS/Xray-core) focused on **transparent QUIC/HTTP3 proxying** and **deterministic source-IP handling** for multi-hop proxy chains.

## What This Fork Does

Standard xray-core is a Layer-4 proxy. QUIC (HTTP/3) is a Layer-7 protocol with encrypted short headers that carry no SNI. This creates a fundamental mismatch: xray can sniff the SNI from a QUIC Initial (long header), but cannot determine the destination for 1-RTT short headers.

This fork bridges that gap with a UDP socket pool that demuxes QUIC replies by Connection ID (CID), allowing transparent QUIC proxying without TPROXY, iptables, or WireGuard.

### What Works

| Feature | Status |
|---------|--------|
| h3 test sites (quic.nginx.org, cloudflare-quic.com) over QUIC | ✅ Working |
| YouTube over TCP (fallback) | ✅ Working |
| DNS hijacking mode (no WireGuard needed) | ✅ Working |
| Multi-IP inbound listen | ✅ Working |
| Deterministic source-IP binding (sendThrough: origin) | ✅ Working |
| TCP warm pool (faster video-to-video transitions) | ✅ Working |
| Sticky DNS resolver with wildcard cache | ✅ Working |

### What Does Not Work

| Feature | Status | Reason |
|---------|--------|--------|
| YouTube over QUIC | ❌ Not working | QUIC 1-RTT short headers are encrypted (no SNI). YouTube opens multiple parallel QUIC connections with CID rotation, breaking DCID-based reply demuxing. Without TPROXY + WireGuard, xray cannot route 1-RTT packets to the correct destination. |

---

## Changes From Upstream

### New Files Created

| File | Purpose |
|------|---------|
| `common/protocol/quic/dcid.go` | QUIC DCID (Destination Connection ID) parser for long and short headers |
| `common/protocol/quic/dcid_test.go` | Tests for DCID parser |
| `common/protocol/quic/split.go` | Coalesced QUIC packet splitter (RFC 9000 Section 12.2) |
| `common/protocol/quic/sniff_bench_test.go` | Benchmarks for QUIC sniffer |
| `common/protocol/quic/workerhook.go` | Server SCID notification hook for the inbound worker |
| `proxy/freedom/udp_pool.go` | UDP socket pool with DCID-based reply demuxing |
| `proxy/freedom/udp_sticky.go` | Sticky DNS resolver with wildcard cache + stale-while-revalidate |
| `proxy/freedom/tcp_pool.go` | TCP warm pool for faster video-to-video transitions |
| `proxy/freedom/udptimeout/udptimeout.go` | Configurable UDP timeout (replaces hardcoded 2-minute) |
| `example-configs/vps-consolidated.json` | Example configuration with all features |

### Files Modified

| File | What Changed |
|------|--------------|
| `app/proxyman/inbound/worker.go` | Added QUIC CID migration, synthetic dest (DCID-based connID), Solution A (srcIndex routing for short headers) |
| `app/dispatcher/default.go` | UDP sniffer integration for DispatchLink |
| `app/dispatcher/sniffer.go` | QUIC sniffer registration |
| `app/dns/cache_controller.go` | Wildcard fallback for SERVFAIL, prefetch refresh, cache optimizations |
| `app/dns/nameserver_cached.go` | SERVFAIL fallback integration, stale-while-revalidate |
| `app/dns/nameserver.go` | IPv4/IPv6 preference support |
| `app/dns/config.proto` | DNS config fields for new features |
| `common/protocol/quic/sniff.go` | Full QUIC SNI sniffer with ECH support, DCID cache, CRYPTO frame accumulation |
| `common/protocol/tls/sniff.go` | Truncated ClientHello SNI extraction (ECH split across QUIC packets) |
| `proxy/freedom/freedom.go` | Pool + sticky resolver integration, sendThrough: origin, UDP/TCP separation |
| `proxy/freedom/config.proto` | UDPConfig fields for socket pool, sticky resolver, TCP warm pool |
| `infra/conf/freedom.go` | Config parsing for udpConfig |
| `transport/internet/system_dialer.go` | resolveSrcAddr with family-mismatch guard, loopback guard |
| `transport/internet/dialer.go` | LookupForIP queries both A and AAAA regardless of source IP family |
| `transport/internet/udp/hub.go` | UDP hub integration for QUIC sniffing |
| `core/core.go` | Version tracking |

---

## How It Works

### The Problem

When you use DNS hijacking (e.g., Control D) to point youtube.com at your VPS:

1. Chrome resolves youtube.com to your VPS IP (e.g., 85.155.228.208)
2. Chrome sends QUIC Initial (long header) to VPS:443
3. xray sniffs SNI from the ClientHello and identifies the destination
4. xray forwards to Google
5. Google replies and xray forwards back to Chrome

This works for the Initial (step 2) because long headers carry the ClientHello with SNI. But 1-RTT short headers (step 5+) are encrypted — they carry no SNI. xray has no way to know where to send them.

### The Solution: UDP Socket Pool with DCID Demuxing

The UDP socket pool shares one outbound UDP socket per destination IP. When a QUIC session sends its first packet, the pool registers the client's SCID and DCID in a demux map. When the server replies, the pool parses the reply's DCID and routes it to the correct session.

```
Chrome sends QUIC Initial (DCID=A, SCID=B)
  -> xray sniffs SNI -> freedom dials Google IP
  -> pool.Acquire(googleIP) -> pooledSocket
  -> WriteTo registers DCID=A and SCID=B in demux map
  -> Packet sent to Google

Google replies (DCID=B, matches Chrome's SCID)
  -> pool readLoop parses DCID=B
  -> demux[B] -> session inbox -> Chrome
```

**Why this works for h3 test sites:** One QUIC connection per destination IP. The SCID is non-zero, so server replies have a matching DCID. Demuxing works cleanly.

**Why this does not work for YouTube:** YouTube opens multiple parallel QUIC connections to the same Google IP. Chrome uses 0-length SCID (server replies have DCID=empty). CID rotation (NEW_CONNECTION_ID frames) changes the DCID mid-connection. These factors break DCID-based demuxing.

### The Sticky DNS Resolver

YouTube rotates CDN edge hostnames every 60-90 seconds. Public DNS cannot keep up — new hostnames return NXDOMAIN before DNS caches them.

The sticky resolver:
1. Caches the first successful DNS resolution per hostname (TTL: 300s recommended)
2. Supports wildcard caching (*.googlevideo.com) for sibling hostnames
3. Returns stale entries immediately while refreshing in the background (stale-while-revalidate)
4. Falls back to sibling IPs on SERVFAIL (same CDN edge family serves same content)

### The TCP Warm Pool

Pre-warms TCP connections to commonly-accessed destinations. When Chrome requests the next video segment, the connection is already established (saves ~100-200ms of TCP+TLS handshake per request).

---

## Configuration

### Recommended Config (DNS Hijacking Mode)

```json
{
  "log": {
    "loglevel": "warning",
    "error": "/var/log/xray/error.log"
  },
  "dns": {
    "cacheSize": 1000,
    "serveStale": true,
    "servers": ["127.0.0.1", "[::1]"]
  },
  "inbounds": [
    {
      "listen": ["YOUR_VPS_IPV4", "YOUR_VPS_IPV6"],
      "port": 443,
      "protocol": "dokodemo-door",
      "tag": "in-443",
      "settings": { "network": "tcp,udp" },
      "sniffing": { "enabled": true, "destOverride": ["tls", "quic"] },
      "streamSettings": {
        "sockopt": {
          "tcpFastOpen": true,
          "tcpNoDelay": true,
          "tcpUserTimeout": 30000,
          "tcpKeepAlive": 15
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
          "domainStrategy": "UseIp",
          "tcpFastOpen": true,
          "tcpNoDelay": true,
          "tcpUserTimeout": 30000,
          "tcpKeepAlive": 15
        }
      },
      "settings": {
        "udpConfig": {
          "enableSocketPool": true,
          "enableStickyResolver": true,
          "preferIpv4": true,
          "sessionIdleTimeout": 1800,
          "stickyResolverTtl": 300,
          "poolStalenessTimeout": 300,
          "poolIdleTimeout": 600,
          "poolUnusedTimeout": 300,
          "enableTcpWarmPool": true,
          "tcpWarmPoolTimeout": 30,
          "preWarmFirstN": 10,
          "preWarmLearnVisits": 3,
          "enableTcpWarmPoolHealthCheck": true,
          "tcpWarmPoolMaxIdle": 120,
          "tcpConnectTimeout": 10,
          "edgeHealthCooldown": 30
        }
      }
    },
    { "protocol": "blackhole", "tag": "block" }
  ],
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

### UDP Config Options

| Option | Default | Recommended | Description |
|--------|---------|-------------|-------------|
| enableSocketPool | false | true | UDP socket pool with DCID demuxing (required for h3 test sites) |
| enableStickyResolver | false | true | Cache DNS with stale-while-revalidate |
| preferIpv4 | false | true | Prefer IPv4 from DNS results |
| sessionIdleTimeout | 300 | 1800 | UDP session idle timeout (seconds) |
| stickyResolverTtl | 60 | 300 | DNS cache TTL (seconds) — YouTube reuses CDN hostnames |
| poolStalenessTimeout | 300 | 300 | Socket staleness check (seconds) |
| poolIdleTimeout | 600 | 600 | Socket idle timeout (seconds) |
| poolUnusedTimeout | 300 | 300 | Unused socket timeout (seconds) |
| enableTcpWarmPool | false | true | Pre-warm TCP connections |
| tcpWarmPoolTimeout | 10 | 30 | Warm connection timeout (seconds) |
| preWarmFirstN | 5 | 10 | Number of connections to pre-warm |
| preWarmLearnVisits | 3 | 3 | Visits before pre-warming |
| enableTcpWarmPoolHealthCheck | false | true | Health check warm connections |
| tcpWarmPoolMaxIdle | 60 | 120 | Max idle warm connections |
| tcpConnectTimeout | 10 | 10 | TCP connect timeout (seconds) |
| edgeHealthCooldown | 30 | 30 | Edge health cooldown (seconds) |

### Tuning for YouTube TCP Performance

For faster video-to-video transitions (reduces stall when swiping):

- **stickyResolverTtl: 300** — YouTube reuses CDN hostnames within a session, so caching DNS for 5 minutes means most video-to-video transitions skip DNS entirely (saves 50-130ms per lookup)
- **tcpWarmPoolTimeout: 30** — Keep TCP warm for 30s (was 10s) — Chrome often needs the connection 15-20s later
- **preWarmFirstN: 10** — Pre-warm 10 connections (was 5) — YouTube fetches video, audio, and thumbnails simultaneously
- **tcpWarmPoolMaxIdle: 120** — Allow 120 idle connections (was 60) — YouTube opens many parallel connections

---

## Version History

### v26.11.116 (Current — Final Polished Version)

Base: v26.11.56 (last version where h3 test sites work AND YouTube falls back to TCP properly)

Kept improvements:
1. ECH ClientHello SNI extraction from truncated QUIC packets (v26.11.75)
2. Packet slicing in udp_pool readLoop (v26.11.81)

Removed (experimental code that caused stalling):
- SNI cache (v26.11.109) — created duplicate connections
- connBySrc (v26.11.110) — fragile conn lifecycle
- directWrite (v26.11.111) — bypassed pipe but did not fix root cause
- Silent drop (v26.11.114) — lost packets instead of routing them
- TPROXY (v26.11.116) — does not work with DNS hijacking

### v26.11.56 (Last stable base)

- Synthetic dest + Solution A (srcIndex-based routing for short headers)
- SplitCoalesced in udpConn.Write (no truncate to 1250)
- Original v26.11.0 worker (silent drop for demux misses)
- h3 test sites work, YouTube falls back to TCP

### v26.11.54 (Proven QUIC support for h3 test sites)

- UDP socket pool with DCID-based reply demuxing
- Sticky resolver with wildcard cache + stale-while-revalidate
- QUIC CID migration handling
- h3 test sites (quic.nginx.org, cloudflare-quic.com) work over QUIC

### v26.11.0 (First fully functional fork)

- All four architectural fixes working together
- Extended UDP timeout (30 minutes)
- Sticky DNS resolver
- UDP socket pool
- QUIC CID migration

### v26.10.0-v26.10.43 (Multi-IP + source-IP binding)

- Multi-IP inbound listen (array of IPs)
- sendThrough: "origin" for deterministic source-IP binding
- Family-mismatch guard in resolveSrcAddr
- Loopback guard to prevent EADDRNOTAVAIL

### v26.9.9 (Initial fork)

- Extended UDP timeout from 2 minutes to 30 minutes
- Sticky DNS resolver with IPv4/IPv6 preference
- NXDOMAIN edge rotation handling (wildcard cache for *.googlevideo.com)
- UDP socket pool with dead-socket detection

---

## What We Tried and Why It Did Not Work (v26.11.101-v26.11.115)

Over 15 versions, we attempted to make YouTube work over QUIC. Every attempt failed because of the fundamental limitation: xray cannot know the destination for QUIC 1-RTT short headers without TPROXY + WireGuard.

| Version | Approach | Why it failed |
|---------|----------|---------------|
| v26.11.101 | lastActiveCh for 0-SCID | Only worked for long headers with empty DCID |
| v26.11.103 | Source-port pool keying | Eliminated sharing but did not fix CID rotation |
| v26.11.105 | Extend lastActiveCh to all demux misses | Replies delivered but Chrome still stalled |
| v26.11.107 | Synthetic dest + Solution A | Short headers still created new conns to 127.0.0.1 loop |
| v26.11.109 | SNI cache by source address | Created duplicate connections, overwrote connBySrc |
| v26.11.110 | connBySrc direct conn cache | Fragile conn lifecycle, misses when conn dies |
| v26.11.111 | directWrite bypass | ACKs reached Google but data still stalled after ~50KB |
| v26.11.114 | Silent drop for unmatched short headers | Prevented 127.0.0.1 loop but lost packets |
| v26.11.115 | Route ALL packets through existing conn | Long headers still created new conns |
| v26.11.116 | TPROXY | Does not work with DNS hijacking (only works with WireGuard) |

Root cause: Without TPROXY + WireGuard, xray cannot know the destination IP for QUIC 1-RTT short headers. This is a protocol-level limitation, not a code bug.

---

## Bugs We Hit and Fixed

1. **Tab vs newline in struct definition** — Tab character between fields caused Go to interpret the second field as part of the first's comment. x86 build succeeded (cached), ARM64 failed. Fix: replaced tab with newline. Lesson: always go clean -cache before building.

2. **Calling IP() on a DomainAddress** — destination.Address.IP() panicked when destination was a domain (SNI-sniffed traffic). Fix: use conn.RemoteAddr() (always an IP after dial). Lesson: xray's net.Address is a discriminated union.

3. **Pool init after early return** — Pool init placed after usesDialerProxy early return. Fix: moved to top of Init.

4. **65535-byte buffer sent instead of packet[:n]** — readLoop sent the full pool buffer instead of the actual packet length. SplitCoalesced saw garbage, failed, and caused EMSGSIZE. Fix: getPacket() returns b[:cap(b)], readLoop sends packet[:n].

5. **Truncate to 1250 corrupted QUIC packets** — v26.11.58 added truncate as EMSGSIZE fallback. Chrome saw malformed data and stalled. Fix: removed truncate entirely. QUIC retransmits dropped packets (correct behavior).

6. **SNI cache created duplicate connections** — v26.11.109's SNI cache created NEW freedom.Process for cached packets, overwriting connBySrc. Fix: removed SNI cache.

7. **Broad chmod +x on all files** — A chmod +x during development made all 1100+ files executable (mode 755). GitHub showed our commit as the last modifier for files we never touched. Fix: git filter-branch to rewrite history, reverting all non-script files to mode 644.

---

## Building

```bash
# AMD64
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w" -o xray-linux-amd64 ./main

# ARM64
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "-s -w" -o xray-linux-arm64 ./main
```

## Installation

```bash
wget https://github.com/cddeppe/Xray-quiclink/releases/download/v26.11.116/xray-linux-amd64
chmod +x xray-linux-amd64
mv xray-linux-amd64 /usr/local/bin/xray

mkdir -p /etc/xray
cp example-configs/vps-consolidated.json /etc/xray/config.json
# Edit config to match your IPs

systemctl enable xray
systemctl start xray
```

## Known Limitations

1. **YouTube over QUIC does not work.** QUIC 1-RTT short headers are encrypted (no SNI). Without TPROXY + WireGuard, xray cannot determine the destination. YouTube falls back to TCP cleanly.

2. **Only QUIC, not non-QUIC UDP.** The pool's reply demuxing relies on parsing QUIC DCID. Non-QUIC UDP (DNS, games, WireGuard) falls back to the existing per-session dial path.

3. **Pool keys on destination IP, not hostname.** CDNs that rotate IPs aggressively create separate pooled sockets per IP. Could be improved by pooling on hostname, but adds complexity.

4. **CID length defaults to 8 for short headers.** If a QUIC variant uses a different default CID length and the first packet is a short header, the parser will get the wrong CID. In practice, handshakes always start with a long header.

5. **TPROXY does not work with DNS hijacking.** TPROXY only works with routed tunnels (WireGuard). The tproxy/ directory contains setup scripts, but they are only useful with a WireGuard architecture.

---

## Maintenance

### Rebasing Against Upstream

```bash
git remote add upstream https://github.com/XTLS/Xray-core.git
git fetch upstream
git rebase upstream/main
# Resolve conflicts in:
# - app/proxyman/inbound/worker.go
# - proxy/freedom/freedom.go
# - proxy/freedom/udp_pool.go
# - common/protocol/tls/sniff.go
# - common/protocol/quic/sniff.go
```

### Considered But Not Built

1. **HTTP/2 stream-aware routing** — requires custom CA (security risk, breaks transparent setup)
2. **Pool on hostname instead of IP** — adds DNS re-resolution complexity, marginal benefit
3. **NEW_CONNECTION_ID frame tracking** — current srcIndex fallback handles common case
4. **GSO/GRO for outbound** — batch syscalls for throughput, not needed for single user
5. **WireGuard + TPROXY** — the only way to make YouTube over QUIC work. Would require switching from DNS hijacking to a routed tunnel architecture.

---

## License

[Mozilla Public License Version 2.0](LICENSE)

This fork is based on [Xray-core](https://github.com/XTLS/Xray-core) by the Project X community. All upstream license terms apply to the original code. Fork-specific additions are licensed under the same MPL-2.0.

## Credits

- [Xray-core](https://github.com/XTLS/Xray-core) — the upstream project this fork is based on
- [Project X](https://github.com/XTLS) — the community behind xray-core
- All contributors to the upstream project whose work this fork builds upon
