# Handoff: Xray-core fork

This document captures the full context of the fork — what we built, why, how it was diagnosed, what bugs we hit, and how to maintain it. Written for future reference and for anyone who inherits or contributes to this fork.

## TL;DR

Three features added to xray-core for transparent proxy setups that forward QUIC end-to-end:

1. **QUIC connection migration** (always on) — handles source-port and CID changes mid-connection
2. **UDP socket pool** (opt-in via JSON `udpConfig.enableSocketPool`; legacy env var `XRAY_UDP_POOL=1` for older deployments) — shares one outbound UDP socket per destination across many inbound QUIC sessions
3. **HTTP/3 end-to-end** (v26.11.x) — fixes coalesced datagram truncation, SNI loss on short headers, and demux misses that previously made browsers fall back to h2 (TCP). See the dedicated section below.

The first two features are in production and eliminated mobile client stalls on a multi-hop transparent proxy chain. The v26.11.x work finally made HTTP/3 (QUIC) work end-to-end through the proxy — browsers no longer fall back to h2 over TCP.

## The actual problem we were solving

### Setup

- A home network uses DNS hijack (via a custom DNS resolver) to point certain domains at a multi-hop chain of xray proxies
- Each hop is a dokodemo inbound then freedom outbound, UDP enabled end-to-end
- The first hop's freedom re-resolves the SNI-sniffed domain to reach the next hop
- The final hop's freedom re-resolves to reach the real destination
- End-to-end UDP/QUIC preserved through all hops

### Symptom

Mobile apps (and to a lesser extent desktop browsers) would stall every few minutes when streaming video. Desktop browsers were less affected (graceful TCP fallback); mobile apps less so.

### Diagnosis journey

1. **First hypothesis:** QUIC connection migration (source port change with same DCID) breaking xray's 4-tuple-keyed session map.
2. **Built CID migration fork** — handles source-port migration with same DCID.
3. **Tested — mobile still stalled.** Looked at logs, found the mobile app created many new QUIC connections per minute (each with fresh DCID and source port), not migrations.
4. **Pcap analysis on the final hop** — confirmed it was creating one new outbound UDP socket per new QUIC connection. Each socket had kernel overhead + forced new QUIC handshake.
5. **Built UDP socket pool** — shares one outbound UDP socket per destination IP:port across all inbound sessions.
6. **Hit three bugs during deployment** (see below).
7. **Final test** — mobile video plays without stalls. Pool verified working: 1 source port per destination IP, no redundant socket creation.

## Architecture

### Files changed

- `common/protocol/quic/dcid.go` (new) — QUIC DCID parser
- `common/protocol/quic/dcid_test.go` (new) — Tests for the parser
- `app/proxyman/inbound/worker.go` (modified) — CID-based session lookup for migration
- `proxy/freedom/udp_pool.go` (new) — UDP socket pool with DCID-based reply demuxing
- `proxy/freedom/freedom.go` (modified) — Wire pool into Process(), gated by `config.UdpConfig.EnableSocketPool` (JSON canonical; legacy `XRAY_UDP_POOL=1` env var fallback)

### Component: dcid.go

Parses the QUIC Destination Connection ID from any QUIC packet:
- Long headers (Initial, 0-RTT, Handshake, Retry): DCID length is in the packet (byte 5), DCID follows
- Short headers (1-RTT): DCID length is NOT in the packet — defaults to 8 (Chrome/Firefox/Safari default). Use `ParseShortHeaderDCIDWithLen` for known lengths.

Public API:
- `ParseDCID(packet []byte) (dcid []byte, isLong bool, err error)` — main entry point
- `ParseShortHeaderDCIDWithLen(packet []byte, cidLen int) ([]byte, bool, error)` — for known CID lengths
- `MaxCIDLen = 20` (RFC 9000 section 17.2)
- Errors: `ErrNotQUIC`, `ErrTooShort`, `ErrBadCILen`

Reference: RFC 9000 section 17.2 (long), section 17.3 (short), RFC 9369 (QUIC v2).

### Component: worker.go (CID migration)

The `udpWorker` struct gets two new maps:
- `dcidIndex map[string]connID` — DCID hex then connID (for source-port migration with same DCID)
- `srcIndex map[string]connID` — src.String() then connID (for CID rotation with source port change)

On packet arrival:
1. `tryQUICMigration(packet, id)` parses the packet's DCID
2. Looks up `dcidIndex[dcidHex]` — if found with different src, it's a migration. Update conn's src, re-key in activeConn and dcidIndex, return existing conn.
3. If DCID lookup misses, looks up `srcIndex[srcKey]` — if found with different DCID, it's CID rotation (aggressive CID rotation). Reuse conn, add new DCID to dcidIndex, return existing conn.
4. If both miss, fall back to existing `getConnection(id)` path.

`recordDCID` and `recordSrc` populate the maps for new flows.

`removeConn` and `clean()` clean both maps on conn close.

Logs:
- `QUIC migration detected: DCID <hex> from <old src> to <new src>`
- `QUIC CID rotation detected: new DCID <hex> from <src>`

### Component: udp_pool.go

The `UDPSocketPool` struct maps destination IP:port to `*pooledSocket`.

`Acquire(dest *net.UDPAddr)` returns a `*pooledConn` (refcounted handle). Many sessions can hold the same `*pooledSocket` concurrently.

`pooledSocket` has:
- `conn net.PacketConn` — the shared UDP socket
- `refCount int` — number of sessions using it
- `demux map[string]chan<- readResult` — SCID hex to session inbox channel
- `readLoop()` goroutine — reads packets, parses DCID, routes to the right session's inbox

`pooledConn` has:
- `inbox chan readResult` — per-session packet channel
- `scids map[string]bool` — CIDs this session has sent
- `WriteTo(b []byte, addr net.Addr)` — auto-registers SCID on long headers, writes to shared socket
- `ReadFrom(p []byte)` — blocks on inbox channel
- `Close()` — releases refcount, removes CIDs from demux

`PooledPacketReader` and `PooledPacketWriter` implement `buf.Reader` and `buf.Writer` for integration with freedom's existing I/O loop.

### Component: freedom.go integration

In `Handler`:
- Added `socketPool *UDPSocketPool` field

In `Init`:
- Pool init at the **top** (before `usesDialerProxy` early return) — bug we hit
- Only initializes if `config.UdpConfig.EnableSocketPool` is true (JSON `udpConfig.enableSocketPool` is the canonical switch; the legacy `XRAY_UDP_POOL=1` env var is a fallback for older deployments that haven't migrated to the JSON struct)

In `Process`:
- After `dialer.Dial()`, before reader/writer assignment
- Branch: if destination is not TCP and h.socketPool is not nil
- Use `conn.RemoteAddr()` (already-resolved IP) for pool key — bug we hit (was `destination.Address.IP()` which panics on domain addresses)
- Acquire `pooledConn`, defer its Close
- Use `PooledPacketReader`/`PooledPacketWriter` instead of regular `NewPacketReader`/`NewPacketWriter`
- Falls back to existing path if pool disabled

## Bugs we hit (and fixed)

### Bug 1: Tab vs newline in struct definition

First commit had a tab character between `src` and `dcid` field declarations in `udpConn` struct. Go interpreted `dcid` as part of `src`'s comment, so `dcid` field was never declared. x86 build succeeded (cached), ARM64 cross-build failed with "conn.dcid undefined".

Fix: replaced tab with newline.

Lesson: always build with clean cache (`go clean -cache`) to catch this kind of bug.

### Bug 2: Calling IP() on a DomainAddress

`h.socketPool.Acquire(...)` with `destination.Address.IP()` panicked when destination was a domain (which is the case for QUIC traffic that was SNI-sniffed). Error: `panic: Calling IP() on a DomainAddress`.

Fix: use `conn.RemoteAddr()` (always an IP after `dialer.Dial()`).

Lesson: xray's `net.Address` is a discriminated union — `IP()` panics on `DomainAddress`. Always check `.Family().IsIP()` or use the already-resolved address from the dialed connection.

### Bug 3: Pool init after usesDialerProxy early return

Pool init was placed in `Init` AFTER the `if h.usesDialerProxy { return nil }` block. When freedom was used as a non-final outbound (with `dialerProxy` set), the pool init never ran.

Fix: moved pool init to the **top** of `Init`, before the `usesDialerProxy` check.

Lesson: when adding init code, place it before any early returns — or refactor the function to avoid early returns.

## Deployment notes

### Binaries

Build both architectures from the repo root:

    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o xray-pool-amd64 ./main
    GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o xray-pool-arm64 ./main

Distribute binaries via a shared network drive or copy directly to each server.

### Enabling the pool (canonical: JSON config)

The canonical way to enable the pool is the JSON `udpConfig` block on each freedom outbound in `config.json`:

    {
      "outbounds": [
        {
          "protocol": "freedom",
          "settings": {
            "udpConfig": {
              "enableSocketPool": true
            }
          }
        }
      ]
    }

Other `udpConfig` fields (all optional, see `proxy/freedom/config.proto` for the full `UDPConfig` proto): `enableStickyResolver`, `preferIpv4`, `preferIpv6`, `sessionIdleTimeout`, `poolStalenessTimeout`, `poolIdleTimeout`, `poolUnusedTimeout`, `stickyResolverTtl`, `enableTcpWarmPool`, `tcpWarmPoolTimeout`, `preWarmCount`, `preWarmFirstN`, `preWarmLearnVisits`.

Reload with `systemctl reload xray` (SIGHUP) or `systemctl restart xray`.

### Legacy: env var drop-in (deprecated)

Older deployments may still use the env var drop-in. This is a legacy fallback for configs that haven't migrated to the JSON `udpConfig` struct. To use it, create `/etc/systemd/system/xray.service.d/udp-pool.conf` on each server that should have the pool active, with content:

    [Service]
    Environment=XRAY_UDP_POOL=1

Then run `systemctl daemon-reload` and `systemctl restart xray`. New deployments should prefer the JSON `udpConfig.enableSocketPool` field.

### Configuration checklist per server

- Pool fork binary installed at `/usr/local/bin/xray`
- UDP enabled on inbounds: `"network": "tcp,udp"` (where appropriate)
- Policy section in `config.json` with `connIdle: 1800` (30 min idle timeout)
- JSON `udpConfig.enableSocketPool` set on the freedom outbound (canonical; or legacy `XRAY_UDP_POOL=1` env var drop-in)

## Known limitations

1. **Only QUIC, not non-QUIC UDP.** The pool's reply demuxing relies on parsing QUIC DCID. Non-QUIC UDP (DNS, games, WireGuard) falls back to the existing per-session dial path. This is intentional — non-QUIC UDP doesn't create many parallel connections to the same destination, so pooling wouldn't help.

2. **Pool keys on destination IP, not hostname.** Some CDNs rotate IPs aggressively (many unique IPs in minutes of playback). Each gets its own pooled socket. Could be improved by pooling on hostname (with re-resolution), but adds complexity.

3. **Short-header CID length bootstrapping.** As of v26.11.37, the pool learns the short-header DCID length from the client's Initial SCID length and stores it per-socket (`shortHeaderCIDLen`, atomic). Before an Initial is observed on a fresh socket, the readLoop falls back to `DefaultShortHeaderCIDLen` (8), which matches Firefox and is also the correct bootstrap behavior for Chrome/Edge's 0-length SCID case (handled explicitly as of v26.11.38). The pre-v26.11.37 text below is preserved for context: long headers always carry the DCID length, so the parser only relies on the default/learned length when the first packet on a socket is a short header (which doesn't happen for a normal handshake but can happen for late-arriving packets on a freshly-created socket).

4. **Config mechanism (was: env var, not config field).** Pool is enabled via the JSON `udpConfig.enableSocketPool` field, backed by the `UDPConfig` proto message in `proxy/freedom/config.proto` (with full config validation through the proto-generated getters). The `XRAY_UDP_POOL=1` env var is a legacy fallback for older deployments. For an upstream PR, the JSON field is already a proper `Config` proto field — only minor polish (field-level docs) is needed.

5. **Tests (was: no automated tests for the pool).** `dcid.go` and `split.go` have unit tests. As of v26.11.37, `udp_pool.go` has `comprehensive_test.go` (478 lines), `production_test.go` (218 lines), and `cidlen_test.go` (187 lines) covering multiple sessions to same dest, session close, concurrent access, reply demuxing, CID length learning, and the v26.11.34 demux-lifecycle fix. The earlier "no automated tests" limitation is no longer true.

6. **No idle reaper.** Sockets with refcount=0 stay alive forever. Should add a goroutine that closes them after an idle timeout (currently the pool size is bounded by the number of unique destinations, which is small).

## Maintenance

### Rebasing against upstream xray-core

When upstream xray-core releases new versions:

    cd <repo>
    git remote add upstream https://github.com/XTLS/Xray-core.git
    git fetch upstream
    git rebase upstream/main
    # Resolve conflicts in:
    # - app/proxyman/inbound/worker.go (CID migration, v26.11.28 coalesced-datagram split)
    # - proxy/freedom/freedom.go (pool integration, v26.11.32 route-all-QUIC, v26.11.35 source to Acquire)
    # - proxy/freedom/udp_pool.go (v26.11.x source SCID cache, shortHeaderCIDLen, no-remove-on-Close, isQUICPacket)
    # - app/dispatcher/default.go (v26.11.31 UDP SNI cache)
    # - common/protocol/quic/split.go (v26.11.28 NEW file — SplitCoalesced)
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o xray-pool-amd64 ./main
    GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o xray-pool-arm64 ./main
    # Distribute binaries and deploy

### Adding a new server to the deployment

1. Get the pool binary onto the new server (via network drive or direct copy)
2. Install at `/usr/local/bin/xray`
3. Enable UDP on 443 inbounds in `/etc/xray/01-https.json` (`"network": "tcp,udp"`)
4. Add policy section to `/etc/xray/config.json` with `connIdle: 1800`
5. Enable pool if the server handles UDP traffic that benefits from pooling: set JSON `udpConfig.enableSocketPool` on the freedom outbound in `/etc/xray/config.json` (canonical), or create the legacy `XRAY_UDP_POOL=1` env var drop-in
6. Restart xray

### Roll back from a broken deployment

On any server:

    sudo systemctl stop xray
    LATEST_BACKUP=$(ls -t /usr/local/bin/xray.bak.* | head -1)
    sudo cp "$LATEST_BACKUP" /usr/local/bin/xray
    sudo rm -f /etc/systemd/system/xray.service.d/udp-pool.conf
    sudo systemctl daemon-reload
    sudo systemctl start xray

## Upstream PR plan (future work)

If you want to upstream this:

1. **Open an issue on https://github.com/XTLS/Xray-core/issues** describing the problem and proposed design. Get maintainers' input before writing the PR.

2. **Config field for upstream PR.** The JSON `udpConfig.enableSocketPool` field is already a proper `UDPConfig` proto message in `proxy/freedom/config.proto` (field `udp_config` = 9 on the freedom `Config`). For an upstream PR, all that's needed is field-level documentation, a proper JSON schema example in the docs, and removing the legacy `XRAY_UDP_POOL=1` env var fallback (or keeping it explicitly as a deprecated alias). No proto changes are required.

3. **Write tests for the pool.** `proxy/freedom/udp_pool_test.go` (already exists as `comprehensive_test.go`, `production_test.go`, `cidlen_test.go` as of v26.11.37). For an upstream PR, expand them to cover:
   - Two sessions to same destination share one socket
   - Session close releases refcount
   - Concurrent access doesn't race
   - Reply demuxing routes to correct session
   - Non-QUIC UDP falls back to existing path

4. **Add idle reaper.** Goroutine that closes sockets with refcount=0 after a timeout.

5. **Submit PR.** Clean commit history, link to issue, follow xray-core's contribution guidelines.

## Considered but not built

These were considered during the project but not implemented:

1. **HTTP/2 stream-aware routing** — would solve browser connection coalescing without needing per-hostname IPs. Rejected: requires custom CA on home devices (security risk, breaks "transparent" setup).

2. **Pool on destination hostname instead of IP** — would reduce source port count by pooling all subdomains of a service. Rejected for now: adds DNS re-resolution complexity, marginal benefit.

3. **Multiple-CID support via NEW_CONNECTION_ID frames** — current `srcIndex` fallback handles the common case, but proper NEW_CONNECTION_ID tracking would be more correct. Could be future improvement.

4. **GSO/GRO for outbound** — would batch syscalls for higher throughput. Not needed for this use case (single user, mobile video).

## Final Tuning (Post-Initial Release)

After extensive testing with the YouTube Android app, we discovered that YouTube rotates its CDN edge hostnames every 60-90 seconds. This caused videos to occasionally get "stuck at 0:00" when swiping to a new video after watching one for a minute or two.

### The Root Cause
1. The Sticky Resolver's wildcard cache (`*.googlevideo.com`) was permanent (no TTL).
2. When YouTube rotated the edge, the wildcard cache still held the old (now dead) IP.
3. The pool created new sockets to this dead IP.
4. The QUIC handshake went into a black hole, and the video sat at 0:00.

### The Fix: Stale-While-Revalidate
1. **Wildcard TTL:** Set to 60 seconds to match YouTube's rotation window.
2. **Stale-While-Revalidate:** When the wildcard expires, the stale IP is returned immediately (so the current request isn't blocked), AND a background goroutine does a fresh DNS resolution to update the cache for the next request.
3. **Pool Staleness Check:** Reduced from 60 seconds to 30 seconds. If a socket hasn't received a reply in 30 seconds, it is marked dead and evicted, ensuring the next request creates a fresh socket to a live edge.

This combination ensures that:
- The first request after a rotation gets the stale IP (fast, but might fail).
- The background refresh updates the cache immediately.
- The next request (e.g., the browser's retry) gets the fresh, live IP.
- The video plays smoothly without getting stuck at 0:00.

## Production-Ready Refactor

The fork was refactored to be production-ready for potential upstream inclusion:

### 1. Proper UDPConfig struct
- Replaced environment-variable-only configuration with a proper `UDPConfig` proto message in `proxy/freedom/config.proto` (the `UDPConfig` message is wired onto the freedom `Config` as field `udp_config` = 9)
- `Handler.Init` reads the JSON struct directly via `config.UdpConfig.EnableSocketPool`, `config.UdpConfig.EnableStickyResolver`, etc. (there is no separate `parseUDPConfig` function; the proto-generated getters on `*UDPConfig` handle defaults)
- Supports `EnableSocketPool`, `EnableStickyResolver`, `PreferIpv4`, `PreferIpv6`, plus the tuning fields (`SessionIdleTimeout`, `PoolStalenessTimeout`, `PoolIdleTimeout`, `PoolUnusedTimeout`, `StickyResolverTtl`, `EnableTcpWarmPool`, `TcpWarmPoolTimeout`, `PreWarmCount`, `PreWarmFirstN`, `PreWarmLearnVisits`)
- The legacy `XRAY_UDP_*` env vars are kept as a fallback for older deployments; the JSON struct is canonical

### 2. IPv4/IPv6 Preference
- Added `PreferIPv4` and `PreferIPv6` fields to the `StickyResolver` struct
- When `PreferIPv4` is true, the resolver only picks IPv4 addresses from DNS results
- When `PreferIPv6` is true, the resolver only picks IPv6 addresses
- If neither is set, it uses the first address returned (dual-stack auto)
- Configured via the JSON `udpConfig.preferIpv4` / `udpConfig.preferIpv6` fields (canonical); legacy env vars `XRAY_UDP_PREFER_IPV4=1` / `XRAY_UDP_PREFER_IPV6=1` remain as a fallback

### 3. Configuration Mechanism (Current)
All features are configured via the JSON `udpConfig` struct on each freedom outbound (defined in `proxy/freedom/config.proto` as the `UDPConfig` proto message). The env vars below are a legacy fallback for older deployments that haven't migrated to JSON; the JSON struct is canonical. `Init` reads the JSON struct directly (`config.UdpConfig.EnableSocketPool`, `config.UdpConfig.EnableStickyResolver`, etc.).
- JSON `udpConfig.enableSocketPool` (legacy env: `XRAY_UDP_POOL=1`) — Enable the UDP socket pool
- JSON `udpConfig.enableStickyResolver` (legacy env: `XRAY_UDP_STICKY=1`) — Enable the sticky DNS resolver
- JSON `udpConfig.preferIpv4` (legacy env: `XRAY_UDP_PREFER_IPV4=1`) — Force IPv4 preference (optional)
- JSON `udpConfig.preferIpv6` (legacy env: `XRAY_UDP_PREFER_IPV6=1`) — Force IPv6 preference (optional)

### 4. Final Tuning Parameters
- Wildcard TTL: 60 seconds (matches YouTube's CDN edge rotation)
- Pool staleness check: 30 seconds (silently dropped connections)
- Idle reaper: 10 minutes (no replies) / 5 minutes (refCount=0)
- UDP worker timeout: 30 minutes (was 2 minutes in stock xray)

## v26.11.x: HTTP/3 End-to-End (The Real Fix)

The v26.10.x work (UDP socket pool, QUIC connection migration) made QUIC *forward* end-to-end through the proxy chain, but browsers still fell back to HTTP/2 over TCP. v26.11.x is the long debugging cycle that finally made HTTP/3 (QUIC) actually work end-to-end through the proxy.

### The problem

Browsers fell back to h2 (TCP) when using the proxy, even though QUIC was being forwarded. Three failure modes combined to break the QUIC handshake:

1. **The coalesced datagram problem.** QUIC servers (nginx, Cloudflare, Google) coalesce Initial + Handshake + 0-RTT packets into a single UDP datagram up to 65535 bytes via GSO. Forwarding this as a single UDP datagram requires IP fragmentation (path MTU ~1500), which is unreliable across PPPoE, VPN tunnels, IPv6, and many NAT/firewall setups. Lose one fragment and the whole datagram is gone — the browser never sees the handshake response and falls back to TCP.

2. **The SNI loss problem.** Only the QUIC Initial (long header) carries the SNI. Subsequent packets (short headers, 1-RTT) do not. xray's sniffer sniffs SNI on the first UDP packet of a flow; if that packet is a short header (normal mid-stream), sniffing fails and the packet is routed to the default destination `127.0.0.1:443` — a packet loop that kills the QUIC connection.

3. **The demux miss problem.** The pool demuxes reply packets by parsing the QUIC DCID. Several bugs caused the DCID lookup to miss: the short-header DCID was parsed with the wrong length (8 bytes when the actual length was 3), short headers bypassed the pool entirely (each got its own per-session socket with a different source port), and the DCID was removed from the demux map on `pooledConn.Close()` — but each UDP packet from the browser creates a new `pooledConn`, so the Initial's `pooledConn` closed before the reply arrived, evicting the DCID and turning every reply into a demux miss.

### The journey (key versions)

- **v26.11.0**: First "working" QUIC — pool forwards Initial + Handshake. Browsers still fell back to h2. Diagnosis began.
- **v26.11.19**: Sent ICMP "Fragmentation Needed" (Type 3 Code 4) to tell servers to send smaller packets. Didn't help — servers ignore ICMP for the Initial because the anti-amplification limit (RFC 9000 §8.1) requires them to coalesce Initial + Handshake in one datagram, and the Initial is at least 1200 bytes (§14.1).
- **v26.11.23**: Found that `readResult.n` was not being set by the readLoop; readers were copying 65535 bytes per packet, mostly garbage. Fixed the length propagation. Reduced memory bandwidth but did not fix h2 fallback.
- **v26.11.25–26**: Tried software IP-fragment reassembly in the readLoop. Wrong — the kernel already reassembles IP fragments before delivering the UDP datagram to userspace. Our reassembly was redundant and just added overhead. Removed in v26.11.30.
- **v26.11.28**: Added `SplitCoalesced` (new file `common/protocol/quic/split.go`) and called it from `udpConn.Write` in `app/proxyman/inbound/worker.go`. Splits coalesced datagrams into individual UDP datagrams on the outbound path. Each individual QUIC packet (Initial ~1250, Handshake ~200, 1-RTT ~1250) fits within a single IP frame — no IP fragmentation. Wire-compliant per RFC 9000 §12.2 (receivers MUST accept both coalesced and non-coalesced packets).
- **v26.11.30**: Removed the harmful reassembly loop added in v26.11.25–26.
- **v26.11.31**: Added UDP SNI cache in `app/dispatcher/default.go`. When sniffing succeeds for a long header (Initial), cache the source IP:port -> sniffed SNI. When a subsequent short header arrives from the same source, sniffing fails on the packet itself; look up the cache and reuse the cached SNI as the destination. Without this, short headers looped to `127.0.0.1` and killed the QUIC connection. TTL 5 minutes.
- **v26.11.32**: Routed ALL QUIC packets (long AND short headers) through the pool. Previously only long headers were routed; short headers used the per-session dial path, getting a different outbound socket (and a different source port) per packet — so the server saw fragmented source ports and couldn't map replies to a single 4-tuple.
- **v26.11.34**: Stopped removing the DCID from the demux map on `pooledConn.Close()`. See root cause (d) below. The readLoop now handles sends to closed inboxes gracefully (recover from panic, drop packet).
- **v26.11.35**: Added source-keyed SCID cache in `udp_pool.go`. When DNS rotation sends subsequent short-header packets to a DIFFERENT destination IP, those packets go to a different pooled socket. The server replies from that new IP with DCID = client's SCID (A), but the new socket's demux doesn't have A -> demux miss -> drop -> h2 fallback. The cache stores source IP:port -> client's SCID A when we see a long header; when a short header arrives from the same source, look up A and register it on the current socket's demux. TTL 5 minutes.
- **v26.11.36**: Diagnostic build with 28 `DIAG:` log lines tracing the full QUIC packet lifecycle (Initial sniff, split, pool Acquire, demux register, readLoop dispatch, demux hit/miss). Used to pinpoint which root cause was actually firing in production.
- **v26.11.37**: THE fix — learned the short-header DCID length from the client's SCID length. The readLoop was parsing short-header DCIDs using `DefaultShortHeaderCIDLen` (8), but the client used a 3-byte SCID, so the server's DCID for our connection was also 3 bytes. Parsing 3 bytes of DCID as 8 meant the demux key included 5 bytes of packet number -> wrong key -> demux miss -> drop -> h2 fallback. Now the socket's `shortHeaderCIDLen` is set atomically when the Initial's SCID length is observed, and the readLoop uses it for short-header parsing.
- **v26.11.38**: Clean production build. Removed all 28 `DIAG:` log lines. Added the 0-length SCID fix for Chrome/Edge (which use 0-length SCIDs in some scenarios — fall back to `DefaultShortHeaderCIDLen` when no SCID length has been observed yet).

### The 5 root causes

a. **Coalesced datagram truncation.** Servers coalesce Initial + Handshake into one 65535-byte UDP datagram (via GSO). Forwarding it required IP fragmentation, which is unreliable across the path MTU. Fix: v26.11.28 (`SplitCoalesced`) splits the datagram into individual UDP packets on the outbound path; no IP fragmentation needed.

b. **SNI loss on short headers.** Only the Initial (long header) carries SNI. Subsequent short-header packets don't, so the sniffer failed on them and routed them to the default destination `127.0.0.1:443` — a packet loop that killed the QUIC connection. Fix: v26.11.31 (UDP SNI cache) caches the sniffed SNI from the Initial and reuses it for short headers from the same source.

c. **Short headers bypassing the pool.** Only long headers were routed to the pool; short headers used the per-session dial path, getting a fresh outbound socket (and source port) per packet. The server saw fragmented source ports and demux misses proliferated. Fix: v26.11.32 routes ALL QUIC packets (long AND short) through the pool.

d. **DCID removed from demux on Close.** Each UDP packet from the browser triggers a separate `freedom.Process` call, each creating a new `pooledConn` with its own inbox. The Initial's `pooledConn` registers the client's SCID (A) as a DCID in the demux map. When that `pooledConn.Close()` fires (input pipe exhausted, timer fires), it REMOVED A from the demux. Subsequent short-header packets create new `pooledConns`, but they don't carry A — they carry the server's SCID (B') as their DCID. So A is never re-registered. All server replies (which use DCID = A) became demux misses. Fix: v26.11.34 — don't remove the DCID from demux on `Close()`. Let new `pooledConns` that register the same DCID overwrite the entry; the readLoop handles sends to closed inboxes gracefully (recover from panic, drop packet).

e. **Wrong short-header DCID length.** `readLoop` parsed short-header DCIDs using `DefaultShortHeaderCIDLen` (8 bytes). But the client used a 3-byte SCID, so the server's DCID for our connection was also 3 bytes. Parsing 3 bytes of DCID as 8 meant the demux key included 5 bytes of packet number -> wrong key -> demux miss -> drop -> h2 fallback. Fix: v26.11.37 — learn `shortHeaderCIDLen` from the client's Initial SCID length, store it atomically on the socket, and use it for short-header DCID parsing in the readLoop.

### Files changed in v26.11.x

- `common/protocol/quic/split.go` (NEW): `SplitCoalesced` function — parses a coalesced QUIC datagram and returns the byte offsets of each individual QUIC packet (long header + short header + Retry + Version Negotiation handling). Backed by `split_test.go`.
- `app/proxyman/inbound/worker.go`: `udpConn.Write` splits coalesced datagrams into individual UDP packets via `quic.SplitCoalesced`. Fast path for <=1250-byte datagrams (no split attempt). Falls through to a single `output` call if the buffer isn't coalesced or fails to parse.
- `app/dispatcher/default.go`: UDP SNI cache (`udpSNICache`). Caches sniffed SNI from long headers, reuses for short headers from the same source. TTL 5 minutes.
- `proxy/freedom/udp_pool.go`: source-keyed SCID cache (`sourceSCIDCache`), per-socket `shortHeaderCIDLen` (atomic, learned from the Initial SCID), do-not-remove-on-Close semantics (v26.11.34), `isQUICPacket` helper (matches BOTH long AND short headers, v26.11.32).
- `proxy/freedom/freedom.go`: passes the browser source IP:port to `Acquire` (so the source SCID cache can be keyed correctly, v26.11.35), routes ALL QUIC packets (long AND short) through the pool (v26.11.32).

### Known limitations (updated)

- **Chrome/Edge 0-length SCID**: handled as of v26.11.38. When no SCID length has been observed yet (no Initial seen on this socket), the readLoop falls back to `DefaultShortHeaderCIDLen` (8), which matches Firefox. Chrome/Edge use 0-length SCIDs in some scenarios; the fallback handles the bootstrapping case before the Initial arrives.
- **Pool keys by destination IP**: DNS rotation fragments demux because rotation sends packets to a different IP, hence a different pooled socket, whose demux doesn't have the client's SCID. Fixed by the source-keyed SCID cache (v26.11.35) — the SCID follows the source, not the destination.
- **No automated tests for `udp_pool.go`**: FALSE as of v26.11.37. Now has `comprehensive_test.go` (478 lines), `production_test.go` (218 lines), and `cidlen_test.go` (187 lines). Coverage: multiple sessions to same dest, session close, concurrent access, reply demuxing, CID length learning, demux lifecycle with the v26.11.34 fix.

### How to verify h3 works

1. Deploy the v26.11.38 binary to every hop in the proxy chain.
2. In the browser, clear the QUIC cache (chrome://net-internals/#sockets -> "Flush sockets"; or just restart the browser).
3. Open https://cloudflare-quic.com/cdn-cgi/trace in the browser.
4. Check the `http=` field in the response. It should read `http=http/3`. If it reads `http=http/2`, QUIC is still falling back — check the dispatcher logs for `udpSNICache` hits/misses and the pool logs for `demux miss` to narrow down which root cause is still firing.
