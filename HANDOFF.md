# Handoff: Xray-core fork

This document captures the full context of the fork — what we built, why, how it was diagnosed, what bugs we hit, and how to maintain it. Written for future reference and for anyone who inherits or contributes to this fork.

## TL;DR

Two features added to xray-core for transparent proxy setups that forward QUIC end-to-end:

1. **QUIC connection migration** (always on) — handles source-port and CID changes mid-connection
2. **UDP socket pool** (opt-in via `XRAY_UDP_POOL=1`) — shares one outbound UDP socket per destination across many inbound QUIC sessions

Both features are in production and have eliminated mobile client stalls on a multi-hop transparent proxy chain.

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
- `proxy/freedom/freedom.go` (modified) — Wire pool into Process(), gated by `XRAY_UDP_POOL=1`

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
- Only initializes if `os.Getenv("XRAY_UDP_POOL") == "1"`

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

### Pool env var drop-in

Create `/etc/systemd/system/xray.service.d/udp-pool.conf` on each server that should have the pool active, with content:

    [Service]
    Environment=XRAY_UDP_POOL=1

Then run `systemctl daemon-reload` and `systemctl restart xray`.

### Configuration checklist per server

- Pool fork binary installed at `/usr/local/bin/xray`
- UDP enabled on inbounds: `"network": "tcp,udp"` (where appropriate)
- Policy section in `config.json` with `connIdle: 1800` (30 min idle timeout)
- Pool env var drop-in (if pool should be active on this server)

## Known limitations

1. **Only QUIC, not non-QUIC UDP.** The pool's reply demuxing relies on parsing QUIC DCID. Non-QUIC UDP (DNS, games, WireGuard) falls back to the existing per-session dial path. This is intentional — non-QUIC UDP doesn't create many parallel connections to the same destination, so pooling wouldn't help.

2. **Pool keys on destination IP, not hostname.** Some CDNs rotate IPs aggressively (many unique IPs in minutes of playback). Each gets its own pooled socket. Could be improved by pooling on hostname (with re-resolution), but adds complexity.

3. **CID length defaults to 8 for short headers.** If a future QUIC variant uses a different default CID length and the session's first packet is a short header, the parser will get the wrong CID. Long headers always carry the length, so this is only an issue for "first packet is a short header" which doesn't happen in practice (handshake always starts with a long header).

4. **Pool env var, not config field.** Pool is enabled via env var, not a proper config field. For upstream PR, this needs to be a proper `Config` proto field with config validation.

5. **No automated tests for the pool.** `dcid.go` has unit tests, but `udp_pool.go` doesn't. Needs tests for: multiple sessions to same dest, session close, concurrent access, reply demuxing.

6. **No idle reaper.** Sockets with refcount=0 stay alive forever. Should add a goroutine that closes them after an idle timeout (currently the pool size is bounded by the number of unique destinations, which is small).

## Maintenance

### Rebasing against upstream xray-core

When upstream xray-core releases new versions:

    cd <repo>
    git remote add upstream https://github.com/XTLS/Xray-core.git
    git fetch upstream
    git rebase upstream/main
    # Resolve conflicts in:
    # - app/proxyman/inbound/worker.go (CID migration)
    # - proxy/freedom/freedom.go (pool integration)
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o xray-pool-amd64 ./main
    GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o xray-pool-arm64 ./main
    # Distribute binaries and deploy

### Adding a new server to the deployment

1. Get the pool binary onto the new server (via network drive or direct copy)
2. Install at `/usr/local/bin/xray`
3. Enable UDP on 443 inbounds in `/etc/xray/01-https.json` (`"network": "tcp,udp"`)
4. Add policy section to `/etc/xray/config.json` with `connIdle: 1800`
5. Enable pool if the server handles UDP traffic that benefits from pooling: create the env var drop-in
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

2. **Convert env var to a proper config field.** Add to `proxy/freedom/config.proto`:

       message Config {
         // ... existing fields
         bool udp_socket_pool = 9;
       }

   Regenerate proto bindings. Add config validation.

3. **Write tests for the pool.** `proxy/freedom/udp_pool_test.go` with:
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
