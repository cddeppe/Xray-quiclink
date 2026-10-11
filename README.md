# Xray-quiclink

A fork of [Xray-core](https://github.com/XTLS/Xray-core) focused on **transparent QUIC/HTTP3 proxying** for YouTube and h3 websites through a VPS using DNS hijacking.

## What This Fork Does

Standard xray-core is a Layer-4 proxy. QUIC (HTTP/3) is a Layer-7 protocol with encrypted short headers that carry no SNI. This creates a fundamental mismatch: xray can sniff the SNI from a QUIC Initial (long header), but cannot determine the destination for 1-RTT short headers.

This fork bridges that gap with a **UDP socket pool** that demuxes QUIC replies by Connection ID (CID), allowing transparent QUIC proxying without TPROXY, iptables, or WireGuard.

### What Works

| Feature | Status |
|---------|--------|
| **YouTube over QUIC (HTTP/3)** | ✅ Working — long videos, Shorts swiping, seeking, quality changes |
| h3 test sites (quic.nginx.org, cloudflare-quic.com) over QUIC | ✅ Working |
| YouTube over TCP (fallback) | ✅ Working |
| DNS hijacking mode (no WireGuard needed) | ✅ Working |
| Multi-IP inbound listen | ✅ Working |
| Deterministic source-IP binding (sendThrough: origin) | ✅ Working |
| TCP warm pool (faster video-to-video transitions) | ✅ Working |
| Sticky DNS resolver with wildcard cache | ✅ Working |

---

## How Upstream Xray-core Fails at QUIC Proxying

Upstream xray-core has several fundamental problems when proxying QUIC/HTTP3 traffic:

1. **Per-destination IP pool sockets.** The pool keys on `dest.String()` (e.g. `[2a00:1450:4017:4::8]:443`). Each different Google CDN edge IP gets its own socket with its own random source port. When Chrome switches videos and resolves to a different Google IP, Google sees a new source port, interprets this as QUIC connection migration, and initiates path validation — which stalls the connection for 25-30 seconds.

2. **Process lifecycle kills the inbox.** Each UDP packet from Chrome triggers `freedom.Process`. When Process returns (Chrome paused sending, or the inactivity timer fired), `defer pooledConn.Close()` fires — closing the inbox channel. Google's in-flight replies hit a closed channel and are dropped. Chrome never receives ACKs and declares the QUIC path dead.

3. **Socket eviction by the reaper.** The reaper (`evictStale`) checks `isIdle` (no replies in 600s) and `isUnused` (no writes in 300s). With a shared socket, one idle connection triggers eviction of the socket that ALL other connections are using — creating a new socket with a new source port.

4. **No activity tracking on the pool path.** `udpConn.lastActivityTime` is only updated by `udpConn.Write()` and `udpConn.ReadMultiBuffer()`. The pool path (`PooledPacketWriter` / `BufferedPacketReader`) bypasses these entirely — so `clean()` retires active connections after `sessionIdleTimeout` even while video is playing.

5. **No BufferedPacketReader.** When Process returns, `responseDone` stops reading from `PooledPacketReader`. Nobody drains the pool's inbox. Google's replies fill the inbox (256 cap) and are dropped. Chrome stalls at ~10 seconds (CID rotation point).

6. **No goroutine restart.** When Process returns, the inbound worker calls `removeConn` and closes the connection. The next packet from Chrome creates a brand new connection from scratch — new dial, new source port, new everything.

### How This Fork Fixes It

| Upstream Problem | This Fork's Fix |
|-----------------|-----------------|
| Per-destination IP pool sockets | Key pool by PORT ONLY (`:443`) — ONE socket, ONE source port for all Google IPs |
| Close kills the inbox | Don't close pooledConn on Process return; don't delete DCID from demux on Close |
| Reaper kills shared socket | Reaper only evicts dead + refCount==0 sockets; shared socket is never evicted |
| No activity tracking on pool path | `onActivity` callback fires on every WriteTo/ReadFrom, updates `lastActivityTime` |
| No BufferedPacketReader | Added BufferedPacketReader with readLoop that drains inbox even when Process is away |
| No goroutine restart | `callback()` restarts the Process goroutine when `processRunning == false`; no `removeConn` |

---

## Architecture: How YouTube QUIC Finally Worked

### The Problem

When proxying QUIC through a VPS using DNS hijacking, the proxy faces several challenges:

1. **Chrome uses 0-length SCID** — Google's 1-RTT replies have DCID=∅ (empty), making DCID-based demux routing impossible for post-handshake traffic
2. **CDN edge rotation** — YouTube rotates CDN edge hostnames, resolving to different Google IPs on each video switch
3. **CID rotation** — Chrome rotates its QUIC DCID at ~10 seconds, changing the connection identifier mid-stream
4. **Process lifecycle** — Each UDP packet from Chrome triggers a separate `freedom.Process` call; when Process returns, the outbound socket is destroyed, giving Google a new source port

### The Solution: 6 Key Innovations

#### 1. Port-Only Pool Keying (v26.11.204)

**The single most important fix.** The pool is keyed by **PORT ONLY** (`:443`), not by destination IP:port. This means ALL QUIC traffic to port 443 shares ONE pool socket with ONE source port.

**Before:** Chrome switches video → different googlevideo.com subdomain → different Google IP → different pool socket → **different source port** → Google sees connection migration → path validation → stall.

**After:** All Google IPs share one socket. Google sees the same source port regardless of which CDN edge it is. No path validation, no stall.

The DCID-based demux handles routing replies to the correct connection — the readLoop receives from ALL source IPs on the wildcard-bound socket, parses the DCID, and routes to the correct inbox.

#### 2. BufferedPacketReader (v26.11.201)

Decouples the pool's inbox from `freedom.Process`. When Process returns (video switch, CID rotation, timer fires), `responseDone` stops reading from `PooledPacketReader` → nobody drains `pooledConn.inbox` → inbox fills up (256 cap) → readLoop drops replies → Chrome never gets ACKs → stall at ~10 seconds.

`BufferedPacketReader` wraps `PooledPacketReader` with a background `readLoop` goroutine that continuously drains the underlying reader into an internal buffer (chan, cap 256). When Process returns, the readLoop keeps running — Google's replies keep being consumed and buffered. When the goroutine restarts, the new `responseDone` reads from the buffer, getting all accumulated replies — no stall.

**Critical:** The BufferedPacketReader must be closed when `responseDone` exits (`defer bpr.Close()`), otherwise the readLoop competes with the new Process's BufferedPacketReader for the same inbox — causing random stalls.

#### 3. Goroutine Restart (v26.11.196)

When `freedom.Process` returns (Chrome stopped sending, Google stopped replying, or timer fired), the inbound worker's `callback()` detects that `processRunning == false` and restarts the goroutine. The new Process reads from the same pipe, uses the same pool socket, and forwards data to Google with the same source port.

**Key:** `removeConn` is NOT called when Process returns — the connection mapping persists until `clean()` retires it after the idle timeout (SessionIdleSeconds, default 1800).

#### 4. Don't Delete DCID on Close (v26.11.198)

When `pooledConn.Close()` fires, the DCID is NOT deleted from the pool's demux map. Previously, deleting the DCID caused Google's in-flight replies (retransmissions, ACKs) to be silently dropped by readLoop (demux miss). Chrome's QUIC stack never received ACKs → declared the path dead → fell back to TCP after ~25s.

Now the DCID stays as a stale entry. The inbox channel is closed, so readLoop's send panics — but the panic is recovered and the stale entry is cleaned up. When a new connection registers the same DCID, the stale entry is overwritten.

#### 5. No Socket Eviction (v26.11.207)

The reaper (`evictStale`) previously checked `isIdle` (lastReplyTime > 600s) and `isUnused` (lastUsed > 300s). With port-only keying, the shared socket would get evicted when one connection was idle — removed from pool map → next Acquire creates new socket → new source port → stall.

Now the reaper ONLY evicts sockets that are `dead AND refCount==0` (truly abandoned). The shared socket is never evicted — it stays alive forever, keeping the source port stable.

#### 6. 30s ReadFrom Timeout + Input Pipe Interruption (v26.11.208-210)

When Google stops replying (Chrome swiped away from a Short), `ReadFrom` returns EOF after 30 seconds. This makes `BufferedPacketReader`'s readLoop exit, which makes `responseDone` return. `responseDone` then:
1. Calls `cancel()` to cancel the context
2. Calls `common.Interrupt(input)` to directly interrupt the input pipe (cancel alone doesn't work because `buf.Copy(input, writer)` blocks on `input.ReadMultiBuffer()` which doesn't check context)
3. Closes the BufferedPacketReader via `defer bpr.Close()`

This makes `requestDone` also return, so `task.Run` completes, Process returns, `processRunning` is set to false, and the goroutine restarts on the next packet.

#### 7. Activity Tracking via onActivity Callback (v26.11.212)

The inbound worker's `clean()` function retires connections after `sessionIdleTimeout` (default 1800s) of inactivity. It checks `udpConn.lastActivityTime`, which is updated by `udpConn.Write()` and `udpConn.ReadMultiBuffer()`.

**Problem:** `BufferedPacketReader` and `PooledPacketWriter` bypass `udpConn.Write/Read` entirely — they go through `pooledConn.WriteTo()` and `pooledConn.ReadFrom()` instead. So `lastActivityTime` was never updated, and `clean()` retired active connections after 30 minutes — causing sudden stalls on videos that had been playing for 30+ minutes.

**Fix:** Added an `onActivity` callback to `pooledConn`. It is called on every `WriteTo` (Chrome sends a packet) and every `ReadFrom` (Google replies). The callback is wired to `udpConn.UpdateActivity()`, which updates `lastActivityTime` via an atomic store. `clean()` now sees the connection as active and doesn't retire it.

The callback is set once during `freedom.Process` when the pooledConn is created:
```go
if updater, ok := inbound.Conn.(interface{ UpdateActivity() }); ok {
    pconn.onActivity = updater.UpdateActivity
}
```

No hot-path overhead — one nil check + one atomic store per packet (~5ns).

---

## Packet Flow

```
                          UDP/QUIC packet flow
  ┌────────┐  QUIC Initial   ┌───────────────────────────────┐   QUIC Initial  ┌────────┐
  │ Chrome │ ──────────────> │ VPS xray inbound (UDP :443)   │ ──────────────> │ Google │
  │ 0-SCID │  1-RTT data     │   udpWorker.callback()        │   (via pool)    │  CDN   │
  └────────┘ <─────────────  │   ├─ dcidIndex/srcIndex       │ <─────────────  └────────┘
     ▲      QUIC reply       │   ├─ udpConn (per-flow)       │   QUIC reply        │
     │                       │   └─ proxy.Process(ctx,UDP)   │                     │
     │                       └────────────┬──────────────────┘                     │
     │                       ┌────────────┴──────────────────┐                     │
     │                       │ freedom.Process               │                     │
     │                       │  ├─ peek packet → QUIC?       │                     │
     │                       │  ├─ socketPool.Acquire(:443)  │ ── pooledConn ──┐   │
     │                       │  │    (ONE socket for ALL)    │                 │   │
     │                       │  ├─ requestDone:              │                 │   │
     │                       │  │    buf.Copy(input,writer)  │ ── WriteTo ───> │   │
     │                       │  └─ responseDone:             │                 │   │
     │                       │       buf.Copy(reader,output) │ <─ ReadFrom ────┘   │
     │                       │       → BufferedPacketReader  │  (30s timeout)      │
     │                       │         └─ readLoop goroutine │                     │
     │                       │            (drains inbox even │                     │
     │                       │             when Process away)│                     │
     │                       └──────────────┬────────────────┘                     │
     │                                      │                                      │
     │             ┌────────────────────────┘                                      │
     │             v                                                               │
     │  ┌──────────────────────────────────────────────────┐                       │
     │  │ pooledSocket (shared by ALL connections to :443) │                       │
     │  │  ├─ conn: net.PacketConn (outbound, wildcard)    │ ───── WriteTo ───>    │
     │  │  ├─ demux: map[dcidKey]chan readResult           │                       │
     │  │  ├─ demuxSource: map[dcidKey]*UDPAddr            │ <──── ReadFrom ───    │
     │  │  └─ readLoop() goroutine:                        │   (parse DCID,        │
     │  │      for { ReadFrom → ParseDCID → demux → inbox} │    demux → inbox)     │
     │  └──────────────────────────────────────────────────┘                       │
     └──────────────────── QUIC reply delivered to Chrome ─────────────────────────┘
```

### Lifecycle of one QUIC flow

1. Chrome sends QUIC Initial to VPS:443 (UDP).
2. `udpWorker.callback()` parses DCID, looks up `dcidIndex` / `srcIndex`. For a new DCID it creates a `udpConn`, registers the DCID, spawns a goroutine running `proxy.Process`.
3. `freedom.Process` peeks the first packet; if it is a QUIC long header it calls `socketPool.Acquire(:443)` (ONE shared socket for all QUIC), captures `pooledConn.source = inbound.Source`.
4. `requestDone` goroutine runs `buf.Copy(input, PooledPacketWriter)` → for each Chrome packet, `pooledConn.WriteTo` parses SCID+DCID, registers them in the socket's demux, then calls `socket.conn.WriteTo(b, dest)`.
5. `pooledSocket.readLoop()` blocks on `socket.conn.ReadFrom`, parses the DCID of each Google reply, looks up `demux[dcid]` (with SCID fallback for 0-length SCID Chrome), and non-blocking-sends the packet to the matching `pooledConn.inbox`.
6. `responseDone` goroutine runs `buf.Copy(BufferedPacketReader, output)`. The BufferedPacketReader's internal `readLoop` drains `pooledConn.ReadFrom` (which blocks on `inbox` with 30s timeout) into an internal buffer. `buf.Copy` reads from this buffer.
7. When Google stops replying (Chrome swiped away), ReadFrom times out after 30s → BufferedPacketReader readLoop exits → responseDone exits → input pipe interrupted → requestDone exits → Process returns → `processRunning = false` → goroutine restarts on next packet.

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
          "enableTcpWarmPool": true,
          "tcpWarmPoolTimeout": 30,
          "preWarmFirstN": 10,
          "preWarmLearnVisits": 3
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
| enableSocketPool | false | **true** | UDP socket pool with DCID demuxing (required for QUIC) |
| enableStickyResolver | false | true | Cache DNS with stale-while-revalidate |
| preferIpv4 | false | true | Prefer IPv4 from DNS results |
| sessionIdleTimeout | 300 | 1800 | UDP session idle timeout (seconds) |
| stickyResolverTtl | 60 | 300 | DNS cache TTL (seconds) |
| enableTcpWarmPool | false | true | Pre-warm TCP connections |
| tcpWarmPoolTimeout | 10 | 30 | Warm connection timeout (seconds) |
| preWarmFirstN | 5 | 10 | Number of connections to pre-warm |
| preWarmLearnVisits | 3 | 3 | Visits before pre-warming |

> **Note:** `poolStalenessTimeout`, `poolIdleTimeout`, and `poolUnusedTimeout` are no longer used — the pool socket is never evicted (v26.11.206-207). They can be omitted from the config.

---

## Installation

```bash
# AMD64
wget https://github.com/cddeppe/Xray-quiclink/releases/download/v26.11.212/xray-linux-amd64
chmod +x xray-linux-amd64
mv xray-linux-amd64 /usr/local/bin/xray

# ARM64
wget https://github.com/cddeppe/Xray-quiclink/releases/download/v26.11.212/xray-linux-arm64
chmod +x xray-linux-arm64
mv xray-linux-arm64 /usr/local/bin/xray

# Config
mkdir -p /etc/xray
cp example-configs/vps-consolidated.json /etc/xray/config.json
# Edit config to match your IPs

# Systemd service
systemctl enable xray
systemctl start xray
```

### Systemd Service File

```ini
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=root
ExecStart=/usr/local/bin/xray run -confdir /etc/xray/
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
```

---

## Verifying QUIC is Working

```bash
# Check UDP (QUIC) vs TCP ratio
grep -c "default route for udp" /var/log/xray/error.log
grep -c "default route for tcp" /var/log/xray/error.log

# Check video traffic is over UDP
grep "default route for udp.*googlevideo" /var/log/xray/error.log | tail -10

# Verify pool is being used
grep "pool=true" /var/log/xray/error.log | tail -10

# Verify only ONE pool socket exists (should show exactly 1 entry)
grep "NEW socket created" /var/log/xray/error.log
```

---

## Building

```bash
# AMD64
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w" -o xray-linux-amd64 ./main

# ARM64
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "-s -w" -o xray-linux-arm64 ./main
```

---

## Version History

### v26.11.212 (Current — YouTube QUIC Working + Activity Tracking)

**Base:** v26.11.196 source (commit `2934ea47`)

**Key fixes that made YouTube QUIC work:**

| Version | Fix | Impact |
|---------|-----|--------|
| v26.11.201 | BufferedPacketReader — decouples pool inbox from Process | Fixes 10-second stall (CID rotation) |
| v26.11.204 | Port-only pool keying — same source port for ALL Google IPs | Fixes fast-swipe stall (CDN edge rotation) |
| v26.11.207 | No socket eviction — shared socket never killed | Fixes "worked for a while then stalled" |
| v26.11.208 | 30s ReadFrom timeout — prevents goroutine leak | Fixes Shorts goroutine accumulation |
| v26.11.209-210 | Cancel context + interrupt input pipe on responseDone exit | Fixes Process deadlock (requestDone never returns) |
| v26.11.211 | Close BufferedPacketReader on responseDone exit | Fixes competing readLoops for same inbox |
| v26.11.212 | Activity tracking via onActivity callback | Fixes 30-minute stall (clean() retired active connections) |
| v26.11.198 | Don't delete DCID on Close | Prevents demux miss for in-flight replies |
| v26.11.196 | Goroutine restart — Process persists across restarts | Stable source port, no removeConn |

### v26.11.196 (Previous baseline)

- Persistent outbound socket concept (release notes describe the fix, but binary had uncommitted changes)
- QUIC works for ~30 seconds, then stalls on video switching
- This was the best version before v26.11.211

### v26.11.116 (Historical — h3 test sites only)

- h3 test sites (quic.nginx.org, cloudflare-quic.com) work over QUIC
- YouTube falls back to TCP (QUIC did not work for YouTube at this point)

---

## What We Tried and Why It Did Not Work

Over 30+ versions, we attempted many approaches before finding the solution:

| Approach | Why it failed |
|----------|---------------|
| Per-connection sockets (v252-v255) | FD leak, transient error handling broke QUIC |
| 0-length SCID demux changes (v38 style) | Hot-path overhead killed QUIC performance |
| Stall detection + ICMP port unreachable | Close() never fires for active QUIC connections |
| Stall detection + IPv6 fallback | IPv6 has same demux problem as IPv4 |
| Stall detection + TCP block list | Blocked wrong IPs, broke DNS |
| Pool keyed by dest IP:port | Different Google IPs → different sockets → different source ports → Google path validation → stall |
| Reaper with staleness/idle checks | Killed the shared socket when one connection was idle |
| BufferedPacketReader without Close() | Two readLoops competed for same inbox → random stalls |
| cancel() without Interrupt(input) | buf.Copy blocks on input.ReadMultiBuffer, doesn't check context |

### Root Causes Discovered

1. **Source port instability** — Each different Google IP got a separate pool socket with a different source port. Google interpreted this as connection migration and initiated path validation, which stalled the connection.

2. **Inbox drain gap** — When Process returned, nobody was reading from the pool's inbox. Google's replies filled the inbox (256 cap) and were dropped. Chrome never received ACKs and declared the path dead after ~25 seconds.

3. **Process deadlock** — When responseDone exited (timeout), requestDone kept blocking on the input pipe because cancel() alone doesn't interrupt pipe reads. Process never returned, the goroutine never restarted, and Chrome's new packets went to a dead pipe.

4. **Socket eviction** — The reaper killed the shared socket based on idle/unused timeouts, creating new sockets with new source ports.

5. **Activity tracking bypass** — BufferedPacketReader and PooledPacketWriter bypassed udpConn.Write/Read, so `lastActivityTime` was never updated. `clean()` retired active connections after `sessionIdleTimeout` (30 min), causing sudden stalls on long videos.

6. **Competing readLoops** — When BufferedPacketReader wasn't closed on responseDone exit, the old readLoop competed with the new Process's readLoop for the same pooledConn's inbox — one got packets, the other blocked, causing random stalls.

---

## Known Limitations

1. **Only QUIC, not non-QUIC UDP.** The pool's reply demuxing relies on parsing QUIC DCID. Non-QUIC UDP (DNS, games, WireGuard) falls back to the existing per-session dial path.

2. **Pool socket is never evicted.** With port-only keying, the shared socket stays alive forever. This is intentional (source port stability) but means the socket's demux map can grow with stale entries. The stale entries are cleaned up on panic (when readLoop tries to send to a closed inbox).

3. **30-second timeout on abandoned connections.** When Google stops replying, it takes 30 seconds for the goroutine to clean up. During this time, the BufferedPacketReader's readLoop is blocking on the inbox. This is acceptable — the goroutine is cleaned up and the connection is retired.

4. **CID length defaults to 8 for short headers.** If a QUIC variant uses a different default CID length and the first packet is a short header, the parser will get the wrong CID. In practice, handshakes always start with a long header.

5. **Activity tracking via callback.** The `onActivity` callback fires on every `WriteTo` and `ReadFrom` call. This adds one nil check + one atomic store per packet (~5ns). The callback is set once during Process when the pooledConn is created.

---

## Files Modified From Upstream

### New Files

| File | Purpose |
|------|---------|
| `common/protocol/quic/dcid.go` | QUIC DCID parser for long and short headers |
| `common/protocol/quic/split.go` | Coalesced QUIC packet splitter (RFC 9000 Section 12.2) |
| `common/protocol/quic/workerhook.go` | Server SCID notification hook for the inbound worker |
| `proxy/freedom/udp_pool.go` | UDP socket pool with DCID demuxing + BufferedPacketReader |
| `proxy/freedom/udp_sticky.go` | Sticky DNS resolver with wildcard cache |
| `proxy/freedom/tcp_pool.go` | TCP warm pool for faster video transitions |
| `proxy/freedom/udptimeout/udptimeout.go` | Configurable UDP timeout |
| `example-configs/vps-consolidated.json` | Example configuration |

### Key Modified Files

| File | What Changed |
|------|--------------|
| `app/proxyman/inbound/worker.go` | Goroutine restart, persistent outbound conn, DCID migration, processRunning tracking |
| `proxy/freedom/freedom.go` | Pool integration, BufferedPacketReader, input pipe interruption, persistent pooledConn |
| `proxy/freedom/udp_pool.go` | Port-only keying, no socket eviction, BufferedPacketReader, 30s ReadFrom timeout, panic recovery |
| `common/protocol/quic/sniff.go` | QUIC SNI sniffer with ECH support |
| `common/protocol/tls/sniff.go` | Truncated ClientHello SNI extraction |
| `transport/internet/udp/hub.go` | UDP hub integration for QUIC sniffing |

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

---

## Support

If this fork saves you time and you want to support its maintenance, feel free to buy me a coffee:

[![Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/cdeppe)

## License

[Mozilla Public License Version 2.0](LICENSE)

This fork is based on [Xray-core](https://github.com/XTLS/Xray-core) by the Project X community. All upstream license terms apply to the original code. Fork-specific additions are licensed under the same MPL-2.0.

## Credits

- [Xray-core](https://github.com/XTLS/Xray-core) — the upstream project this fork is based on
- [Project X](https://github.com/XTLS) — the community behind xray-core
- All contributors to the upstream project whose work this fork builds upon
