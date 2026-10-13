# Handoff: TCP warm pool on the clean-tcp branch

Written 2026-10-13. Supersedes the `HANDOFF.md` on `main`, which describes the
earlier UDP/QUIC-era fork (UDP socket pool, CID migration, `XRAY_UDP_POOL` env
vars). None of that applies here: `clean-tcp` is TCP-only, has no
`udp_pool.go`, and is driven by `udpConfig` fields rather than env vars.

Branch layout as of writing:

- Release branch: `clean-tcp`
- `main` is behind (`v26.11.287`, UDP era) and still contains `udp_pool.go`
- Latest release: `v26.13.5` (tag points at `105007d`, which is on `clean-tcp`)

---

## 0. The headline: the warm pool has never run

`enableTcpWarmPool` is silently discarded by the config loader. The feature is
unreachable until the generated protobuf file is regenerated. Details in
section 2. Everything else below is either already fixed or a smaller open item.

---

## 1. What was fixed

### 1.1 TCP warm pool handed out used connections (merged: squash `11ddc4c`)

`proxy/freedom/tcp_pool.go`

`freedom.Process` called `h.tcpWarmPool.Release(conn, destination)` on the
success path, where `conn` is the outbound socket to the real destination and
has just carried a complete TLS session. `Release` parked it in the pool keyed
only by `tcp:<ip>:443`; `Acquire` handed it to the next request for that
address. Writing a second client's ClientHello into a socket whose peer has
already completed a TLS session splices two sessions together, so the peer
resets it. Because `Acquire` returned non-nil, `Process` skipped its dial and
had no fallback:

```go
if warmConn := h.tcpWarmPool.Acquire(destination); warmConn != nil {
        conn = warmConn
        return nil          // no dial, no retry
}
```

`Acquire` and `Release` both called `isConnAlive`, which cannot detect this:
the socket is idle and healthy at probe time, it is the *protocol state* that is
wrong. Note also that on the error path the socket was closed rather than
pooled, so the pool was selecting for the worst sockets — only cleanly
finished ones (peers that completed and closed their session) ever got in.

Fixes applied, all confined to `tcp_pool.go`:

- `Acquire` hands out a connection only if it is `pristine` — dialled by this
  pool and never written to. The `preWarmed` flag set by `doPreWarm` was
  previously written and never read; it is now the gate (renamed `pristine`).
- `Release` closes the connection instead of parking it. It is kept as a method
  so callers have one explicit place to say "this socket is finished". The
  pre-warm path — the part that actually skips the handshake, which is the whole
  point of the feature — is unchanged.
- `NewTCPSocketPool` honours `preWarmN` as a fallback for `preWarmFirstN` and
  clamps `timeout`; `time.NewTicker(p.timeout)` with a zero timeout previously
  panicked.
- `trackFirstN` re-evaluates the learned first-N set on every completed visit.
  The match and update branches were nested inside `if !stabilized`, so they were
  unreachable after the first stabilisation: the learned set was frozen forever
  and CDN edge rotation (`pattern updated`) could never be detected. Pre-warming
  therefore kept dialling addresses that no longer served.
- `isConnAlive` resets the read deadline through a closure and documents that it
  can only observe failures already delivered to the socket (FIN/RST), not a NAT
  timeout whose FIN has not arrived.

**This code has never executed in production** (see section 2), so it is correct
by inspection but untested at runtime.

### 1.2 Sticky resolver collapsed subdomains onto one IP (open: PR #2)

`proxy/freedom/udp_sticky.go`, branch `fix/sticky-resolver-scope`, latest commit
`7850f72`.

Resolving a hostname also wrote a wildcard entry, and every sibling hostname was
then answered from it without being looked up:

```go
if parent, ok := parentDomain(hostname); ok {
        wildcardKey := "*." + parent
        if _, exists := s.entries[wildcardKey]; !exists {
                wcEntry := &stickyEntry{ip: ip}
                s.entries[wildcardKey] = wcEntry
        }
}
```

So `www.example.com` stored `*.example.com` at its address, and every other
sibling got that address. `refreshWildcard` additionally wrote *both* the
wildcard key and the hostname key, overwriting a hostname's own correct entry,
and `refreshExact`/`refreshWildcard` each swept the whole map deleting entries
that merely shared the old address. Because each `*.googlevideo.com` hostname
names a different edge server, this forced all video traffic through whichever
edge was resolved first — which is the reported buffering.

Fix: an entry is created only from a DNS answer for that exact hostname, and
nothing is derived from it. Removed with the wildcard: its lookup path, the
refresh-time overwrite of exact entries, the stale-serve fallback that scanned
wildcards, and the sibling-invalidation sweep. Each hostname now re-resolves on
its own TTL. `ResolveFresh` no longer leans on the coalescing channel — it looks
up inline so the caller really waits, and falls back to a stale address if the
lookup fails.

Also fixed in the same file: `selectAddr` compared `len(addr.IP)` against
`net.IPv4len`/`net.IPv6len`, but an IPv4 address produced by `net.ParseIP` is
held in its 16-byte form, so it was classified as IPv6. `preferIpv6` could
return an IPv4 address and `preferIpv4` could skip every address. Family is now
decided with `To4()`. The fallback to `addrs[0]` when the preferred family is
absent is kept (returning nil made the caller discard the entry and log
`invalid IP format: []`), and the previously unguarded final `return addrs[0].IP`
is now length-checked.

CI status: the first push of this branch failed all 28 platform builds because a
line in the `ResolveFresh` doc comment was missing its `//` prefix and was
parsed as code. Fixed in `7850f72`; builds re-triggered, verify before merging.

**Recommendation: the sticky resolver is not worth enabling on this deployment.**
It exists to solve a UDP/QUIC problem — xray's UDP path picks an address per
packet, so a single flow scatters across servers. This branch is TCP-only: a TCP
connection resolves once and stays on that IP for its lifetime, so the failure
mode cannot occur. The deployment's DNS config already has `cacheSize`,
`serveStale`, `serveExpiredTTL` and `prefetchInterval`/`prefetchThreshold`,
which cover the caching half better than the resolver does (xray's cache returns
the whole address list rather than collapsing to one). What remains of the
resolver is only the cost: pinned to one address for 300s even when it is the
wrong one.

### 1.3 Documentation (`c042fff`)

`docs/freedom-udpconfig.md` — config reference for both features, the invariant
the pool depends on, the observed behaviour of each field combination, and the
caveats. The `clean-tcp` `README.md` is stock upstream and documents none of this.

### 1.4 Release automation (`b6a7115`, `105007d`; mirrored to `main` as `b53d26f`)

`.github/workflows/publish-bare-binaries.yml`

The bare `xray-linux-amd64` / `xray-linux-arm64` assets on `v26.13.4` were
uploaded by hand, so a new tag produced only zips and the documented install
one-liner stopped working. This workflow runs on `release: published` and on a
`v*` tag push, builds the two linux binaries statically (`CGO_ENABLED=0`,
stripped), creates the release if the tag exists but the release does not, and
attaches them under those exact names. It is a separate workflow rather than
another step in `release.yml` so a mistake in it cannot break the zip build.

Releases can therefore be cut entirely from the GitHub web UI: **Releases → Draft
a new release → tag `vX.Y.Z` → Target: `clean-tcp` → Publish.** The Target
dropdown matters — leaving it on the default puts the tag on `main` and the
binaries are built from the wrong code.

Note the token used by the GitHub MCP integration needs **Contents: write** and
**Workflows: read and write**; without the latter, pushes touching
`.github/workflows/` fail with `403 Resource not accessible by personal access
token` at tree creation.

---

## 2. THE BLOCKER: `config.pb.go` has a hand-edited struct with a stale descriptor

`proxy/freedom/config.pb.go` was modified by hand. The Go struct gained the
warm-pool fields, but the **embedded `FileDescriptorProto` was never
regenerated**, so the protobuf layer does not know those fields exist.

Evidence, from the `file_proxy_freedom_config_proto_rawDesc` string literal. The
`UDPConfig` `DescriptorProto` is introduced by the length prefix `\xb1\x01` =
177, and contains exactly four `FieldDescriptorProto` entries:

| field | number | bytes in descriptor |
| --- | --- | --- |
| `enable_socket_pool` | 1 | 46 |
| `enable_sticky_resolver` | 2 | 54 |
| `prefer_ipv4` | 3 | 33 |
| `prefer_ipv6` | 4 | 33 |

Plus 11 bytes for the message name `UDPConfig`: 11 + 46 + 54 + 33 + 33 = **177**,
which is exactly the declared length. Nothing follows. The `Config` message
starts immediately after.

The Go struct declares 14 fields. Fields **5–14 are absent from the
descriptor**:

```
session_idle_timeout, pool_staleness_timeout, pool_idle_timeout,
pool_unused_timeout, sticky_resolver_ttl, enable_tcp_warm_pool,
tcp_warm_pool_timeout, pre_warm_count, pre_warm_first_n, pre_warm_learn_visits
```

xray's config loader unmarshals `settings` through protobuf reflection, which
uses that descriptor. Unknown keys are discarded silently, so every one of those
fields reads as its zero value no matter what the JSON says.

Corroborating evidence that the file was hand-edited: the field tags are
inconsistent with the generator's output. The original fields carry snake_case
JSON tags (`json:"udp_config,omitempty"`) while the added ones carry camelCase
(`json:"enableTcpWarmPool,omitempty"`).

### Consequences, all verified on a live server

- `freedom: TCP warm pool enabled (timeout=... preWarmFirstN=... preWarmLearnVisits=...)`
  is **never** logged, including immediately after a restart with
  `enableTcpWarmPool: true` in the live config. That line is emitted by
  `Handler.Init` whenever the block runs.
- Therefore `h.tcpWarmPool` is always nil and the warm pool is dead code.
- `stickyResolverTtl` is inert: the resolver always uses its built-in 300s.
- `preWarmFirstN`, `preWarmLearnVisits`, `tcpWarmPoolTimeout` are inert.
- `enable_sticky_resolver`, `prefer_ipv4`, `prefer_ipv6` **do** work (fields 2–4
  are in the descriptor). This is why the sticky resolver was the one feature
  that was actually active, and why turning it off is what fixed the reported
  outage and buffering.
- `enableTcpWarmPoolHealthCheck`, present in the deployment config, is not in
  `config.proto` at all and is ignored.

### What to do

Regenerate `proxy/freedom/config.pb.go` from `proxy/freedom/config.proto`:

```bash
protoc \
  --go_out=. --go_opt=paths=source_relative \
  --go-grpc_out=. --go-grpc_opt=paths=source_relative \
  proxy/freedom/config.proto
```

The header records the toolchain this tree was generated with:
`protoc-gen-go v1.36.12`, `protoc v3.21.12`. Preserve the **camelCase `json:`
tag** convention — xray's config layer reads camelCase names, and that convention
must hold for the new fields too.

`test.yml`'s `check-proto` job compares the first four lines of every `*.pb.go`
against `core/config.pb.go`, so a regenerated file with a different toolchain
header will fail that check. Either match the versions or update the reference.

**Do not hand-edit the descriptor string.** A malformed descriptor panics inside
`init()` at process start. The build will pass and xray will refuse to boot,
which is a far worse failure than the current one.

### Verification after regenerating

1. `xray run -confdir /etc/xray/` and confirm the warning line appears in the
error log:
   `freedom: TCP warm pool enabled (timeout=300s preWarmFirstN=10 preWarmLearnVisits=1)`
   If it is absent, the fields still are not reaching the struct.
2. With `loglevel: "info"`, `grep "reused warm TCP connection"` should appear
   once the pool starts serving pre-warmed sockets. That distinguishes
   "initialised" from "actually reusing".
3. Confirm the feature is a net win: page starts should be marginally faster and
   nothing should regress. The bug fixed in 1.1 caused outright failure, so
   "it still works" is the minimum bar.

---

## 3. Deployment configuration

xray runs as `xray run -confdir /etc/xray/`, so **every file in that directory is
loaded**, not just `config.json`. The live config is `/etc/xray/config.json`.

Target `udpConfig` once the proto is regenerated:

```json
"udpConfig": {
  "enableTcpWarmPool": true,
  "tcpWarmPoolTimeout": 300,
  "preWarmFirstN": 10,
  "preWarmLearnVisits": 1,
  "enableStickyResolver": false
}
```

The `udpConfig` block must be present even while the features are off — see the
nil-dereference item in section 4.

Housekeeping: there is a stray `/etc/xray/config.jsonu` in the confdir. It
duplicates config that also exists in `config.json` and should be removed or
renamed out of the directory.

---

## 4. Still open

Ordered by importance.

1. **Regenerate `config.pb.go`** (section 2). This is the only thing standing
   between the user and a working warm pool.
2. **The pre-warm dialer does not apply the outbound gateway.** `Init` wires
   `SetDialFunc` to `internet.Dial(ctx, dest, streamSettings)` with a fresh
   `context.Background()`. There is no inbound in that context, so
   `sendThrough: "origin"` cannot resolve and pre-warmed sockets bind to the
   kernel's default source instead of the inbound's local address. This
   deployment sets `sendThrough: "origin"` on the freedom outbound and the fork
   exists precisely for deterministic source-IP handling, so this matters on any
   host with more than one address. Fix before enabling the pool in a chain
   where the source address is load-bearing — for example, skip pre-warming when
   the configured send-through is `origin`.
3. **Nil-pointer panic on a missing `udpConfig`.** `Handler.Init` uses direct
   field access:

   ```go
   if config.UdpConfig.EnableTcpWarmPool {
   ```

   `UdpConfig` is a `*UDPConfig`, so any freedom outbound whose JSON has no
   `udpConfig` block panics during config load. Use `config.GetUdpConfig()` and
   nil-check it. The current deployment always has the block, so this is latent.
4. **Warm pool and sticky resolver are skipped when `sockopt.dialerProxy` is
   set.** Both are initialised *after* `Init`'s early return for that case, so
   they are silently disabled in exactly the multi-hop configuration this fork
   targets. The old `HANDOFF.md` on `main` records this as already fixed; it is
   not fixed here. Move the initialisation above the early return.
5. **No tests.** `tcp_pool.go` and `udp_sticky.go` have none. The original bug in
   1.1 would have been caught by a single test asserting that a `Release`d
   connection never comes back out of `Acquire`. Suggested file:
   `proxy/freedom/tcp_pool_test.go`.
6. **`test.yml` is red independently of all of the above.** `check-proto` fails
   on generated-file headers and `check-format` fails because `freedom.go` is
   indented with spaces where gofmt requires tabs (compare
   `transport/internet/system_dialer.go`, which uses tabs). The `build` jobs are
   the only trustworthy signal in that workflow right now. Do not use
   `check-format` as a gate until the tree is gofmt-clean.
7. **The NXDOMAIN flood.** The error log is full of
   `failed to resolve ip > app/dns: returning nil for domain
   <name>.googlevideo.com > rcode: 3`. The deployment's local resolver returns
   NXDOMAIN for YouTube CDN hostnames. Unrelated to either feature, but it is a
   plausible cause of remaining stalls. Worth noting that the wildcard entry
   removed in 1.2 was also masking this: an unresolvable name used to receive
   another edge's address from the wildcard instead of failing.

---

## 5. Reference

| item | value |
| --- | --- |
| warm pool fix (merged) | squash `11ddc4c` |
| sticky resolver fix | branch `fix/sticky-resolver-scope`, `7850f72`, PR #2 |
| docs | `c042fff` |
| release workflow | `105007d` (clean-tcp), `b53d26f` (main) |
| release `v26.13.5` | tag → `105007d`, target `clean-tcp` |
| `xray-linux-amd64` | 39,465,084 bytes, sha256 `d1424669...e62282` |
| `xray-linux-arm64` | 36,831,356 bytes, sha256 `29524e5e...e8716` |

Install command (matches the existing deployment habit):

```bash
cp /usr/local/bin/xray /usr/local/bin/xray.bak.$(date +%s)
cd /tmp && wget -q https://github.com/cddeppe/Xray-quiclink/releases/download/<tag>/xray-linux-amd64
sha256sum xray-linux-amd64
chmod +x xray-linux-amd64 && mv xray-linux-amd64 /usr/local/bin/xray
systemctl restart xray
cd /tmp && rm -f xray-linux-amd64
```
