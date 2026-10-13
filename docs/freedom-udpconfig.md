# freedom: TCP warm pool and sticky resolver

Config reference for the two opt-in features this fork adds to the `freedom`
outbound. Both live under `settings.udpConfig` and both default to off.

## Why this document exists

The values below are the ones that work. The combinations that do not work are
documented too, because they fail in ways that look like network problems
rather than configuration problems.

## Configuration

```json
{
  "protocol": "freedom",
  "tag": "direct",
  "sendThrough": "origin",
  "settings": {
    "udpConfig": {
      "enableTcpWarmPool": true,
      "tcpWarmPoolTimeout": 300,
      "preWarmFirstN": 10,
      "preWarmLearnVisits": 1,
      "enableStickyResolver": false,
      "stickyResolverTtl": 300,
      "preferIpv4": false,
      "preferIpv6": false
    }
  }
}
```

| Field | Meaning |
| --- | --- |
| `enableTcpWarmPool` | Pre-dial TCP connections to likely next destinations so a later request can skip the TCP handshake. |
| `tcpWarmPoolTimeout` | Seconds a pre-dialled connection stays usable. Default 300. |
| `preWarmFirstN` | How many destinations to learn per page-load visit and keep pre-dialled. |
| `preWarmLearnVisits` | Visits before the learned set is considered stable. `1` learns fastest. |
| `enableStickyResolver` | Pin each hostname to one resolved IP for `stickyResolverTtl`. |
| `stickyResolverTtl` | Seconds a stickied IP is used before re-resolution. |
| `preferIpv4` / `preferIpv6` | Force an address family. Leave both `false` unless you have a reason. |

`enableSocketPool`, `sessionIdleTimeout`, `poolStalenessTimeout`, `poolIdleTimeout`,
`poolUnusedTimeout` and `preWarmCount` are accepted for backward compatibility
but do nothing in this TCP-only build.

## Rules the pool depends on

A warm connection may only be handed to a session if **nothing has ever been
written to it**. A TCP connection belongs to the session that created it: once a
client has sent a `ClientHello` over it, the peer's TLS state belongs to that
client. Writing a second client's first bytes into it splices two sessions
together and the peer resets the connection.

So `Release` closes a connection rather than parking it, and `Acquire` only
evends a connection that `doPreWarm` dialled and that is still untouched. This
is the whole point of the pre-warm: a socket that is still in the
pre-`ClientHello` state can be handed over safely, and the handshake is what it
saves.

## Observed behaviour of the combinations

| `enableTcpWarmPool` | `enableStickyResolver` | Result |
| --- | --- | --- |
| `true` | `true` | Browsing fails. Every request after the first inherits a socket whose peer already finished a TLS session, and the failed acquire suppresses the fallback dial. |
| `false` | `true` | Works, but video buffers. The wildcard cache pins every `*.googlevideo.com` onto one edge IP, so per-subdomain edge selection collapses onto a single server. |
| either | `false` | Works. |

The first two rows are fixed/degraded for a reason rather than a bug in the
routing layer, so if you see them again check these two fields before anything
else.

## Caveats

- **Pre-warming is skipped when `sendThrough` is `origin`.** The pre-warm dialer
  runs with a background context, so it has no inbound connection and cannot
  resolve `origin`. A pre-dialled socket therefore binds to the kernel's default
  source. Harmless on a single-address host, wrong on a multi-address host.
- **The pool and the sticky resolver are coupled.** `Acquire` is keyed on the
  destination, and `Process` calls it after the sticky resolver has replaced the
  domain with an IP. With the resolver off the key is `tcp:example.com:443`;
  with it on the key is `tcp:203.0.113.7:443`. Either is self-consistent, but the
  two do not share entries across a resolver change.
- **Pool and resolver are disabled entirely when `sockopt.dialerProxy` is set.**
  Both are initialised after `Init`'s early return for that case. See the open
  items in the repository notes.
- **`udpConfig` must be present** for any freedom outbound whose config is
  loaded from JSON, or `Init` panics on a nil dereference.
