# Multi-Hop Chain Example

This directory contains a three-hop chain example: **home gateway → vps1 → vps2 → internet**.

## Topology

```
Browser ──DNS hijack──> Home Gateway (192.0.2.10)
                              │
                              │  (freedom outbound, re-resolves SNI to vps1)
                              ▼
                           VPS1 (198.51.100.10)
                              │
                              │  (freedom outbound, re-resolves SNI to vps2)
                              ▼
                           VPS2 (203.0.113.10)
                              │
                              │  (freedom outbound, re-resolves SNI to real dest)
                              ▼
                          Internet (YouTube, Cloudflare, etc.)
```

## How it works

1. **Home Gateway** (`home-gateway.json`): receives browser traffic on `192.0.2.10:443`. Sniffs SNI. For target domains (YouTube, etc.), DNS resolves to the real destination IP — BUT the home gateway's DNS hijack (ctrld) returns VPS1's IP instead. So the freedom outbound dials VPS1.

2. **VPS1** (`vps1.json`): receives traffic from the home gateway on `198.51.100.10:443`. Sniffs SNI. The DNS on VPS1 resolves the SNI to VPS2's IP (via VPS1's own ctrld hijack). Freedom outbound dials VPS2.

3. **VPS2** (`vps2.json`): receives traffic from VPS1 on `203.0.113.10:443`. Sniffs SNI. The DNS on VPS2 resolves the SNI to the REAL destination IP. Freedom outbound dials the real server (YouTube, Cloudflare, etc.).

The QUIC DCID demux, SplitCoalesced, source SCID cache, and shortHeaderCIDLen learning all happen on EACH hop independently. Each hop maintains its own pool of UDP sockets to the next hop.

## DNS hijack setup

Each hop needs a DNS resolver (we use `ctrld`) that returns the NEXT hop's IP for target domains:
- Home gateway: `*.googlevideo.com`, `youtube.com`, etc. → VPS1 IP (`198.51.100.10`)
- VPS1: same domains → VPS2 IP (`203.0.113.10`)
- VPS2: same domains → real IPs (no hijack; resolve normally)

## File reference

| File | Role | Listen IP | Next hop |
|------|------|-----------|----------|
| `home-gateway.json` | First hop (at home) | `192.0.2.10` | VPS1 (`198.51.100.10`) |
| `vps1.json` | Intermediate hop | `198.51.100.10` | VPS2 (`203.0.113.10`) |
| `vps2.json` | Final hop (exit node) | `203.0.113.10` | Real internet |

## Deployment

1. Install xray on each VPS (see `../../HANDOFF.md`).
2. Copy the matching config to `/etc/xray/config.json` on each.
3. Set up ctrld on each with the appropriate DNS hijack rules.
4. Open 443/tcp + 443/udp on each VPS firewall.
5. Configure your home router's DNS to point at the home gateway.

## Notes

- **Documentation IPs**: All IPs in these configs are from documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`). Replace with your real IPs.
- **No encryption between hops**: Traffic between hops is the raw browser TLS/QUIC, not wrapped in VLESS/VMess. If you need encryption between hops (e.g., VPS1 is in an untrusted network), add a VLESS or WireGuard transport layer.
- **Single-hop is simpler**: If you only need one VPS, use `../vps-consolidated.json` instead — it's the same config without the chaining.
