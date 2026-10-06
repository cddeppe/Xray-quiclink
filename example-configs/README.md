# Example Configs

This directory contains example xray-quiclink configurations for different deployment topologies.

## Files

### `vps-consolidated.json`
A single-server (single-hop) configuration where one VPS handles everything: DNS hijack listening, dokodemo-door inbound, and freedom outbound with the UDP socket pool. This is the simplest deployment and what most users will want. Uses documentation IP ranges (`192.0.2.0/24`, `2001:db8::/32`) — replace with your real IPs.

### `multi-hop/` (directory)
A three-hop chain example (home gateway → vps1 → vps2 → internet) for users who need to chain multiple servers. Each hop has its own config file. See `multi-hop/README.md` for the full topology and deployment instructions.

## Key features demonstrated

- **DNS hijack**: the `dns` block points at `127.0.0.1` (a local resolver like `ctrld` that returns the VPS IP for target domains)
- **dokodemo-door inbound** on port 443 with `network: "tcp,udp"` and `sniffing.destOverride: ["tls","quic"]` — this is what makes QUIC work end-to-end
- **freedom outbound** with `udpConfig.enableSocketPool: true` — the pool with DCID demux is the core QUIC fix
- **`sendThrough: "origin"`** — TCP uses the listen IP as source; UDP/QUIC uses the wildcard-bound pool socket
- **Dual-stack IPv4 + IPv6** — `listen: ["v4", "v6"]` with both addresses
- **No tproxy** — uses dokodemo-door, not transparent proxy
- **Firewall wide open** — no firewall rules in the config; assume 443/tcp and 443/udp are open

## What's NOT in these configs

- **No VLESS/VMess/Trojan** — these are transparent proxy configs, not encrypted proxy protocols. The traffic between hops is the raw browser traffic (TLS/QUIC), not wrapped in another protocol. If you need encryption between hops, add a VLESS or WireGuard transport layer.
- **No tproxy** — we deliberately do not use tproxy. The `dokodemo-door` + `freedom` combination is simpler and works for QUIC.
- **No fake-ip DNS** — the `dns` block uses a real resolver (`127.0.0.1` pointing at `ctrld` or similar). Fake-ip would break QUIC because the SNI sniffing needs the real domain.

## Deployment

See `../HANDOFF.md` for the full deployment playbook. Summary:
1. Install xray: `wget https://github.com/cddeppe/Xray-quiclink/releases/latest/download/xray-linux-amd64 -O /usr/local/bin/xray && chmod +x /usr/local/bin/xray`
2. Copy the config to `/etc/xray/config.json`
3. Create a systemd unit (see HANDOFF.md)
4. Open 443/tcp and 443/udp on the firewall
5. Configure your DNS hijack resolver (ctrld) to return the VPS IP for the domains you want to proxy
6. Point your browser/client at the VPS IP for those domains (via the DNS hijack)
