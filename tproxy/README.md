# TPROXY Setup Guide for xray-quiclink

This enables transparent QUIC/HTTP3 proxying (YouTube) using Linux TPROXY.
The kernel provides xray with the original destination IP for every UDP packet,
eliminating the need for SNI sniffing on 1-RTT short headers.

## What This Does

- Redirects **only UDP :443** to xray's TPROXY listener
- TCP traffic (SSH, HTTP, etc.) is **untouched**
- DNS (port 53) is **untouched**
- Loopback traffic is **untouched**
- xray receives the original destination IP from the kernel

## Safety Features

1. **SSH-safe**: Only UDP :443 is redirected. TCP :22 (SSH) is never touched.
2. **Idempotent**: Safe to run multiple times (cleans up before setting up).
3. **Cleanup on exit**: `tproxy-setup.sh cleanup` removes all rules.
4. **systemd integration**: Rules are cleaned up when the service stops.

## Installation

### Step 1: Install the TPROXY script

```bash
sudo cp tproxy-setup.sh /usr/local/bin/tproxy-setup.sh
sudo chmod +x /usr/local/bin/tproxy-setup.sh
```

### Step 2: Install the xray config

```bash
sudo cp config-tproxy.json /usr/local/etc/xray/config.json
```

### Step 3: Install the systemd service

```bash
sudo cp xray-tproxy.service /etc/systemd/system/xray-tproxy.service
sudo systemctl daemon-reload
```

### Step 4: Enable and start

```bash
# Enable TPROXY service (runs before xray)
sudo systemctl enable xray-tproxy

# Start TPROXY
sudo systemctl start xray-tproxy

# Restart xray to pick up the new config
sudo systemctl restart xray
```

### Step 5: Verify

```bash
# Check TPROXY rules are active
sudo tproxy-setup.sh status

# Check xray is running
sudo systemctl status xray

# Check logs
tail -100 /var/log/xray/error.log
```

## How It Works

### Before TPROXY (broken):

```
Chrome → QUIC packet to 142.251.x.x:443 → xray inbound
  → xray tries to sniff SNI from 1-RTT short header
  → short headers are ENCRYPTED, no SNI
  → xray routes to 127.0.0.1:443 → DROPPED
  → YouTube stalls
```

### After TPROXY (working):

```
Chrome → QUIC packet to 142.251.x.x:443 → kernel TPROXY
  → kernel tells xray: "this packet was going to 142.251.x.x:443"
  → xray dials 142.251.x.x:443 directly
  → no SNI sniffing needed for UDP
  → YouTube plays
```

## Managing TPROXY

```bash
# Check status
sudo tproxy-setup.sh status

# Remove rules (xray will fall back to sniffing)
sudo tproxy-setup.sh cleanup

# Re-install rules
sudo tproxy-setup.sh setup

# Restart (cleanup + setup)
sudo tproxy-setup.sh restart
```

## Troubleshooting

### SSH is broken

This should NEVER happen — the script only touches UDP :443, not TCP.
If SSH breaks, the script did NOT cause it. To recover:

```bash
# From console (not SSH):
sudo tproxy-setup.sh cleanup
sudo systemctl stop xray-tproxy
```

### YouTube still doesn't work

1. Check TPROXY rules are active: `sudo tproxy-setup.sh status`
2. Check xray is running: `sudo systemctl status xray`
3. Check xray logs for errors: `tail -100 /var/log/xray/error.log`
4. Verify the config has `"tproxy": "tproxy"` in sockopt
5. Verify `"receiveOriginalDestAddress": true` in sockopt

### Rules don't persist after reboot

The systemd service (`xray-tproxy.service`) should handle this.
Make sure it's enabled:

```bash
sudo systemctl enable xray-tproxy
```

## What About DNS?

You do NOT need your VPS to be your DNS resolver. TPROXY intercepts
the actual UDP :443 traffic, not DNS queries. Chrome's DNS queries
go through the tunnel normally.

The only reason you'd need DNS hijacking is if you wanted to route
based on domain rules (e.g., "proxy youtube.com but not google.com").
For transparent all-traffic proxying, TPROXY alone is sufficient.
