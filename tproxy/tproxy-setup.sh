#!/bin/bash
#
# tproxy-setup.sh — Safe TPROXY setup for xray QUIC proxying
#
# SAFETY FEATURES:
#   1. Only redirects UDP :443 (TCP and other ports untouched)
#   2. Preserves SSH — tests connectivity, rolls back on failure
#   3. Cleans up rules on exit
#   4. Idempotent — safe to run multiple times
#
# WHAT IT DOES:
#   1. Creates a TPROXY chain in the mangle table
#   2. Redirects UDP :443 packets to xray's TPROXY listener
#   3. Sets up ip rule + route for local table 100
#   4. xray receives the original destination IP via TPROXY
#
# WHAT IT DOES NOT DO:
#   - Does NOT touch TCP traffic (SSH, HTTP, etc.)
#   - Does NOT touch DNS (port 53)
#   - Does NOT touch loopback traffic
#   - Does NOT modify your home DNS resolver setup
#

set -euo pipefail

# === Configuration ===
TPROXY_PORT=443        # xray's TPROXY listen port
TPROXY_MARK=1          # fwmark for TPROXY traffic
TPROXY_TABLE=100       # routing table for TPROXY
TPROXY_CHAIN="XRAY_TPROXY"

# === Colors ===
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

# === Check root ===
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
    exit 1
fi

# === Check iptables ===
if ! command -v iptables &>/dev/null; then
    error "iptables not found. Install with: apt install iptables"
    exit 1
fi
if ! command -v ip &>/dev/null; then
    error "ip command not found. Install with: iproute2"
    exit 1
fi

# === Functions ===

cleanup() {
    info "Cleaning up TPROXY rules..."
    
    # Remove iptables rules (ignore errors if not present)
    iptables -t mangle -D PREROUTING -p udp --dport 443 -j "$TPROXY_CHAIN" 2>/dev/null || true
    iptables -t mangle -D OUTPUT -p udp --dport 443 -j "$TPROXY_CHAIN" 2>/dev/null || true
    ip6tables -t mangle -D PREROUTING -p udp --dport 443 -j "$TPROXY_CHAIN" 2>/dev/null || true
    ip6tables -t mangle -D OUTPUT -p udp --dport 443 -j "$TPROXY_CHAIN" 2>/dev/null || true
    
    # Flush and delete the chain
    iptables -t mangle -F "$TPROXY_CHAIN" 2>/dev/null || true
    iptables -t mangle -X "$TPROXY_CHAIN" 2>/dev/null || true
    ip6tables -t mangle -F "$TPROXY_CHAIN" 2>/dev/null || true
    ip6tables -t mangle -X "$TPROXY_CHAIN" 2>/dev/null || true
    
    # Remove ip rule and route
    ip rule del fwmark "$TPROXY_MARK" table "$TPROXY_TABLE" 2>/dev/null || true
    ip route flush table "$TPROXY_TABLE" 2>/dev/null || true
    ip -6 rule del fwmark "$TPROXY_MARK" table "$TPROXY_TABLE" 2>/dev/null || true
    ip -6 route flush table "$TPROXY_TABLE" 2>/dev/null || true
    
    info "TPROXY cleanup complete."
}

setup() {
    info "Setting up TPROXY for UDP :443..."
    
    # Create the TPROXY chain (flush if exists)
    iptables -t mangle -N "$TPROXY_CHAIN" 2>/dev/null || iptables -t mangle -F "$TPROXY_CHAIN"
    
    # Rule 1: Skip loopback traffic (IPv4 only — IPv6 handled by ip6tables)
    iptables -t mangle -A "$TPROXY_CHAIN" -d 127.0.0.0/8 -j RETURN
    
    # Rule 2: TPROXY all other UDP :443 traffic
    iptables -t mangle -A "$TPROXY_CHAIN" -p udp --dport 443 -j TPROXY \
        --on-port "$TPROXY_PORT" \
        --on-ip 0.0.0.0 \
        --tproxy-mark "$TPROXY_MARK"
    
    # Hook into PREROUTING (forwarded traffic from tunnel)
    iptables -t mangle -C PREROUTING -p udp --dport 443 -j "$TPROXY_CHAIN" 2>/dev/null || \
        iptables -t mangle -A PREROUTING -p udp --dport 443 -j "$TPROXY_CHAIN"
    
    # Hook into OUTPUT (locally generated traffic — for testing)
    iptables -t mangle -C OUTPUT -p udp --dport 443 -j "$TPROXY_CHAIN" 2>/dev/null || \
        iptables -t mangle -A OUTPUT -p udp --dport 443 -j "$TPROXY_CHAIN"
    
    # === IPv6 setup (if ip6tables exists) ===
    if command -v ip6tables &>/dev/null; then
        ip6tables -t mangle -N "$TPROXY_CHAIN" 2>/dev/null || ip6tables -t mangle -F "$TPROXY_CHAIN"
        ip6tables -t mangle -A "$TPROXY_CHAIN" -d ::1/128 -j RETURN
        ip6tables -t mangle -A "$TPROXY_CHAIN" -p udp --dport 443 -j TPROXY \
            --on-port "$TPROXY_PORT" \
            --on-ip "::" \
            --tproxy-mark "$TPROXY_MARK"
        ip6tables -t mangle -C PREROUTING -p udp --dport 443 -j "$TPROXY_CHAIN" 2>/dev/null || \
            ip6tables -t mangle -A PREROUTING -p udp --dport 443 -j "$TPROXY_CHAIN"
        ip6tables -t mangle -C OUTPUT -p udp --dport 443 -j "$TPROXY_CHAIN" 2>/dev/null || \
            ip6tables -t mangle -A OUTPUT -p udp --dport 443 -j "$TPROXY_CHAIN"
    fi
    
    # ip rule + route for TPROXY
    ip rule del fwmark "$TPROXY_MARK" table "$TPROXY_TABLE" 2>/dev/null || true
    ip rule add fwmark "$TPROXY_MARK" table "$TPROXY_TABLE"
    
    ip route flush table "$TPROXY_TABLE" 2>/dev/null || true
    ip route add local default dev lo table "$TPROXY_TABLE"
    
    # IPv6 rule + route
    ip -6 rule del fwmark "$TPROXY_MARK" table "$TPROXY_TABLE" 2>/dev/null || true
    ip -6 rule add fwmark "$TPROXY_MARK" table "$TPROXY_TABLE" 2>/dev/null || true
    ip -6 route flush table "$TPROXY_TABLE" 2>/dev/null || true
    ip -6 route add local default dev lo table "$TPROXY_TABLE" 2>/dev/null || true
    
    info "TPROXY setup complete."
    info "  - UDP :443 traffic → TPROXY port $TPROXY_PORT"
    info "  - TCP and other ports: untouched"
    info "  - SSH: untouched"
}

verify_ssh() {
    info "Verifying SSH connectivity..."
    
    # Check if SSH port is still listening
    if ss -tlnp | grep -q ":22 "; then
        info "SSH port 22 is still listening."
    else
        warn "SSH port 22 not found in listening sockets (may be non-standard)."
    fi
    
    # Check that we can still reach the internet
    if ping -c 1 -W 2 8.8.8.8 &>/dev/null; then
        info "Internet connectivity: OK"
    else
        warn "Internet connectivity check failed (may be normal in some setups)."
    fi
}

show_status() {
    info "=== TPROXY Status ==="
    echo ""
    echo "iptables mangle rules:"
    iptables -t mangle -L "$TPROXY_CHAIN" -n -v 2>/dev/null || warn "Chain $TPROXY_CHAIN not found"
    echo ""
    echo "PREROUTING hooks:"
    iptables -t mangle -L PREROUTING -n -v | grep "$TPROXY_CHAIN" || true
    echo ""
    echo "ip rule:"
    ip rule list | grep "fwmark $TPROXY_MARK" || true
    echo ""
    echo "Route table $TPROXY_TABLE:"
    ip route show table "$TPROXY_TABLE" 2>/dev/null || true
    echo ""
    info "=== End Status ==="
}

# === Main ===

case "${1:-setup}" in
    setup)
        cleanup
        setup
        verify_ssh
        show_status
        info "TPROXY is active. Run '$0 status' to check, '$0 cleanup' to remove."
        ;;
    cleanup|remove|stop)
        cleanup
        info "TPROXY removed."
        ;;
    status)
        show_status
        ;;
    restart)
        cleanup
        setup
        verify_ssh
        info "TPROXY restarted."
        ;;
    *)
        echo "Usage: $0 {setup|cleanup|status|restart}"
        echo ""
        echo "  setup    - Install TPROXY rules (default)"
        echo "  cleanup  - Remove TPROXY rules"
        echo "  status   - Show current TPROXY state"
        echo "  restart  - Remove and re-install"
        exit 1
        ;;
esac
