#!/usr/bin/env bash
set -euo pipefail

# nftables baseline:
# - block SMTP spam ports
# - block common reflection/amplification target ports
# - rate-limit suspicious tcp syn bursts

cat >/etc/nftables.conf <<'EOF'
flush ruleset

table inet vpn_filter {
  set blocked_udp_ports {
    type inet_service
    elements = { 19, 123, 161, 1900, 11211 }
  }

  chain output {
    type filter hook output priority 0; policy accept;

    # SMTP spam prevention
    tcp dport {25, 465, 587} drop

    # Reflection attack primitives
    udp dport @blocked_udp_ports drop
  }

  chain forward {
    type filter hook forward priority 0; policy accept;

    # Per source flood control
    tcp flags syn limit rate over 120/second burst 200 packets drop
  }
}
EOF

systemctl enable nftables >/dev/null 2>&1 || true
systemctl restart nftables
echo "Applied nftables egress policy."
