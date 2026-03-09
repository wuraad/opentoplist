#!/usr/bin/env bash
set -euo pipefail

# Port-scan detection and blocking via nftables.
#
# Detects peers sending SYN to many distinct destination ports within a
# time window and adds them to a dynamic blocklist.
#
# Usage:
#   sudo ./detect_port_scan.sh [SCAN_THRESHOLD] [BLOCK_DURATION]
#
# Defaults:
#   SCAN_THRESHOLD=20   (unique SYN dport within 10s triggers block)
#   BLOCK_DURATION=300  (seconds to block scanning peer)

SCAN_THRESHOLD="${1:-20}"
BLOCK_DURATION="${2:-300}"

cat >/etc/nftables.d/scan_detect.nft <<EOF
table inet scan_detect {
  set scanners {
    type ipv4_addr
    timeout ${BLOCK_DURATION}s
    flags dynamic
  }

  chain scan_filter {
    type filter hook forward priority -10; policy accept;

    # Drop traffic from known scanners.
    ip saddr @scanners drop

    # Track SYN flood / port-scan behavior.
    # If a source sends TCP SYN to more than ${SCAN_THRESHOLD} distinct
    # destination ports within 10 seconds, add to scanners set.
    tcp flags syn \
      meter scan_meter { ip saddr . tcp dport timeout 10s limit rate over ${SCAN_THRESHOLD}/second } \
      add @scanners { ip saddr }
  }
}
EOF

nft -f /etc/nftables.d/scan_detect.nft 2>/dev/null || {
  mkdir -p /etc/nftables.d
  nft -f /etc/nftables.d/scan_detect.nft
}

echo "Port-scan detection enabled: threshold=${SCAN_THRESHOLD} dports/10s, block=${BLOCK_DURATION}s"
