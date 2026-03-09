#!/usr/bin/env bash
set -euo pipefail

# Per-user bandwidth and connection limits for WireGuard peers.
#
# Usage:
#   sudo ./apply_per_user_limits.sh <WAN_IFACE> <PEER_IP> <BW_MBIT> <MAX_CONNS>
#
# Example:
#   sudo ./apply_per_user_limits.sh eth0 10.66.0.2 50 500
#
# Requires: tc, nftables (or iptables+conntrack)

if [[ $# -lt 4 ]]; then
  echo "Usage: $0 <WAN_IFACE> <PEER_IP> <BW_MBIT> <MAX_CONNS>"
  exit 1
fi

IFACE="$1"
PEER_IP="$2"
BW_MBIT="$3"
MAX_CONNS="$4"

# Derive a unique class id from the last two octets of peer IP.
IFS='.' read -ra OCTETS <<< "${PEER_IP}"
CLASS_MINOR=$(( OCTETS[2] * 256 + OCTETS[3] ))
if [[ ${CLASS_MINOR} -lt 1 ]]; then
  CLASS_MINOR=1
fi

# ── Per-user bandwidth limit via tc ──
# Ensure HTB root exists (idempotent).
tc qdisc show dev "${IFACE}" | grep -q 'htb' || {
  tc qdisc add dev "${IFACE}" root handle 1: htb default 10
  tc class add dev "${IFACE}" parent 1: classid 1:1 htb rate 1000mbit ceil 1000mbit
  tc class add dev "${IFACE}" parent 1:1 classid 1:10 htb rate 500mbit ceil 1000mbit prio 2
}

# Remove existing class for this peer if present.
tc class del dev "${IFACE}" classid "1:${CLASS_MINOR}" 2>/dev/null || true
tc filter del dev "${IFACE}" parent 1: prio "${CLASS_MINOR}" 2>/dev/null || true

tc class add dev "${IFACE}" parent 1:1 classid "1:${CLASS_MINOR}" \
  htb rate "${BW_MBIT}mbit" ceil "${BW_MBIT}mbit" prio 1

tc qdisc add dev "${IFACE}" parent "1:${CLASS_MINOR}" handle "${CLASS_MINOR}:" fq_codel 2>/dev/null || true

tc filter add dev "${IFACE}" parent 1: protocol ip prio "${CLASS_MINOR}" \
  u32 match ip src "${PEER_IP}/32" flowid "1:${CLASS_MINOR}"

echo "tc: Peer ${PEER_IP} limited to ${BW_MBIT} Mbit/s"

# ── Per-user connection limit via nftables ──
TABLE_NAME="vpn_per_user"
CHAIN_NAME="limit_${OCTETS[2]}_${OCTETS[3]}"

nft add table inet "${TABLE_NAME}" 2>/dev/null || true
nft add chain inet "${TABLE_NAME}" "${CHAIN_NAME}" '{ type filter hook forward priority 0; policy accept; }' 2>/dev/null || true

nft flush chain inet "${TABLE_NAME}" "${CHAIN_NAME}" 2>/dev/null || true

nft add rule inet "${TABLE_NAME}" "${CHAIN_NAME}" \
  ip saddr "${PEER_IP}" ct count over "${MAX_CONNS}" drop \
  comment "\"conn-limit ${PEER_IP} max=${MAX_CONNS}\""

echo "nft: Peer ${PEER_IP} limited to ${MAX_CONNS} concurrent connections"
