#!/usr/bin/env bash
set -euo pipefail

# Apply traffic shaping and connection limits for abuse control.
# Usage:
#   sudo ./apply_traffic_controls.sh <WAN_IFACE> [MAX_MBIT]

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <WAN_IFACE> [MAX_MBIT]"
  exit 1
fi

IFACE="$1"
MAX_MBIT="${2:-500}"

# Reset qdisc if exists.
tc qdisc del dev "${IFACE}" root 2>/dev/null || true

# HTB root class
tc qdisc add dev "${IFACE}" root handle 1: htb default 10
tc class add dev "${IFACE}" parent 1: classid 1:1 htb rate "${MAX_MBIT}mbit" ceil "${MAX_MBIT}mbit"
tc class add dev "${IFACE}" parent 1:1 classid 1:10 htb rate "$((MAX_MBIT * 70 / 100))mbit" ceil "${MAX_MBIT}mbit" prio 1
tc class add dev "${IFACE}" parent 1:1 classid 1:20 htb rate "$((MAX_MBIT * 30 / 100))mbit" ceil "$((MAX_MBIT * 80 / 100))mbit" prio 2

# fq_codel for fairness and lower latency under load.
tc qdisc add dev "${IFACE}" parent 1:10 handle 10: fq_codel
tc qdisc add dev "${IFACE}" parent 1:20 handle 20: fq_codel

echo "Applied traffic controls on ${IFACE} with max ${MAX_MBIT}mbit"
