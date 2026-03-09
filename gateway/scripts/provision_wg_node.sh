#!/usr/bin/env bash
set -euo pipefail

# Standard WireGuard node bootstrap for Ubuntu/Debian.
# Usage:
#   sudo ./provision_wg_node.sh <PUBLIC_IP_OR_DNS> <WG_PRIVATE_KEY>

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <PUBLIC_IP_OR_DNS> <WG_PRIVATE_KEY>"
  exit 1
fi

PUBLIC_ENDPOINT="$1"
WG_PRIVATE_KEY="$2"

WG_INTERFACE="wg0"
WG_PORT="51820"
WG_CIDR="10.66.0.1/24"
WG_CONF="/etc/wireguard/${WG_INTERFACE}.conf"

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends wireguard wireguard-tools nftables qrencode

sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1

cat >/etc/sysctl.d/99-vpn-forward.conf <<EOF
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
sysctl --system >/dev/null

cat >"${WG_CONF}" <<EOF
[Interface]
PrivateKey = ${WG_PRIVATE_KEY}
Address = ${WG_CIDR}
ListenPort = ${WG_PORT}
SaveConfig = false

PostUp = nft -f /etc/nftables.conf
PostDown = nft flush ruleset
EOF

chmod 600 "${WG_CONF}"

mkdir -p "/etc/systemd/system/wg-quick@${WG_INTERFACE}.service.d"
cat >/etc/systemd/system/wg-quick@${WG_INTERFACE}.service.d/override.conf <<EOF
[Service]
Restart=always
RestartSec=3
EOF

systemctl daemon-reload
systemctl enable --now wg-quick@"${WG_INTERFACE}"

cat <<EOF
WireGuard node provisioned.
- Endpoint: ${PUBLIC_ENDPOINT}:${WG_PORT}
- Interface: ${WG_INTERFACE}
- Address: ${WG_CIDR}
EOF
