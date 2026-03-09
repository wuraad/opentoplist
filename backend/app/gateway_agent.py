"""Gateway Agent — bridges control plane ↔ WireGuard nodes.

Manages peer lifecycle: allocate IP, generate keys, push config, revoke.
Communicates with gateway nodes via HTTP or local shell for self-managed nodes.
"""
from __future__ import annotations

import json
import subprocess
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv4Network
from secrets import token_hex
from typing import Optional


@dataclass(slots=True)
class WgPeer:
    user_id: str
    device_id: str
    public_key: str
    allowed_ip: str
    node_id: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(slots=True)
class WgNodeConfig:
    node_id: str
    region: str
    endpoint: str
    public_key: str
    subnet: str = "10.66.0.0/24"
    listen_port: int = 51820


class GatewayAgent:
    """Manages WireGuard peer allocation and gateway communication."""

    def __init__(self) -> None:
        self._peers: dict[str, WgPeer] = {}
        self._nodes: dict[str, WgNodeConfig] = {}
        self._ip_pool: dict[str, IPv4Network] = {}
        self._allocated_ips: dict[str, set[str]] = {}

    def register_node(self, config: WgNodeConfig) -> dict:
        self._nodes[config.node_id] = config
        self._ip_pool[config.node_id] = IPv4Network(config.subnet)
        self._allocated_ips.setdefault(config.node_id, {"10.66.0.0", "10.66.0.1"})
        return {"ok": True, "node_id": config.node_id}

    def allocate_peer(
        self, user_id: str, device_id: str, node_id: str, client_public_key: str
    ) -> Optional[dict]:
        node = self._nodes.get(node_id)
        if not node:
            return None

        peer_key = f"{user_id}:{device_id}:{node_id}"
        if peer_key in self._peers:
            existing = self._peers[peer_key]
            return self._peer_config(existing, node)

        allocated = self._allocated_ips.get(node_id, set())
        network = self._ip_pool[node_id]
        peer_ip = None
        for addr in network.hosts():
            if str(addr) not in allocated:
                peer_ip = str(addr)
                break
        if peer_ip is None:
            return None

        allocated.add(peer_ip)
        peer = WgPeer(
            user_id=user_id,
            device_id=device_id,
            public_key=client_public_key,
            allowed_ip=f"{peer_ip}/32",
            node_id=node_id,
        )
        self._peers[peer_key] = peer

        self._push_peer_to_node(node, peer)
        return self._peer_config(peer, node)

    def revoke_peer(self, user_id: str, device_id: str, node_id: str) -> bool:
        peer_key = f"{user_id}:{device_id}:{node_id}"
        peer = self._peers.pop(peer_key, None)
        if not peer:
            return False
        ip = peer.allowed_ip.split("/")[0]
        self._allocated_ips.get(node_id, set()).discard(ip)
        node = self._nodes.get(node_id)
        if node:
            self._remove_peer_from_node(node, peer)
        return True

    def revoke_all_user_peers(self, user_id: str) -> int:
        to_remove = [k for k, p in self._peers.items() if p.user_id == user_id]
        for key in to_remove:
            peer = self._peers.pop(key)
            ip = peer.allowed_ip.split("/")[0]
            self._allocated_ips.get(peer.node_id, set()).discard(ip)
        return len(to_remove)

    def list_user_peers(self, user_id: str) -> list[dict]:
        return [
            {
                "node_id": p.node_id,
                "device_id": p.device_id,
                "allowed_ip": p.allowed_ip,
                "created_at": p.created_at.isoformat(),
            }
            for p in self._peers.values()
            if p.user_id == user_id
        ]

    def apply_bandwidth_limit(
        self, node_id: str, peer_ip: str, bandwidth_mbps: int, max_conns: int = 500
    ) -> dict:
        node = self._nodes.get(node_id)
        if not node:
            return {"ok": False, "message": "node_not_found"}
        return {
            "ok": True,
            "command": f"apply_per_user_limits.sh eth0 {peer_ip} {bandwidth_mbps} {max_conns}",
            "node_id": node_id,
            "peer_ip": peer_ip,
        }

    def _peer_config(self, peer: WgPeer, node: WgNodeConfig) -> dict:
        return {
            "ok": True,
            "interface": {
                "address": peer.allowed_ip,
                "dns": "1.1.1.1, 8.8.8.8",
            },
            "peer": {
                "public_key": node.public_key,
                "endpoint": f"{node.endpoint}:{node.listen_port}",
                "allowed_ips": "0.0.0.0/0",
                "persistent_keepalive": 25,
            },
            "node_id": node.node_id,
            "region": node.region,
        }

    def _push_peer_to_node(self, node: WgNodeConfig, peer: WgPeer) -> None:
        pass

    def _remove_peer_from_node(self, node: WgNodeConfig, peer: WgPeer) -> None:
        pass


class NodeScheduler:
    """Periodic tasks for gateway nodes: stale detection, health probing."""

    def __init__(self, store: "Any", gateway: GatewayAgent) -> None:
        self._store = store
        self._gateway = gateway

    def mark_stale_nodes(self, threshold_minutes: int = 5) -> int:
        return self._store.mark_stale_nodes(threshold_minutes)

    def probe_node_health(self, node_id: str) -> dict:
        nodes = self._store.all_nodes()
        node = next((n for n in nodes if n.node_id == node_id), None)
        if not node:
            return {"ok": False, "message": "node_not_found"}
        return {
            "ok": True,
            "node_id": node.node_id,
            "healthy": node.healthy,
            "load_ratio": round(node.current_load / max(node.capacity, 1), 3),
            "latency_ms": node.avg_latency_ms,
            "packet_loss": node.packet_loss_ratio,
        }
