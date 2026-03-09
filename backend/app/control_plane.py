from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from secrets import token_hex
from typing import Optional

from .models import DeviceBinding, NodeStatus, SessionSnapshot, UserStatus
from .store import InMemoryStore


class ControlPlaneService:
    def __init__(self, store: InMemoryStore) -> None:
        self.store = store

    # ── auth ──────────────────────────────────────────────────

    def register(self, user_id: str, password: str, plan: str = "free") -> dict:
        if not user_id or not user_id.strip():
            return {"ok": False, "message": "invalid_user_id"}
        if not password or len(password) < 6:
            return {"ok": False, "message": "password_too_short"}
        user = self.store.register_user(user_id.strip(), password, plan)
        if user is None:
            return {"ok": False, "message": "user_already_exists"}
        return {"ok": True, "user_id": user.user_id, "plan": user.plan}

    def login(self, user_id: str, password: str, device_id: str) -> dict:
        if not self.store.authenticate(user_id, password):
            return {"ok": False, "message": "invalid_credentials"}

        bind_result = self.store.bind_device(
            DeviceBinding(
                user_id=user_id,
                device_id=device_id,
                device_label=f"device-{device_id[:6]}",
            )
        )
        if not bind_result["ok"]:
            return bind_result

        token = self.store.issue_token(user_id)
        return {"ok": True, "token": token}

    def logout(self, token: str) -> dict:
        revoked = self.store.revoke_token(token)
        return {"ok": revoked}

    # ── devices ───────────────────────────────────────────────

    def bind_device(self, user_id: str, device_id: str, device_label: str) -> dict:
        return self.store.bind_device(
            DeviceBinding(
                user_id=user_id,
                device_id=device_id,
                device_label=device_label,
            )
        )

    def list_devices(self, user_id: str) -> dict:
        devices = self.store.list_devices(user_id)
        return {
            "ok": True,
            "devices": [
                {
                    "device_id": d.device_id,
                    "device_label": d.device_label,
                    "bound_at": d.bound_at.isoformat(),
                }
                for d in devices
            ],
        }

    def unbind_device(self, user_id: str, device_id: str) -> dict:
        removed = self.store.unbind_device(user_id, device_id)
        if not removed:
            return {"ok": False, "message": "device_not_found"}
        return {"ok": True, "message": "device_unbound"}

    # ── nodes ─────────────────────────────────────────────────

    def report_node_heartbeat(self, payload: dict) -> dict:
        node = NodeStatus(
            node_id=payload["node_id"],
            region=payload["region"],
            endpoint=payload["endpoint"],
            capacity=int(payload["capacity"]),
            current_load=int(payload.get("current_load", 0)),
            avg_latency_ms=int(payload.get("avg_latency_ms", 35)),
            packet_loss_ratio=float(payload.get("packet_loss_ratio", 0.0)),
            healthy=bool(payload.get("healthy", True)),
        )
        self.store.upsert_node(node)
        return {"ok": True}

    def list_nodes(self, region: Optional[str] = None) -> dict:
        nodes = self.store.all_nodes()
        if region:
            nodes = [n for n in nodes if n.region == region]
        return {
            "ok": True,
            "nodes": [self.store.node_to_dict(n) for n in nodes],
        }

    def route_node(self, user_id: str, region: Optional[str] = None) -> dict:
        user = self.store.users.get(user_id)
        if not user:
            return {"ok": False, "message": "user_not_found"}
        if user.status == UserStatus.BANNED:
            return {"ok": False, "message": "user_banned"}
        if user.status == UserStatus.QUARANTINED:
            return {"ok": False, "message": "user_quarantined"}

        candidates = self.store.healthy_nodes(region=region)
        if not candidates:
            return {"ok": False, "message": "no_healthy_nodes"}

        selected = min(
            candidates,
            key=lambda n: (
                n.current_load / max(n.capacity, 1),
                n.avg_latency_ms,
                n.packet_loss_ratio,
            ),
        )
        return {"ok": True, "node": self.store.node_to_dict(selected)}

    # ── admin ─────────────────────────────────────────────────

    def ban_user(self, user_id: str) -> dict:
        ok = self.store.update_user_status(user_id, UserStatus.BANNED)
        return {"ok": ok}

    def unban_user(self, user_id: str) -> dict:
        ok = self.store.update_user_status(user_id, UserStatus.ACTIVE)
        return {"ok": ok}

    def quarantine_user(self, user_id: str) -> dict:
        ok = self.store.update_user_status(user_id, UserStatus.QUARANTINED)
        return {"ok": ok}

    def push_policy(self, user_id: str, policy: dict) -> dict:
        self.store.set_user_policy(user_id, policy)
        return {"ok": True}

    def get_policy(self, user_id: str) -> dict:
        policy = self.store.get_user_policy(user_id)
        if policy is None:
            return {"ok": False, "message": "no_policy"}
        return {"ok": True, "policy": policy}

    def list_users(self) -> dict:
        users = self.store.list_users()
        return {
            "ok": True,
            "users": [
                {
                    "user_id": u.user_id,
                    "plan": u.plan,
                    "status": u.status.value,
                    "created_at": u.created_at.isoformat(),
                }
                for u in users
            ],
        }

    # ── sessions ──────────────────────────────────────────────

    def register_session(self, user_id: str, node_id: str, egress_ip: str) -> dict:
        session = SessionSnapshot(
            session_id=token_hex(12),
            user_id=user_id,
            node_id=node_id,
            egress_ip=egress_ip,
            started_at=datetime.now(timezone.utc),
        )
        self.store.save_session(session)
        data = asdict(session)
        data["started_at"] = session.started_at.isoformat()
        return data
