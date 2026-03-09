from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from hashlib import pbkdf2_hmac, sha256
from os import urandom
from secrets import token_urlsafe
from typing import Dict, List, Optional

from .models import (
    DeviceBinding,
    NodeStatus,
    SessionSnapshot,
    TokenRecord,
    UserAccount,
    UserStatus,
)

DEFAULT_TOKEN_TTL = timedelta(hours=24)


_LEGACY_MODE = True  # keep sha256 compat for existing tests/data


def hash_password(password: str) -> str:
    if _LEGACY_MODE:
        return sha256(password.encode("utf-8")).hexdigest()
    salt = urandom(16)
    dk = pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations=260000)
    return f"pbkdf2:{salt.hex()}:{dk.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    if stored_hash.startswith("pbkdf2:"):
        _, salt_hex, dk_hex = stored_hash.split(":", 2)
        salt = bytes.fromhex(salt_hex)
        dk = pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations=260000)
        return dk.hex() == dk_hex
    return stored_hash == sha256(password.encode("utf-8")).hexdigest()


class InMemoryStore:
    def __init__(self) -> None:
        self.users: Dict[str, UserAccount] = {}
        self.device_bindings: Dict[str, List[DeviceBinding]] = {}
        self.node_status: Dict[str, NodeStatus] = {}
        self.sessions: Dict[str, SessionSnapshot] = {}
        self.token_records: Dict[str, TokenRecord] = {}
        self.user_tokens: Dict[str, str] = {}
        self.user_policies: Dict[str, dict] = {}
        self.admin_api_key: str = "admin-secret-key"
        self._audit_log: List[dict] = []
        self._policy_versions: Dict[str, List[dict]] = {}
        self.bootstrap()

    def bootstrap(self) -> None:
        self.users["demo"] = UserAccount(
            user_id="demo",
            password_hash=hash_password("demo1234"),
            plan="pro",
        )
        self.node_status["sg-1"] = NodeStatus(
            node_id="sg-1",
            region="sg",
            endpoint="sg-1.vpn.internal:51820",
            capacity=600,
            current_load=125,
            avg_latency_ms=24,
        )
        self.node_status["jp-1"] = NodeStatus(
            node_id="jp-1",
            region="jp",
            endpoint="jp-1.vpn.internal:51820",
            capacity=500,
            current_load=90,
            avg_latency_ms=28,
        )
        self.node_status["us-1"] = NodeStatus(
            node_id="us-1",
            region="us",
            endpoint="us-1.vpn.internal:51820",
            capacity=700,
            current_load=310,
            avg_latency_ms=118,
        )

    # ── auth ──────────────────────────────────────────────────

    def register_user(
        self, user_id: str, password: str, plan: str = "free"
    ) -> Optional[UserAccount]:
        if user_id in self.users:
            return None
        user = UserAccount(
            user_id=user_id,
            password_hash=hash_password(password),
            plan=plan,
        )
        self.users[user_id] = user
        return user

    def authenticate(self, user_id: str, password: str) -> bool:
        user = self.users.get(user_id)
        if not user:
            return False
        if user.status == UserStatus.BANNED:
            return False
        return verify_password(password, user.password_hash)

    def issue_token(
        self, user_id: str, ttl: timedelta = DEFAULT_TOKEN_TTL
    ) -> str:
        token = token_urlsafe(32)
        now = datetime.now(timezone.utc)
        record = TokenRecord(
            token=token,
            user_id=user_id,
            issued_at=now,
            expires_at=now + ttl,
        )
        self.token_records[token] = record
        self.user_tokens[token] = user_id
        return token

    def validate_token(self, token: str) -> Optional[str]:
        record = self.token_records.get(token)
        if record is None:
            return None
        if record.expires_at and datetime.now(timezone.utc) > record.expires_at:
            self.revoke_token(token)
            return None
        user = self.users.get(record.user_id)
        if user and user.status == UserStatus.BANNED:
            return None
        return record.user_id

    def revoke_token(self, token: str) -> bool:
        removed = self.token_records.pop(token, None)
        self.user_tokens.pop(token, None)
        return removed is not None

    def revoke_all_user_tokens(self, user_id: str) -> int:
        to_revoke = [
            t for t, r in self.token_records.items() if r.user_id == user_id
        ]
        for t in to_revoke:
            self.revoke_token(t)
        return len(to_revoke)

    # ── devices ───────────────────────────────────────────────

    def bind_device(self, binding: DeviceBinding, max_devices: int = 3) -> dict:
        current = self.device_bindings.setdefault(binding.user_id, [])
        already_bound = [x for x in current if x.device_id == binding.device_id]
        if already_bound:
            return {"ok": True, "message": "device_already_bound"}
        if len(current) >= max_devices:
            return {"ok": False, "message": "device_limit_exceeded"}
        current.append(binding)
        return {"ok": True, "message": "device_bound"}

    def list_devices(self, user_id: str) -> List[DeviceBinding]:
        return list(self.device_bindings.get(user_id, []))

    def unbind_device(self, user_id: str, device_id: str) -> bool:
        devices = self.device_bindings.get(user_id, [])
        for i, d in enumerate(devices):
            if d.device_id == device_id:
                devices.pop(i)
                return True
        return False

    # ── nodes ─────────────────────────────────────────────────

    def upsert_node(self, node: NodeStatus) -> None:
        node.updated_at = datetime.now(timezone.utc)
        self.node_status[node.node_id] = node

    def healthy_nodes(self, region: Optional[str] = None) -> List[NodeStatus]:
        nodes = [n for n in self.node_status.values() if n.healthy]
        if region:
            nodes = [n for n in nodes if n.region == region]
        return nodes

    def all_nodes(self) -> List[NodeStatus]:
        return list(self.node_status.values())

    def mark_stale_nodes(self, threshold_minutes: int = 5) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=threshold_minutes)
        count = 0
        for node in self.node_status.values():
            if node.healthy and node.updated_at < cutoff:
                node.healthy = False
                count += 1
        return count

    # ── users / admin ─────────────────────────────────────────

    def update_user_status(self, user_id: str, status: UserStatus) -> bool:
        user = self.users.get(user_id)
        if not user:
            return False
        user.status = status
        if status == UserStatus.BANNED:
            self.revoke_all_user_tokens(user_id)
        return True

    def get_user_policy(self, user_id: str) -> Optional[dict]:
        return self.user_policies.get(user_id)

    def set_user_policy(self, user_id: str, policy: dict) -> None:
        self.user_policies[user_id] = policy

    def list_users(self) -> List[UserAccount]:
        return list(self.users.values())

    def verify_admin_key(self, key: str) -> bool:
        return key == self.admin_api_key

    # ── sessions ──────────────────────────────────────────────

    def save_session(self, session: SessionSnapshot) -> None:
        self.sessions[session.session_id] = session

    def find_session_by_egress_ip_and_time(
        self,
        egress_ip: str,
        observed_at: datetime,
        window_minutes: int,
    ) -> Optional[SessionSnapshot]:
        window = timedelta(minutes=window_minutes)
        lower = observed_at - window
        upper = observed_at + window
        for session in self.sessions.values():
            started = session.started_at
            ended = session.ended_at or (observed_at + timedelta(seconds=1))
            if session.egress_ip != egress_ip:
                continue
            if started <= upper and ended >= lower:
                return session
        return None

    # ── audit ─────────────────────────────────────────────────

    def append_audit_log(self, entry: dict) -> None:
        if "ts" not in entry:
            entry["ts"] = datetime.now(timezone.utc).isoformat()
        self._audit_log.append(entry)

    def query_audit_logs(
        self,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        limit: int = 100,
    ) -> List[dict]:
        results = self._audit_log
        if user_id:
            results = [e for e in results if e.get("user_id") == user_id]
        if action:
            results = [e for e in results if e.get("action") == action]
        return list(reversed(results))[:limit]

    # ── policy versions ───────────────────────────────────────

    def save_policy_version(self, user_id: str, policy: dict, version: int) -> None:
        versions = self._policy_versions.setdefault(user_id, [])
        versions.append({
            "user_id": user_id,
            "policy": policy,
            "version": version,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })

    def get_policy_versions(self, user_id: str) -> List[dict]:
        versions = self._policy_versions.get(user_id, [])
        return sorted(versions, key=lambda v: v["version"], reverse=True)

    @staticmethod
    def node_to_dict(node: NodeStatus) -> dict:
        data = asdict(node)
        data["updated_at"] = node.updated_at.isoformat()
        return data
