from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from secrets import token_urlsafe
from typing import Dict, List, Optional

from .models import (
    DeviceBinding,
    NodeStatus,
    SessionSnapshot,
    UserAccount,
    UserStatus,
)


def hash_password(password: str) -> str:
    return sha256(password.encode("utf-8")).hexdigest()


class InMemoryStore:
    def __init__(self) -> None:
        self.users: Dict[str, UserAccount] = {}
        self.device_bindings: Dict[str, List[DeviceBinding]] = {}
        self.node_status: Dict[str, NodeStatus] = {}
        self.sessions: Dict[str, SessionSnapshot] = {}
        self.user_tokens: Dict[str, str] = {}
        self.user_policies: Dict[str, dict] = {}
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

    def authenticate(self, user_id: str, password: str) -> bool:
        user = self.users.get(user_id)
        if not user:
            return False
        if user.status == UserStatus.BANNED:
            return False
        return user.password_hash == hash_password(password)

    def issue_token(self, user_id: str) -> str:
        token = token_urlsafe(32)
        self.user_tokens[token] = user_id
        return token

    def bind_device(self, binding: DeviceBinding, max_devices: int = 3) -> dict:
        current = self.device_bindings.setdefault(binding.user_id, [])
        already_bound = [x for x in current if x.device_id == binding.device_id]
        if already_bound:
            return {"ok": True, "message": "device_already_bound"}
        if len(current) >= max_devices:
            return {"ok": False, "message": "device_limit_exceeded"}
        current.append(binding)
        return {"ok": True, "message": "device_bound"}

    def upsert_node(self, node: NodeStatus) -> None:
        node.updated_at = datetime.now(timezone.utc)
        self.node_status[node.node_id] = node

    def healthy_nodes(self, region: Optional[str] = None) -> List[NodeStatus]:
        nodes = [n for n in self.node_status.values() if n.healthy]
        if region:
            nodes = [n for n in nodes if n.region == region]
        return nodes

    def update_user_status(self, user_id: str, status: UserStatus) -> bool:
        user = self.users.get(user_id)
        if not user:
            return False
        user.status = status
        return True

    def set_user_policy(self, user_id: str, policy: dict) -> None:
        self.user_policies[user_id] = policy

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

    @staticmethod
    def node_to_dict(node: NodeStatus) -> dict:
        data = asdict(node)
        data["updated_at"] = node.updated_at.isoformat()
        return data
