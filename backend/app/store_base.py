"""Abstract store interface for pluggable backends (memory / sqlite / postgres)."""
from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import timedelta
from typing import List, Optional

from .models import DeviceBinding, NodeStatus, SessionSnapshot, UserAccount, UserStatus


class BaseStore(ABC):
    """Every concrete store must implement these methods."""

    # ── auth ──────────────────────────────────────────────────

    @abstractmethod
    def register_user(self, user_id: str, password: str, plan: str = "free") -> Optional[UserAccount]: ...

    @abstractmethod
    def authenticate(self, user_id: str, password: str) -> bool: ...

    @abstractmethod
    def issue_token(self, user_id: str, ttl: timedelta = ...) -> str: ...

    @abstractmethod
    def validate_token(self, token: str) -> Optional[str]: ...

    @abstractmethod
    def revoke_token(self, token: str) -> bool: ...

    @abstractmethod
    def revoke_all_user_tokens(self, user_id: str) -> int: ...

    # ── devices ───────────────────────────────────────────────

    @abstractmethod
    def bind_device(self, binding: DeviceBinding, max_devices: int = 3) -> dict: ...

    @abstractmethod
    def list_devices(self, user_id: str) -> List[DeviceBinding]: ...

    @abstractmethod
    def unbind_device(self, user_id: str, device_id: str) -> bool: ...

    # ── nodes ─────────────────────────────────────────────────

    @abstractmethod
    def upsert_node(self, node: NodeStatus) -> None: ...

    @abstractmethod
    def healthy_nodes(self, region: Optional[str] = None) -> List[NodeStatus]: ...

    @abstractmethod
    def all_nodes(self) -> List[NodeStatus]: ...

    @abstractmethod
    def mark_stale_nodes(self, threshold_minutes: int = 5) -> int: ...

    # ── users / admin ─────────────────────────────────────────

    @abstractmethod
    def update_user_status(self, user_id: str, status: UserStatus) -> bool: ...

    @abstractmethod
    def get_user_policy(self, user_id: str) -> Optional[dict]: ...

    @abstractmethod
    def set_user_policy(self, user_id: str, policy: dict) -> None: ...

    @abstractmethod
    def list_users(self) -> List[UserAccount]: ...

    @abstractmethod
    def verify_admin_key(self, key: str) -> bool: ...

    # ── sessions ──────────────────────────────────────────────

    @abstractmethod
    def save_session(self, session: SessionSnapshot) -> None: ...

    @abstractmethod
    def find_session_by_egress_ip_and_time(
        self, egress_ip: str, observed_at: "datetime", window_minutes: int
    ) -> Optional[SessionSnapshot]: ...

    # ── audit ─────────────────────────────────────────────────

    @abstractmethod
    def append_audit_log(self, entry: dict) -> None: ...

    @abstractmethod
    def query_audit_logs(
        self, user_id: Optional[str] = None, action: Optional[str] = None, limit: int = 100
    ) -> List[dict]: ...

    # ── policy versions ───────────────────────────────────────

    @abstractmethod
    def save_policy_version(self, user_id: str, policy: dict, version: int) -> None: ...

    @abstractmethod
    def get_policy_versions(self, user_id: str) -> List[dict]: ...

    # ── helpers ───────────────────────────────────────────────

    @staticmethod
    def node_to_dict(node: NodeStatus) -> dict:
        from dataclasses import asdict
        data = asdict(node)
        data["updated_at"] = node.updated_at.isoformat()
        return data
