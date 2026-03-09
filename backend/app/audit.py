"""Audit logging — records every significant control-plane action."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional


class AuditLogger:
    """Thin wrapper around the store's audit log."""

    def __init__(self, store: Any) -> None:
        self._store = store

    def log(
        self,
        action: str,
        user_id: Optional[str] = None,
        detail: Optional[dict] = None,
    ) -> None:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "user_id": user_id,
            "detail": detail or {},
        }
        self._store.append_audit_log(entry)

    def query(
        self,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        return self._store.query_audit_logs(user_id=user_id, action=action, limit=limit)
