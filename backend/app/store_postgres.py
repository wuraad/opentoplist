"""PostgreSQL persistent store — production backend.

Requires: psycopg2-binary (or psycopg2)
Configure via DATABASE_URL env var:
  DATABASE_URL=postgresql://user:pass@host:5432/vpn_db
"""
from __future__ import annotations

import json
import os
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from secrets import token_urlsafe
from typing import Generator, List, Optional

from .models import (
    DeviceBinding,
    NodeStatus,
    SessionSnapshot,
    UserAccount,
    UserStatus,
)
from .store import hash_password, verify_password
from .store_base import BaseStore

DEFAULT_TOKEN_TTL = timedelta(hours=24)

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT 'free',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS tokens (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(user_id),
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_tokens_user ON tokens(user_id);
CREATE TABLE IF NOT EXISTS devices (
    user_id TEXT NOT NULL REFERENCES users(user_id),
    device_id TEXT NOT NULL,
    device_label TEXT NOT NULL,
    bound_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, device_id)
);
CREATE TABLE IF NOT EXISTS nodes (
    node_id TEXT PRIMARY KEY,
    region TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    capacity INTEGER NOT NULL,
    current_load INTEGER NOT NULL DEFAULT 0,
    avg_latency_ms INTEGER NOT NULL DEFAULT 35,
    packet_loss_ratio REAL NOT NULL DEFAULT 0.0,
    healthy BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_nodes_region ON nodes(region);
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    egress_ip TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    ended_at TIMESTAMPTZ,
    connection_count INTEGER NOT NULL DEFAULT 0,
    unique_dst_ports INTEGER NOT NULL DEFAULT 0,
    burst_bandwidth_mbps REAL NOT NULL DEFAULT 0.0,
    metadata JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_sessions_egress ON sessions(egress_ip);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS policies (
    user_id TEXT NOT NULL,
    policy JSONB NOT NULL,
    version INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, version)
);
CREATE TABLE IF NOT EXISTS user_policies (
    user_id TEXT PRIMARY KEY,
    policy JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id TEXT,
    action TEXT NOT NULL,
    detail JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
"""


class PostgresStore(BaseStore):
    """Production PostgreSQL store with connection pooling."""

    def __init__(
        self,
        dsn: str | None = None,
        admin_key: str = "admin-secret-key",
        pool_min: int = 2,
        pool_max: int = 10,
    ) -> None:
        import psycopg2
        import psycopg2.pool

        self.admin_api_key = admin_key
        self._dsn = dsn or os.environ.get(
            "DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/vpn_db"
        )
        self._pool = psycopg2.pool.ThreadedConnectionPool(
            pool_min, pool_max, self._dsn
        )
        self._init_schema()

    def _init_schema(self) -> None:
        with self._cursor(commit=True) as cur:
            cur.execute(_SCHEMA_SQL)

    @contextmanager
    def _cursor(self, commit: bool = False) -> Generator:
        conn = self._pool.getconn()
        try:
            cur = conn.cursor()
            yield cur
            if commit:
                conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()
            self._pool.putconn(conn)

    def close(self) -> None:
        self._pool.closeall()

    # ── auth ──────────────────────────────────────────────────

    def register_user(self, user_id: str, password: str, plan: str = "free") -> Optional[UserAccount]:
        pw_hash = hash_password(password)
        try:
            with self._cursor(commit=True) as cur:
                cur.execute(
                    "INSERT INTO users (user_id, password_hash, plan) VALUES (%s,%s,%s) RETURNING created_at",
                    (user_id, pw_hash, plan),
                )
                row = cur.fetchone()
        except Exception:
            return None
        return UserAccount(user_id=user_id, password_hash=pw_hash, plan=plan,
                           created_at=row[0] if row else datetime.now(timezone.utc))

    def authenticate(self, user_id: str, password: str) -> bool:
        with self._cursor() as cur:
            cur.execute("SELECT password_hash, status FROM users WHERE user_id=%s", (user_id,))
            row = cur.fetchone()
        if not row:
            return False
        if row[1] == "banned":
            return False
        return verify_password(password, row[0])

    def issue_token(self, user_id: str, ttl: timedelta = DEFAULT_TOKEN_TTL) -> str:
        token = token_urlsafe(32)
        now = datetime.now(timezone.utc)
        with self._cursor(commit=True) as cur:
            cur.execute(
                "INSERT INTO tokens (token, user_id, issued_at, expires_at) VALUES (%s,%s,%s,%s)",
                (token, user_id, now, now + ttl),
            )
        return token

    def validate_token(self, token: str) -> Optional[str]:
        with self._cursor() as cur:
            cur.execute("SELECT user_id, expires_at FROM tokens WHERE token=%s", (token,))
            row = cur.fetchone()
        if not row:
            return None
        user_id, expires = row
        if expires and datetime.now(timezone.utc) > expires:
            self.revoke_token(token)
            return None
        with self._cursor() as cur:
            cur.execute("SELECT status FROM users WHERE user_id=%s", (user_id,))
            urow = cur.fetchone()
        if urow and urow[0] == "banned":
            return None
        return user_id

    def revoke_token(self, token: str) -> bool:
        with self._cursor(commit=True) as cur:
            cur.execute("DELETE FROM tokens WHERE token=%s", (token,))
            return cur.rowcount > 0

    def revoke_all_user_tokens(self, user_id: str) -> int:
        with self._cursor(commit=True) as cur:
            cur.execute("DELETE FROM tokens WHERE user_id=%s", (user_id,))
            return cur.rowcount

    # ── devices ───────────────────────────────────────────────

    def bind_device(self, binding: DeviceBinding, max_devices: int = 3) -> dict:
        with self._cursor() as cur:
            cur.execute("SELECT 1 FROM devices WHERE user_id=%s AND device_id=%s",
                        (binding.user_id, binding.device_id))
            if cur.fetchone():
                return {"ok": True, "message": "device_already_bound"}
            cur.execute("SELECT COUNT(*) FROM devices WHERE user_id=%s", (binding.user_id,))
            count = cur.fetchone()[0]
        if count >= max_devices:
            return {"ok": False, "message": "device_limit_exceeded"}
        with self._cursor(commit=True) as cur:
            cur.execute(
                "INSERT INTO devices (user_id, device_id, device_label, bound_at) VALUES (%s,%s,%s,%s)"
                " ON CONFLICT DO NOTHING",
                (binding.user_id, binding.device_id, binding.device_label, binding.bound_at),
            )
        return {"ok": True, "message": "device_bound"}

    def list_devices(self, user_id: str) -> List[DeviceBinding]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM devices WHERE user_id=%s", (user_id,))
            rows = cur.fetchall()
        return [DeviceBinding(user_id=r[0], device_id=r[1], device_label=r[2], bound_at=r[3]) for r in rows]

    def unbind_device(self, user_id: str, device_id: str) -> bool:
        with self._cursor(commit=True) as cur:
            cur.execute("DELETE FROM devices WHERE user_id=%s AND device_id=%s", (user_id, device_id))
            return cur.rowcount > 0

    # ── nodes ─────────────────────────────────────────────────

    def upsert_node(self, node: NodeStatus) -> None:
        node.updated_at = datetime.now(timezone.utc)
        with self._cursor(commit=True) as cur:
            cur.execute("""
                INSERT INTO nodes (node_id, region, endpoint, capacity, current_load,
                                   avg_latency_ms, packet_loss_ratio, healthy, updated_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(node_id) DO UPDATE SET
                    region=EXCLUDED.region, endpoint=EXCLUDED.endpoint,
                    capacity=EXCLUDED.capacity, current_load=EXCLUDED.current_load,
                    avg_latency_ms=EXCLUDED.avg_latency_ms, packet_loss_ratio=EXCLUDED.packet_loss_ratio,
                    healthy=EXCLUDED.healthy, updated_at=EXCLUDED.updated_at
            """, (node.node_id, node.region, node.endpoint, node.capacity,
                  node.current_load, node.avg_latency_ms, node.packet_loss_ratio,
                  node.healthy, node.updated_at))

    def _row_to_node(self, r: tuple) -> NodeStatus:
        return NodeStatus(
            node_id=r[0], region=r[1], endpoint=r[2], capacity=r[3],
            current_load=r[4], avg_latency_ms=r[5], packet_loss_ratio=r[6],
            healthy=r[7], updated_at=r[8],
        )

    def healthy_nodes(self, region: Optional[str] = None) -> List[NodeStatus]:
        with self._cursor() as cur:
            if region:
                cur.execute("SELECT * FROM nodes WHERE healthy=TRUE AND region=%s", (region,))
            else:
                cur.execute("SELECT * FROM nodes WHERE healthy=TRUE")
            return [self._row_to_node(r) for r in cur.fetchall()]

    def all_nodes(self) -> List[NodeStatus]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM nodes")
            return [self._row_to_node(r) for r in cur.fetchall()]

    def mark_stale_nodes(self, threshold_minutes: int = 5) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=threshold_minutes)
        with self._cursor(commit=True) as cur:
            cur.execute("UPDATE nodes SET healthy=FALSE WHERE healthy=TRUE AND updated_at<%s", (cutoff,))
            return cur.rowcount

    # ── users / admin ─────────────────────────────────────────

    def update_user_status(self, user_id: str, status: UserStatus) -> bool:
        with self._cursor(commit=True) as cur:
            cur.execute("UPDATE users SET status=%s WHERE user_id=%s", (status.value, user_id))
            if cur.rowcount == 0:
                return False
        if status == UserStatus.BANNED:
            self.revoke_all_user_tokens(user_id)
        return True

    def get_user_policy(self, user_id: str) -> Optional[dict]:
        with self._cursor() as cur:
            cur.execute("SELECT policy FROM user_policies WHERE user_id=%s", (user_id,))
            row = cur.fetchone()
        return row[0] if row else None

    def set_user_policy(self, user_id: str, policy: dict) -> None:
        with self._cursor(commit=True) as cur:
            cur.execute("""
                INSERT INTO user_policies (user_id, policy) VALUES (%s,%s)
                ON CONFLICT(user_id) DO UPDATE SET policy=EXCLUDED.policy
            """, (user_id, json.dumps(policy)))

    def list_users(self) -> List[UserAccount]:
        with self._cursor() as cur:
            cur.execute("SELECT user_id, password_hash, plan, status, created_at FROM users")
            return [
                UserAccount(user_id=r[0], password_hash=r[1], plan=r[2],
                            status=UserStatus(r[3]), created_at=r[4])
                for r in cur.fetchall()
            ]

    def verify_admin_key(self, key: str) -> bool:
        return key == self.admin_api_key

    # ── sessions ──────────────────────────────────────────────

    def save_session(self, session: SessionSnapshot) -> None:
        with self._cursor(commit=True) as cur:
            cur.execute("""
                INSERT INTO sessions (session_id, user_id, node_id, egress_ip, started_at,
                                      ended_at, connection_count, unique_dst_ports,
                                      burst_bandwidth_mbps, metadata)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (session.session_id, session.user_id, session.node_id, session.egress_ip,
                  session.started_at, session.ended_at, session.connection_count,
                  session.unique_dst_ports, session.burst_bandwidth_mbps,
                  json.dumps(session.metadata)))

    def find_session_by_egress_ip_and_time(
        self, egress_ip: str, observed_at: datetime, window_minutes: int
    ) -> Optional[SessionSnapshot]:
        window = timedelta(minutes=window_minutes)
        lower = observed_at - window
        upper = observed_at + window
        with self._cursor() as cur:
            cur.execute("""
                SELECT * FROM sessions WHERE egress_ip=%s AND started_at<=%s
                AND (ended_at IS NULL OR ended_at>=%s) LIMIT 1
            """, (egress_ip, upper, lower))
            row = cur.fetchone()
        if not row:
            return None
        return SessionSnapshot(
            session_id=row[0], user_id=row[1], node_id=row[2], egress_ip=row[3],
            started_at=row[4], ended_at=row[5], connection_count=row[6],
            unique_dst_ports=row[7], burst_bandwidth_mbps=row[8],
            metadata=row[9] if isinstance(row[9], dict) else json.loads(row[9] or "{}"),
        )

    # ── audit ─────────────────────────────────────────────────

    def append_audit_log(self, entry: dict) -> None:
        with self._cursor(commit=True) as cur:
            cur.execute(
                "INSERT INTO audit_log (ts, user_id, action, detail) VALUES (%s,%s,%s,%s)",
                (entry.get("ts", datetime.now(timezone.utc)),
                 entry.get("user_id"), entry["action"], json.dumps(entry.get("detail", {}))),
            )

    def query_audit_logs(
        self, user_id: Optional[str] = None, action: Optional[str] = None, limit: int = 100
    ) -> List[dict]:
        query = "SELECT id, ts, user_id, action, detail FROM audit_log WHERE TRUE"
        params: list = []
        if user_id:
            query += " AND user_id=%s"
            params.append(user_id)
        if action:
            query += " AND action=%s"
            params.append(action)
        query += " ORDER BY id DESC LIMIT %s"
        params.append(limit)
        with self._cursor() as cur:
            cur.execute(query, params)
            return [
                {"id": r[0], "ts": r[1].isoformat() if hasattr(r[1], 'isoformat') else str(r[1]),
                 "user_id": r[2], "action": r[3],
                 "detail": r[4] if isinstance(r[4], dict) else json.loads(r[4] or "{}")}
                for r in cur.fetchall()
            ]

    # ── policy versions ───────────────────────────────────────

    def save_policy_version(self, user_id: str, policy: dict, version: int) -> None:
        with self._cursor(commit=True) as cur:
            cur.execute(
                "INSERT INTO policies (user_id, policy, version) VALUES (%s,%s,%s)",
                (user_id, json.dumps(policy), version),
            )

    def get_policy_versions(self, user_id: str) -> List[dict]:
        with self._cursor() as cur:
            cur.execute("SELECT user_id, policy, version, created_at FROM policies WHERE user_id=%s ORDER BY version DESC", (user_id,))
            return [
                {"user_id": r[0],
                 "policy": r[1] if isinstance(r[1], dict) else json.loads(r[1] or "{}"),
                 "version": r[2],
                 "created_at": r[3].isoformat() if hasattr(r[3], 'isoformat') else str(r[3])}
                for r in cur.fetchall()
            ]

    @property
    def users(self) -> _PgUserProxy:
        return _PgUserProxy(self)


class _PgUserProxy:
    def __init__(self, store: PostgresStore) -> None:
        self._store = store

    def get(self, user_id: str) -> Optional[UserAccount]:
        with self._store._cursor() as cur:
            cur.execute("SELECT user_id, password_hash, plan, status, created_at FROM users WHERE user_id=%s", (user_id,))
            row = cur.fetchone()
        if not row:
            return None
        return UserAccount(user_id=row[0], password_hash=row[1], plan=row[2],
                           status=UserStatus(row[3]), created_at=row[4])
