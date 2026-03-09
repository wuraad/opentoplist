"""SQLite-backed persistent store — drop-in replacement for InMemoryStore."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from secrets import token_urlsafe
from typing import List, Optional

from .models import (
    DeviceBinding,
    NodeStatus,
    SessionSnapshot,
    TokenRecord,
    UserAccount,
    UserStatus,
)
from .store import hash_password
from .store_base import BaseStore

DEFAULT_TOKEN_TTL = timedelta(hours=24)


class SqliteStore(BaseStore):
    def __init__(self, db_path: str = "vpn_control.db", admin_key: str = "admin-secret-key") -> None:
        self.admin_api_key = admin_key
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._create_tables()

    def _create_tables(self) -> None:
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                plan TEXT NOT NULL DEFAULT 'free',
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tokens (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                expires_at TEXT
            );
            CREATE TABLE IF NOT EXISTS devices (
                user_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                device_label TEXT NOT NULL,
                bound_at TEXT NOT NULL,
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
                healthy INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                egress_ip TEXT NOT NULL,
                started_at TEXT NOT NULL,
                ended_at TEXT,
                connection_count INTEGER NOT NULL DEFAULT 0,
                unique_dst_ports INTEGER NOT NULL DEFAULT 0,
                burst_bandwidth_mbps REAL NOT NULL DEFAULT 0.0,
                metadata TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS policies (
                user_id TEXT NOT NULL,
                policy TEXT NOT NULL,
                version INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (user_id, version)
            );
            CREATE TABLE IF NOT EXISTS user_policies (
                user_id TEXT PRIMARY KEY,
                policy TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                user_id TEXT,
                action TEXT NOT NULL,
                detail TEXT NOT NULL DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_egress ON sessions(egress_ip);
            CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
            CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
        """)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # ── auth ──────────────────────────────────────────────────

    def register_user(self, user_id: str, password: str, plan: str = "free") -> Optional[UserAccount]:
        now = datetime.now(timezone.utc).isoformat()
        try:
            self.conn.execute(
                "INSERT INTO users (user_id, password_hash, plan, status, created_at) VALUES (?,?,?,?,?)",
                (user_id, hash_password(password), plan, "active", now),
            )
            self.conn.commit()
        except sqlite3.IntegrityError:
            return None
        return UserAccount(user_id=user_id, password_hash=hash_password(password), plan=plan)

    def authenticate(self, user_id: str, password: str) -> bool:
        row = self.conn.execute("SELECT password_hash, status FROM users WHERE user_id=?", (user_id,)).fetchone()
        if not row:
            return False
        if row["status"] == "banned":
            return False
        return row["password_hash"] == hash_password(password)

    def issue_token(self, user_id: str, ttl: timedelta = DEFAULT_TOKEN_TTL) -> str:
        token = token_urlsafe(32)
        now = datetime.now(timezone.utc)
        expires = now + ttl
        self.conn.execute(
            "INSERT INTO tokens (token, user_id, issued_at, expires_at) VALUES (?,?,?,?)",
            (token, user_id, now.isoformat(), expires.isoformat()),
        )
        self.conn.commit()
        return token

    def validate_token(self, token: str) -> Optional[str]:
        row = self.conn.execute("SELECT user_id, expires_at FROM tokens WHERE token=?", (token,)).fetchone()
        if not row:
            return None
        if row["expires_at"]:
            expires = datetime.fromisoformat(row["expires_at"])
            if datetime.now(timezone.utc) > expires:
                self.revoke_token(token)
                return None
        user_row = self.conn.execute("SELECT status FROM users WHERE user_id=?", (row["user_id"],)).fetchone()
        if user_row and user_row["status"] == "banned":
            return None
        return row["user_id"]

    def revoke_token(self, token: str) -> bool:
        cur = self.conn.execute("DELETE FROM tokens WHERE token=?", (token,))
        self.conn.commit()
        return cur.rowcount > 0

    def revoke_all_user_tokens(self, user_id: str) -> int:
        cur = self.conn.execute("DELETE FROM tokens WHERE user_id=?", (user_id,))
        self.conn.commit()
        return cur.rowcount

    # ── devices ───────────────────────────────────────────────

    def bind_device(self, binding: DeviceBinding, max_devices: int = 3) -> dict:
        existing = self.conn.execute(
            "SELECT device_id FROM devices WHERE user_id=? AND device_id=?",
            (binding.user_id, binding.device_id),
        ).fetchone()
        if existing:
            return {"ok": True, "message": "device_already_bound"}
        count = self.conn.execute(
            "SELECT COUNT(*) as cnt FROM devices WHERE user_id=?", (binding.user_id,)
        ).fetchone()["cnt"]
        if count >= max_devices:
            return {"ok": False, "message": "device_limit_exceeded"}
        self.conn.execute(
            "INSERT INTO devices (user_id, device_id, device_label, bound_at) VALUES (?,?,?,?)",
            (binding.user_id, binding.device_id, binding.device_label, binding.bound_at.isoformat()),
        )
        self.conn.commit()
        return {"ok": True, "message": "device_bound"}

    def list_devices(self, user_id: str) -> List[DeviceBinding]:
        rows = self.conn.execute("SELECT * FROM devices WHERE user_id=?", (user_id,)).fetchall()
        return [
            DeviceBinding(
                user_id=r["user_id"], device_id=r["device_id"],
                device_label=r["device_label"],
                bound_at=datetime.fromisoformat(r["bound_at"]),
            )
            for r in rows
        ]

    def unbind_device(self, user_id: str, device_id: str) -> bool:
        cur = self.conn.execute("DELETE FROM devices WHERE user_id=? AND device_id=?", (user_id, device_id))
        self.conn.commit()
        return cur.rowcount > 0

    # ── nodes ─────────────────────────────────────────────────

    def upsert_node(self, node: NodeStatus) -> None:
        node.updated_at = datetime.now(timezone.utc)
        self.conn.execute("""
            INSERT INTO nodes (node_id, region, endpoint, capacity, current_load,
                               avg_latency_ms, packet_loss_ratio, healthy, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?)
            ON CONFLICT(node_id) DO UPDATE SET
                region=excluded.region, endpoint=excluded.endpoint,
                capacity=excluded.capacity, current_load=excluded.current_load,
                avg_latency_ms=excluded.avg_latency_ms, packet_loss_ratio=excluded.packet_loss_ratio,
                healthy=excluded.healthy, updated_at=excluded.updated_at
        """, (node.node_id, node.region, node.endpoint, node.capacity,
              node.current_load, node.avg_latency_ms, node.packet_loss_ratio,
              1 if node.healthy else 0, node.updated_at.isoformat()))
        self.conn.commit()

    def _row_to_node(self, r: sqlite3.Row) -> NodeStatus:
        return NodeStatus(
            node_id=r["node_id"], region=r["region"], endpoint=r["endpoint"],
            capacity=r["capacity"], current_load=r["current_load"],
            avg_latency_ms=r["avg_latency_ms"], packet_loss_ratio=r["packet_loss_ratio"],
            healthy=bool(r["healthy"]),
            updated_at=datetime.fromisoformat(r["updated_at"]),
        )

    def healthy_nodes(self, region: Optional[str] = None) -> List[NodeStatus]:
        if region:
            rows = self.conn.execute("SELECT * FROM nodes WHERE healthy=1 AND region=?", (region,)).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM nodes WHERE healthy=1").fetchall()
        return [self._row_to_node(r) for r in rows]

    def all_nodes(self) -> List[NodeStatus]:
        rows = self.conn.execute("SELECT * FROM nodes").fetchall()
        return [self._row_to_node(r) for r in rows]

    def mark_stale_nodes(self, threshold_minutes: int = 5) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=threshold_minutes)).isoformat()
        cur = self.conn.execute("UPDATE nodes SET healthy=0 WHERE healthy=1 AND updated_at<?", (cutoff,))
        self.conn.commit()
        return cur.rowcount

    # ── users / admin ─────────────────────────────────────────

    def update_user_status(self, user_id: str, status: UserStatus) -> bool:
        cur = self.conn.execute("UPDATE users SET status=? WHERE user_id=?", (status.value, user_id))
        self.conn.commit()
        if cur.rowcount == 0:
            return False
        if status == UserStatus.BANNED:
            self.revoke_all_user_tokens(user_id)
        return True

    def get_user_policy(self, user_id: str) -> Optional[dict]:
        row = self.conn.execute("SELECT policy FROM user_policies WHERE user_id=?", (user_id,)).fetchone()
        if not row:
            return None
        return json.loads(row["policy"])

    def set_user_policy(self, user_id: str, policy: dict) -> None:
        self.conn.execute(
            "INSERT INTO user_policies (user_id, policy) VALUES (?,?) ON CONFLICT(user_id) DO UPDATE SET policy=excluded.policy",
            (user_id, json.dumps(policy)),
        )
        self.conn.commit()

    def list_users(self) -> List[UserAccount]:
        rows = self.conn.execute("SELECT * FROM users").fetchall()
        return [
            UserAccount(
                user_id=r["user_id"], password_hash=r["password_hash"],
                plan=r["plan"], status=UserStatus(r["status"]),
                created_at=datetime.fromisoformat(r["created_at"]),
            )
            for r in rows
        ]

    def verify_admin_key(self, key: str) -> bool:
        return key == self.admin_api_key

    # ── sessions ──────────────────────────────────────────────

    def save_session(self, session: SessionSnapshot) -> None:
        self.conn.execute("""
            INSERT INTO sessions (session_id, user_id, node_id, egress_ip, started_at,
                                  ended_at, connection_count, unique_dst_ports,
                                  burst_bandwidth_mbps, metadata)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (session.session_id, session.user_id, session.node_id, session.egress_ip,
              session.started_at.isoformat(),
              session.ended_at.isoformat() if session.ended_at else None,
              session.connection_count, session.unique_dst_ports,
              session.burst_bandwidth_mbps, json.dumps(session.metadata)))
        self.conn.commit()

    def find_session_by_egress_ip_and_time(
        self, egress_ip: str, observed_at: datetime, window_minutes: int
    ) -> Optional[SessionSnapshot]:
        window = timedelta(minutes=window_minutes)
        lower = (observed_at - window).isoformat()
        upper = (observed_at + window).isoformat()
        row = self.conn.execute("""
            SELECT * FROM sessions WHERE egress_ip=? AND started_at<=? AND
            (ended_at IS NULL OR ended_at>=?) LIMIT 1
        """, (egress_ip, upper, lower)).fetchone()
        if not row:
            return None
        return SessionSnapshot(
            session_id=row["session_id"], user_id=row["user_id"],
            node_id=row["node_id"], egress_ip=row["egress_ip"],
            started_at=datetime.fromisoformat(row["started_at"]),
            ended_at=datetime.fromisoformat(row["ended_at"]) if row["ended_at"] else None,
            connection_count=row["connection_count"],
            unique_dst_ports=row["unique_dst_ports"],
            burst_bandwidth_mbps=row["burst_bandwidth_mbps"],
            metadata=json.loads(row["metadata"]),
        )

    # ── audit ─────────────────────────────────────────────────

    def append_audit_log(self, entry: dict) -> None:
        self.conn.execute(
            "INSERT INTO audit_log (ts, user_id, action, detail) VALUES (?,?,?,?)",
            (entry.get("ts", datetime.now(timezone.utc).isoformat()),
             entry.get("user_id"), entry["action"], json.dumps(entry.get("detail", {}))),
        )
        self.conn.commit()

    def query_audit_logs(
        self, user_id: Optional[str] = None, action: Optional[str] = None, limit: int = 100
    ) -> List[dict]:
        query = "SELECT * FROM audit_log WHERE 1=1"
        params: list = []
        if user_id:
            query += " AND user_id=?"
            params.append(user_id)
        if action:
            query += " AND action=?"
            params.append(action)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        rows = self.conn.execute(query, params).fetchall()
        return [
            {"id": r["id"], "ts": r["ts"], "user_id": r["user_id"],
             "action": r["action"], "detail": json.loads(r["detail"])}
            for r in rows
        ]

    # ── policy versions ───────────────────────────────────────

    def save_policy_version(self, user_id: str, policy: dict, version: int) -> None:
        self.conn.execute(
            "INSERT INTO policies (user_id, policy, version, created_at) VALUES (?,?,?,?)",
            (user_id, json.dumps(policy), version, datetime.now(timezone.utc).isoformat()),
        )
        self.conn.commit()

    def get_policy_versions(self, user_id: str) -> List[dict]:
        rows = self.conn.execute(
            "SELECT * FROM policies WHERE user_id=? ORDER BY version DESC", (user_id,)
        ).fetchall()
        return [
            {"user_id": r["user_id"], "policy": json.loads(r["policy"]),
             "version": r["version"], "created_at": r["created_at"]}
            for r in rows
        ]

    # ── helpers (users dict access for control_plane.py) ──────

    @property
    def users(self) -> "_UserProxy":
        return _UserProxy(self.conn)


class _UserProxy:
    """Allows control_plane.py to do store.users.get(user_id) against SQLite."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def get(self, user_id: str) -> Optional[UserAccount]:
        row = self._conn.execute("SELECT * FROM users WHERE user_id=?", (user_id,)).fetchone()
        if not row:
            return None
        return UserAccount(
            user_id=row["user_id"], password_hash=row["password_hash"],
            plan=row["plan"], status=UserStatus(row["status"]),
            created_at=datetime.fromisoformat(row["created_at"]),
        )
