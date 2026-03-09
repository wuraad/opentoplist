"""Server configuration — store selection, TLS, environment-driven settings."""
from __future__ import annotations

import os
import ssl
from typing import Optional

from .store import InMemoryStore


def create_store(backend: str | None = None):
    """Factory: create the right store based on env or explicit backend name."""
    backend = backend or os.environ.get("STORE_BACKEND", "memory")

    if backend == "sqlite":
        from .store_sqlite import SqliteStore
        db_path = os.environ.get("SQLITE_PATH", "vpn_control.db")
        return SqliteStore(db_path=db_path)

    if backend == "postgres":
        from .store_postgres import PostgresStore
        return PostgresStore(
            dsn=os.environ.get("DATABASE_URL"),
            pool_min=int(os.environ.get("PG_POOL_MIN", "2")),
            pool_max=int(os.environ.get("PG_POOL_MAX", "10")),
        )

    return InMemoryStore()


def create_ssl_context() -> Optional[ssl.SSLContext]:
    """Create SSL context from env vars TLS_CERT and TLS_KEY, or return None."""
    cert = os.environ.get("TLS_CERT")
    key = os.environ.get("TLS_KEY")
    if not cert or not key:
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx
