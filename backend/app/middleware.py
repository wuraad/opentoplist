"""WSGI middleware stack: CORS, rate limiting, structured request logging."""
from __future__ import annotations

import json
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Callable, Iterable


class CORSMiddleware:
    """Adds CORS headers; handles OPTIONS preflight."""

    def __init__(
        self,
        app: Callable,
        allow_origins: str = "*",
        allow_methods: str = "GET, POST, PUT, DELETE, OPTIONS",
        allow_headers: str = "Content-Type, Authorization, X-Admin-Key",
    ) -> None:
        self.app = app
        self.cors_headers = [
            ("Access-Control-Allow-Origin", allow_origins),
            ("Access-Control-Allow-Methods", allow_methods),
            ("Access-Control-Allow-Headers", allow_headers),
            ("Access-Control-Max-Age", "86400"),
        ]

    def __call__(self, environ: dict, start_response: Callable) -> Iterable[bytes]:
        if environ["REQUEST_METHOD"] == "OPTIONS":
            start_response("204 No Content", self.cors_headers)
            return [b""]

        def _start(status: str, headers: list) -> None:
            start_response(status, headers + self.cors_headers)

        return self.app(environ, _start)


class RateLimitMiddleware:
    """Token-bucket rate limiter per client IP."""

    def __init__(
        self,
        app: Callable,
        requests_per_minute: int = 120,
        burst: int = 20,
    ) -> None:
        self.app = app
        self.rate = requests_per_minute / 60.0
        self.burst = burst
        self._buckets: dict[str, list[float]] = defaultdict(lambda: [float(burst), time.monotonic()])

    def _allow(self, key: str) -> bool:
        bucket = self._buckets[key]
        now = time.monotonic()
        elapsed = now - bucket[1]
        bucket[1] = now
        bucket[0] = min(bucket[0] + elapsed * self.rate, float(self.burst))
        if bucket[0] >= 1.0:
            bucket[0] -= 1.0
            return True
        return False

    def __call__(self, environ: dict, start_response: Callable) -> Iterable[bytes]:
        client_ip = environ.get("REMOTE_ADDR", environ.get("HTTP_X_FORWARDED_FOR", "unknown"))
        if not self._allow(client_ip):
            body = json.dumps({"ok": False, "message": "rate_limited"}).encode("utf-8")
            start_response("429 Too Many Requests", [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(body))),
                ("Retry-After", "5"),
            ])
            return [body]
        return self.app(environ, start_response)


class RequestLogMiddleware:
    """Logs every request as structured JSON to a callback."""

    def __init__(self, app: Callable, log_fn: Callable[[dict], None] | None = None) -> None:
        self.app = app
        self.log_fn = log_fn

    def __call__(self, environ: dict, start_response: Callable) -> Iterable[bytes]:
        start = time.monotonic()
        status_holder: list[str] = []

        def _start(status: str, headers: list) -> None:
            status_holder.append(status)
            start_response(status, headers)

        result = self.app(environ, _start)
        elapsed_ms = round((time.monotonic() - start) * 1000, 2)

        if self.log_fn:
            entry = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "method": environ.get("REQUEST_METHOD", ""),
                "path": environ.get("PATH_INFO", ""),
                "status": status_holder[0] if status_holder else "?",
                "client_ip": environ.get("REMOTE_ADDR", ""),
                "elapsed_ms": elapsed_ms,
            }
            self.log_fn(entry)
        return result
