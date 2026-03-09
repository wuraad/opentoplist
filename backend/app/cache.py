"""Cache layer — Redis-backed with in-memory fallback (stdlib only for fallback)."""
from __future__ import annotations

import time
from typing import Any, Optional


class MemoryCache:
    """In-process TTL cache — used when Redis is unavailable."""

    def __init__(self) -> None:
        self._data: dict[str, tuple[Any, float]] = {}

    def get(self, key: str) -> Optional[str]:
        entry = self._data.get(key)
        if entry is None:
            return None
        value, expires = entry
        if expires and time.monotonic() > expires:
            del self._data[key]
            return None
        return value

    def set(self, key: str, value: str, ttl_seconds: int = 0) -> None:
        expires = (time.monotonic() + ttl_seconds) if ttl_seconds > 0 else 0
        self._data[key] = (value, expires)

    def delete(self, key: str) -> bool:
        return self._data.pop(key, None) is not None

    def delete_pattern(self, prefix: str) -> int:
        keys = [k for k in self._data if k.startswith(prefix)]
        for k in keys:
            del self._data[k]
        return len(keys)

    def exists(self, key: str) -> bool:
        return self.get(key) is not None

    def flush(self) -> None:
        self._data.clear()


class RedisCache:
    """Redis cache wrapper — requires `redis` package.
    Falls back to MemoryCache if redis is not available."""

    def __init__(self, url: str = "redis://localhost:6379/0") -> None:
        self._url = url
        self._redis: Any = None
        self._fallback = MemoryCache()
        self._try_connect()

    def _try_connect(self) -> None:
        try:
            import redis
            self._redis = redis.from_url(self._url, decode_responses=True)
            self._redis.ping()
        except Exception:
            self._redis = None

    @property
    def connected(self) -> bool:
        return self._redis is not None

    def get(self, key: str) -> Optional[str]:
        if self._redis:
            try:
                return self._redis.get(key)
            except Exception:
                pass
        return self._fallback.get(key)

    def set(self, key: str, value: str, ttl_seconds: int = 0) -> None:
        if self._redis:
            try:
                if ttl_seconds > 0:
                    self._redis.setex(key, ttl_seconds, value)
                else:
                    self._redis.set(key, value)
                return
            except Exception:
                pass
        self._fallback.set(key, value, ttl_seconds)

    def delete(self, key: str) -> bool:
        if self._redis:
            try:
                return self._redis.delete(key) > 0
            except Exception:
                pass
        return self._fallback.delete(key)

    def delete_pattern(self, prefix: str) -> int:
        if self._redis:
            try:
                keys = self._redis.keys(f"{prefix}*")
                if keys:
                    return self._redis.delete(*keys)
                return 0
            except Exception:
                pass
        return self._fallback.delete_pattern(prefix)

    def exists(self, key: str) -> bool:
        if self._redis:
            try:
                return self._redis.exists(key) > 0
            except Exception:
                pass
        return self._fallback.exists(key)


class TokenCache:
    """High-level token caching on top of cache backend."""

    def __init__(self, cache: MemoryCache | RedisCache) -> None:
        self._cache = cache

    def cache_token(self, token: str, user_id: str, ttl: int = 86400) -> None:
        self._cache.set(f"tok:{token}", user_id, ttl)

    def get_user_for_token(self, token: str) -> Optional[str]:
        return self._cache.get(f"tok:{token}")

    def invalidate_token(self, token: str) -> None:
        self._cache.delete(f"tok:{token}")

    def invalidate_user_tokens(self, user_id: str) -> int:
        return self._cache.delete_pattern(f"tok:")

    def cache_session(self, session_id: str, data: str, ttl: int = 3600) -> None:
        self._cache.set(f"sess:{session_id}", data, ttl)

    def get_session(self, session_id: str) -> Optional[str]:
        return self._cache.get(f"sess:{session_id}")
