"""JWT Token implementation — HMAC-SHA256 signed, stdlib only (no PyJWT)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Optional


_SECRET_KEY = os.environ.get("JWT_SECRET", "change-me-in-production-use-a-64-char-random-string")
_ALGORITHM = "HS256"
_DEFAULT_TTL = timedelta(hours=24)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _sign(header_payload: str, secret: str = _SECRET_KEY) -> str:
    sig = hmac.new(secret.encode("utf-8"), header_payload.encode("utf-8"), hashlib.sha256).digest()
    return _b64url_encode(sig)


def create_jwt(
    user_id: str,
    plan: str = "free",
    ttl: timedelta = _DEFAULT_TTL,
    secret: str = _SECRET_KEY,
) -> str:
    now = datetime.now(timezone.utc)
    header = {"alg": _ALGORITHM, "typ": "JWT"}
    payload = {
        "sub": user_id,
        "plan": plan,
        "iat": int(now.timestamp()),
        "exp": int((now + ttl).timestamp()),
    }
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    header_payload = f"{h}.{p}"
    sig = _sign(header_payload, secret)
    return f"{header_payload}.{sig}"


def verify_jwt(token: str, secret: str = _SECRET_KEY) -> Optional[dict]:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header_payload = f"{parts[0]}.{parts[1]}"
    expected_sig = _sign(header_payload, secret)
    if not hmac.compare_digest(parts[2], expected_sig):
        return None
    try:
        payload_bytes = _b64url_decode(parts[1])
        payload = json.loads(payload_bytes)
    except (json.JSONDecodeError, ValueError):
        return None
    exp = payload.get("exp")
    if exp and datetime.now(timezone.utc).timestamp() > exp:
        return None
    return payload


def decode_jwt_unsafe(token: str) -> Optional[dict]:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        return json.loads(_b64url_decode(parts[1]))
    except (json.JSONDecodeError, ValueError):
        return None
