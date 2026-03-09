"""Complaint email parsing pipeline — extracts IP + timestamp from abuse reports."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


@dataclass(slots=True)
class ParsedComplaint:
    egress_ip: str
    observed_at: datetime
    source_email: str = ""
    subject: str = ""
    raw_snippet: str = ""


_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_TS_PATTERNS = [
    re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s]*"),
    re.compile(r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}"),
    re.compile(r"\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}"),
]

_PRIVATE_RANGES = [
    (0x0A000000, 0x0AFFFFFF),  # 10.0.0.0/8
    (0xAC100000, 0xAC1FFFFF),  # 172.16.0.0/12
    (0xC0A80000, 0xC0A8FFFF),  # 192.168.0.0/16
    (0x7F000000, 0x7FFFFFFF),  # 127.0.0.0/8
]


def _is_private_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        num = (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])
    except ValueError:
        return True
    return any(lo <= num <= hi for lo, hi in _PRIVATE_RANGES)


def _parse_timestamp(text: str) -> Optional[datetime]:
    for pat in _TS_PATTERNS:
        m = pat.search(text)
        if m:
            raw = m.group(0)
            for fmt in [None, "%Y-%m-%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S"]:
                try:
                    if fmt is None:
                        dt = datetime.fromisoformat(raw)
                    else:
                        dt = datetime.strptime(raw, fmt)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt
                except (ValueError, TypeError):
                    continue
    return None


def parse_complaint_text(
    body: str,
    source_email: str = "",
    subject: str = "",
) -> Optional[ParsedComplaint]:
    ips = _IP_RE.findall(body)
    public_ips = [ip for ip in ips if not _is_private_ip(ip)]
    if not public_ips:
        return None

    ts = _parse_timestamp(body)
    if ts is None:
        ts = datetime.now(timezone.utc)

    return ParsedComplaint(
        egress_ip=public_ips[0],
        observed_at=ts,
        source_email=source_email,
        subject=subject,
        raw_snippet=body[:500],
    )


def parse_complaint_email(headers: dict, body: str) -> Optional[ParsedComplaint]:
    return parse_complaint_text(
        body=body,
        source_email=headers.get("from", headers.get("From", "")),
        subject=headers.get("subject", headers.get("Subject", "")),
    )
