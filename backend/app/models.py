from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class UserStatus(str, Enum):
    ACTIVE = "active"
    BANNED = "banned"
    QUARANTINED = "quarantined"


class RiskAction(str, Enum):
    ALLOW = "allow"
    THROTTLE = "throttle"
    QUARANTINE = "quarantine"
    BAN = "ban"


@dataclass(slots=True)
class UserAccount:
    user_id: str
    password_hash: str
    plan: str = "free"
    status: UserStatus = UserStatus.ACTIVE
    created_at: datetime = field(default_factory=utc_now)


@dataclass(slots=True)
class DeviceBinding:
    user_id: str
    device_id: str
    device_label: str
    bound_at: datetime = field(default_factory=utc_now)


@dataclass(slots=True)
class NodeStatus:
    node_id: str
    region: str
    endpoint: str
    capacity: int
    current_load: int = 0
    avg_latency_ms: int = 35
    packet_loss_ratio: float = 0.0
    healthy: bool = True
    updated_at: datetime = field(default_factory=utc_now)


@dataclass(slots=True)
class SessionSnapshot:
    session_id: str
    user_id: str
    node_id: str
    egress_ip: str
    started_at: datetime
    ended_at: Optional[datetime] = None
    connection_count: int = 0
    unique_dst_ports: int = 0
    burst_bandwidth_mbps: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class RiskSignal:
    user_id: str
    session_id: str
    connection_count: int
    unique_dst_ports: int
    burst_bandwidth_mbps: float


@dataclass(slots=True)
class RiskResult:
    score: int
    action: RiskAction
    reasons: list[str]


@dataclass(slots=True)
class AbuseComplaint:
    egress_ip: str
    observed_at: datetime
    window_minutes: int = 15
