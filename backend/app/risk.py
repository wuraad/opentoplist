from __future__ import annotations

from dataclasses import asdict
from typing import Optional

from .models import RiskAction, RiskResult, RiskSignal, RiskThresholds

_DEFAULT_THRESHOLDS = RiskThresholds()


def evaluate_risk(
    signal: RiskSignal,
    thresholds: Optional[RiskThresholds] = None,
) -> RiskResult:
    t = thresholds or _DEFAULT_THRESHOLDS
    reasons: list[str] = []
    score = 0

    if signal.connection_count > t.conn_high:
        score += 45
        reasons.append("high_connection_count")
    elif signal.connection_count > t.conn_elevated:
        score += 25
        reasons.append("elevated_connection_count")

    if signal.unique_dst_ports > t.port_high:
        score += 35
        reasons.append("wide_port_spread")
    elif signal.unique_dst_ports > t.port_elevated:
        score += 20
        reasons.append("suspicious_port_spread")

    if signal.burst_bandwidth_mbps > t.bw_extreme:
        score += 30
        reasons.append("extreme_burst_bandwidth")
    elif signal.burst_bandwidth_mbps > t.bw_high:
        score += 15
        reasons.append("high_burst_bandwidth")

    if score >= t.score_ban:
        action = RiskAction.BAN
    elif score >= t.score_quarantine:
        action = RiskAction.QUARANTINE
    elif score >= t.score_throttle:
        action = RiskAction.THROTTLE
    else:
        action = RiskAction.ALLOW

    return RiskResult(score=score, action=action, reasons=reasons)


def result_to_dict(result: RiskResult) -> dict:
    data = asdict(result)
    data["action"] = result.action.value
    return data
