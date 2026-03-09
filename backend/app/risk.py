from __future__ import annotations

from dataclasses import asdict

from .models import RiskAction, RiskResult, RiskSignal


def evaluate_risk(signal: RiskSignal) -> RiskResult:
    reasons: list[str] = []
    score = 0

    if signal.connection_count > 1200:
        score += 45
        reasons.append("high_connection_count")
    elif signal.connection_count > 600:
        score += 25
        reasons.append("elevated_connection_count")

    if signal.unique_dst_ports > 120:
        score += 35
        reasons.append("wide_port_spread")
    elif signal.unique_dst_ports > 60:
        score += 20
        reasons.append("suspicious_port_spread")

    if signal.burst_bandwidth_mbps > 450:
        score += 30
        reasons.append("extreme_burst_bandwidth")
    elif signal.burst_bandwidth_mbps > 200:
        score += 15
        reasons.append("high_burst_bandwidth")

    if score >= 80:
        action = RiskAction.BAN
    elif score >= 55:
        action = RiskAction.QUARANTINE
    elif score >= 30:
        action = RiskAction.THROTTLE
    else:
        action = RiskAction.ALLOW

    return RiskResult(score=score, action=action, reasons=reasons)


def result_to_dict(result: RiskResult) -> dict:
    data = asdict(result)
    data["action"] = result.action.value
    return data
