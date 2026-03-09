"""Alerting system — webhook-based notifications for anomaly events."""
from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional


@dataclass(slots=True)
class AlertRule:
    name: str
    condition: str
    threshold: float
    action: str = "notify"


@dataclass
class AlertEvent:
    rule_name: str
    severity: str
    message: str
    ts: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    detail: dict = field(default_factory=dict)


class AlertManager:
    """Evaluates traffic metrics against rules and fires alerts."""

    def __init__(self, webhook_url: Optional[str] = None) -> None:
        self.webhook_url = webhook_url
        self._rules: list[AlertRule] = self._default_rules()
        self._history: list[AlertEvent] = []
        self._callbacks: list[Callable[[AlertEvent], None]] = []

    @staticmethod
    def _default_rules() -> list[AlertRule]:
        return [
            AlertRule(name="high_conn_rate", condition="connection_rate_per_min", threshold=5000),
            AlertRule(name="node_capacity_high", condition="node_load_ratio", threshold=0.9),
            AlertRule(name="ban_rate_spike", condition="bans_per_hour", threshold=20),
            AlertRule(name="packet_loss_high", condition="avg_packet_loss", threshold=0.05),
        ]

    def add_callback(self, cb: Callable[[AlertEvent], None]) -> None:
        self._callbacks.append(cb)

    def evaluate_node_metrics(self, nodes: list[dict]) -> list[AlertEvent]:
        events: list[AlertEvent] = []
        for node in nodes:
            load_ratio = node.get("current_load", 0) / max(node.get("capacity", 1), 1)
            if load_ratio >= 0.9:
                evt = AlertEvent(
                    rule_name="node_capacity_high",
                    severity="warning",
                    message=f"Node {node.get('node_id')} load at {load_ratio:.0%}",
                    detail={"node_id": node.get("node_id"), "load_ratio": round(load_ratio, 3)},
                )
                events.append(evt)

            pkt_loss = node.get("packet_loss_ratio", 0.0)
            if pkt_loss >= 0.05:
                evt = AlertEvent(
                    rule_name="packet_loss_high",
                    severity="critical" if pkt_loss >= 0.1 else "warning",
                    message=f"Node {node.get('node_id')} packet loss {pkt_loss:.1%}",
                    detail={"node_id": node.get("node_id"), "packet_loss_ratio": pkt_loss},
                )
                events.append(evt)

        for evt in events:
            self._fire(evt)
        return events

    def evaluate_risk_action(self, user_id: str, action: str, score: int) -> Optional[AlertEvent]:
        if action in ("ban", "quarantine"):
            evt = AlertEvent(
                rule_name="risk_action_taken",
                severity="warning" if action == "quarantine" else "critical",
                message=f"User {user_id} → {action} (score={score})",
                detail={"user_id": user_id, "action": action, "score": score},
            )
            self._fire(evt)
            return evt
        return None

    def _fire(self, event: AlertEvent) -> None:
        self._history.append(event)
        for cb in self._callbacks:
            try:
                cb(event)
            except Exception:
                pass
        if self.webhook_url:
            self._send_webhook(event)

    def _send_webhook(self, event: AlertEvent) -> None:
        payload = json.dumps({
            "rule": event.rule_name,
            "severity": event.severity,
            "message": event.message,
            "ts": event.ts,
            "detail": event.detail,
        }).encode("utf-8")
        try:
            req = urllib.request.Request(
                self.webhook_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=3)
        except Exception:
            pass

    def recent_alerts(self, limit: int = 50) -> list[dict]:
        return [
            {
                "rule_name": e.rule_name,
                "severity": e.severity,
                "message": e.message,
                "ts": e.ts,
                "detail": e.detail,
            }
            for e in reversed(self._history[-limit:])
        ]
