"""Lightweight Prometheus-compatible metrics — stdlib only, no external deps."""
from __future__ import annotations

import time
from collections import defaultdict
from typing import Optional


class Counter:
    __slots__ = ("_name", "_help", "_values")

    def __init__(self, name: str, help_text: str = "") -> None:
        self._name = name
        self._help = help_text
        self._values: dict[str, float] = defaultdict(float)

    def inc(self, labels: Optional[dict[str, str]] = None, value: float = 1.0) -> None:
        key = _labels_key(labels)
        self._values[key] += value

    def collect(self) -> list[str]:
        lines = [f"# HELP {self._name} {self._help}", f"# TYPE {self._name} counter"]
        for key, val in sorted(self._values.items()):
            lines.append(f"{self._name}{key} {val}")
        return lines


class Histogram:
    __slots__ = ("_name", "_help", "_buckets", "_data")

    def __init__(self, name: str, help_text: str = "", buckets: tuple[float, ...] = (5, 10, 25, 50, 100, 250, 500, 1000)) -> None:
        self._name = name
        self._help = help_text
        self._buckets = buckets
        self._data: dict[str, dict[str, float]] = defaultdict(lambda: self._empty_bucket())

    def _empty_bucket(self) -> dict[str, float]:
        d: dict[str, float] = {}
        for b in self._buckets:
            d[str(b)] = 0
        d["+Inf"] = 0
        d["_sum"] = 0
        d["_count"] = 0
        return d

    def observe(self, value: float, labels: Optional[dict[str, str]] = None) -> None:
        key = _labels_key(labels)
        data = self._data[key]
        data["_sum"] += value
        data["_count"] += 1
        for b in self._buckets:
            if value <= b:
                data[str(b)] += 1
        data["+Inf"] += 1

    def collect(self) -> list[str]:
        lines = [f"# HELP {self._name} {self._help}", f"# TYPE {self._name} histogram"]
        for key, data in sorted(self._data.items()):
            for b in self._buckets:
                lines.append(f'{self._name}_bucket{{le="{b}"{_comma(key)}}} {data[str(b)]}')
            lines.append(f'{self._name}_bucket{{le="+Inf"{_comma(key)}}} {data["+Inf"]}')
            lines.append(f"{self._name}_sum{key} {data['_sum']}")
            lines.append(f"{self._name}_count{key} {data['_count']}")
        return lines


class Gauge:
    __slots__ = ("_name", "_help", "_values")

    def __init__(self, name: str, help_text: str = "") -> None:
        self._name = name
        self._help = help_text
        self._values: dict[str, float] = defaultdict(float)

    def set(self, value: float, labels: Optional[dict[str, str]] = None) -> None:
        self._values[_labels_key(labels)] = value

    def inc(self, labels: Optional[dict[str, str]] = None, value: float = 1.0) -> None:
        self._values[_labels_key(labels)] += value

    def collect(self) -> list[str]:
        lines = [f"# HELP {self._name} {self._help}", f"# TYPE {self._name} gauge"]
        for key, val in sorted(self._values.items()):
            lines.append(f"{self._name}{key} {val}")
        return lines


def _labels_key(labels: Optional[dict[str, str]]) -> str:
    if not labels:
        return ""
    parts = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
    return "{" + parts + "}"


def _comma(key: str) -> str:
    if key and key.startswith("{") and key.endswith("}"):
        return "," + key[1:-1]
    return ""


class MetricsRegistry:
    """Central registry for all application metrics."""

    def __init__(self) -> None:
        self.http_requests = Counter("http_requests_total", "Total HTTP requests")
        self.http_latency = Histogram("http_request_duration_ms", "HTTP request latency in ms")
        self.active_sessions = Gauge("active_sessions", "Currently active VPN sessions")
        self.risk_evaluations = Counter("risk_evaluations_total", "Risk evaluations by action")
        self.auth_attempts = Counter("auth_attempts_total", "Authentication attempts")
        self.node_health = Gauge("node_healthy", "Node health status (1=healthy, 0=unhealthy)")

    def render(self) -> str:
        lines: list[str] = []
        for metric in [self.http_requests, self.http_latency, self.active_sessions,
                       self.risk_evaluations, self.auth_attempts, self.node_health]:
            lines.extend(metric.collect())
            lines.append("")
        return "\n".join(lines) + "\n"
