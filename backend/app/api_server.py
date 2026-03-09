from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Callable, Iterable, Optional
from wsgiref.simple_server import make_server

from .control_plane import ControlPlaneService
from .models import AbuseComplaint, RiskSignal
from .risk import evaluate_risk, result_to_dict
from .store import InMemoryStore

JSON = tuple[str, list[tuple[str, str]], bytes]


def parse_json_body(environ: dict) -> dict:
    content_length = int(environ.get("CONTENT_LENGTH", "0") or "0")
    body = environ["wsgi.input"].read(content_length) if content_length > 0 else b"{}"
    if not body:
        return {}
    return json.loads(body.decode("utf-8"))


def to_json(payload: dict, status_code: int = 200) -> JSON:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    status_text = f"{status_code} {'OK' if status_code < 400 else 'ERROR'}"
    headers = [
        ("Content-Type", "application/json; charset=utf-8"),
        ("Content-Length", str(len(body))),
    ]
    return status_text, headers, body


class ApiApplication:
    def __init__(self) -> None:
        self.store = InMemoryStore()
        self.control = ControlPlaneService(self.store)

    def __call__(
        self,
        environ: dict,
        start_response: Callable[[str, list[tuple[str, str]]], None],
    ) -> Iterable[bytes]:
        method = environ["REQUEST_METHOD"]
        path = environ["PATH_INFO"]

        try:
            response = self.dispatch(method, path, environ)
        except Exception as exc:  # pragma: no cover - protect server process
            response = to_json({"ok": False, "error": str(exc)}, status_code=500)

        status, headers, body = response
        start_response(status, headers)
        return [body]

    def dispatch(self, method: str, path: str, environ: dict) -> JSON:
        if method == "GET" and path == "/healthz":
            return to_json({"ok": True, "service": "control-plane"})

        if method == "POST" and path == "/v1/auth/token":
            body = parse_json_body(environ)
            data = self.control.login(
                user_id=body["user_id"],
                password=body["password"],
                device_id=body["device_id"],
            )
            return to_json(data, status_code=200 if data.get("ok") else 401)

        if method == "POST" and path == "/v1/devices/bind":
            body = parse_json_body(environ)
            data = self.control.bind_device(
                user_id=body["user_id"],
                device_id=body["device_id"],
                device_label=body.get("device_label", "unknown"),
            )
            return to_json(data, status_code=200 if data.get("ok") else 400)

        if method == "POST" and path == "/v1/nodes/heartbeat":
            body = parse_json_body(environ)
            return to_json(self.control.report_node_heartbeat(body))

        if method == "GET" and path == "/v1/nodes/route":
            query = environ.get("QUERY_STRING", "")
            user_id = self._query_value(query, "user_id")
            region = self._query_value(query, "region")
            data = self.control.route_node(user_id=user_id, region=region)
            return to_json(data, status_code=200 if data.get("ok") else 404)

        if method == "POST" and path == "/v1/sessions/register":
            body = parse_json_body(environ)
            return to_json(
                self.control.register_session(
                    user_id=body["user_id"],
                    node_id=body["node_id"],
                    egress_ip=body["egress_ip"],
                )
            )

        if method == "POST" and path == "/v1/risk/evaluate":
            body = parse_json_body(environ)
            signal = RiskSignal(
                user_id=body["user_id"],
                session_id=body["session_id"],
                connection_count=int(body["connection_count"]),
                unique_dst_ports=int(body["unique_dst_ports"]),
                burst_bandwidth_mbps=float(body["burst_bandwidth_mbps"]),
            )
            result = evaluate_risk(signal)
            payload = result_to_dict(result)

            if result.action.value == "ban":
                self.control.ban_user(signal.user_id)
            elif result.action.value == "quarantine":
                self.control.quarantine_user(signal.user_id)

            return to_json({"ok": True, "risk": payload})

        if method == "POST" and path == "/v1/complaints/trace":
            body = parse_json_body(environ)
            complaint = AbuseComplaint(
                egress_ip=body["egress_ip"],
                observed_at=datetime.fromisoformat(body["observed_at"]).astimezone(
                    timezone.utc
                ),
                window_minutes=int(body.get("window_minutes", 15)),
            )
            hit = self.store.find_session_by_egress_ip_and_time(
                complaint.egress_ip,
                complaint.observed_at,
                complaint.window_minutes,
            )
            if not hit:
                return to_json({"ok": False, "message": "session_not_found"}, 404)
            return to_json(
                {
                    "ok": True,
                    "session_id": hit.session_id,
                    "user_id": hit.user_id,
                    "node_id": hit.node_id,
                }
            )

        ban_match = re.match(r"^/v1/admin/users/([^/]+)/ban$", path)
        if method == "POST" and ban_match:
            user_id = ban_match.group(1)
            data = self.control.ban_user(user_id)
            return to_json(data, status_code=200 if data.get("ok") else 404)

        policy_match = re.match(r"^/v1/admin/users/([^/]+)/policy$", path)
        if method == "POST" and policy_match:
            user_id = policy_match.group(1)
            body = parse_json_body(environ)
            data = self.control.push_policy(user_id, body)
            return to_json(data)

        return to_json({"ok": False, "message": "not_found"}, 404)

    @staticmethod
    def _query_value(query: str, key: str) -> Optional[str]:
        for part in query.split("&"):
            if "=" not in part:
                continue
            k, value = part.split("=", 1)
            if k == key:
                return value
        return None


def run_server(host: str = "0.0.0.0", port: int = 8080) -> None:
    app = ApiApplication()
    with make_server(host, port, app) as server:
        print(f"[control-plane] serving on http://{host}:{port}")
        server.serve_forever()


if __name__ == "__main__":
    run_server()
