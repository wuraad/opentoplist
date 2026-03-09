from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Callable, Iterable, Optional
from urllib.parse import parse_qs
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
    status_map = {200: "200 OK", 201: "201 Created", 400: "400 Bad Request",
                  401: "401 Unauthorized", 403: "403 Forbidden", 404: "404 Not Found",
                  500: "500 Internal Server Error"}
    status_text = status_map.get(status_code, f"{status_code} ERROR")
    headers = [
        ("Content-Type", "application/json; charset=utf-8"),
        ("Content-Length", str(len(body))),
    ]
    return status_text, headers, body


def require_fields(body: dict, *fields: str) -> Optional[JSON]:
    missing = [f for f in fields if f not in body or body[f] is None]
    if missing:
        return to_json(
            {"ok": False, "message": "missing_fields", "fields": missing}, 400
        )
    return None


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
        except json.JSONDecodeError:
            response = to_json({"ok": False, "message": "invalid_json"}, 400)
        except KeyError as exc:
            response = to_json(
                {"ok": False, "message": "missing_field", "field": str(exc)}, 400
            )
        except (ValueError, TypeError) as exc:
            response = to_json({"ok": False, "message": str(exc)}, 400)
        except Exception as exc:  # pragma: no cover
            response = to_json({"ok": False, "error": str(exc)}, status_code=500)

        status, headers, body = response
        start_response(status, headers)
        return [body]

    # ── helpers ───────────────────────────────────────────────

    def _bearer_token(self, environ: dict) -> Optional[str]:
        auth = environ.get("HTTP_AUTHORIZATION", "")
        if auth.startswith("Bearer "):
            return auth[7:]
        return None

    def _resolve_user(self, environ: dict) -> Optional[str]:
        token = self._bearer_token(environ)
        if token is None:
            return None
        return self.store.validate_token(token)

    def _require_auth(self, environ: dict) -> tuple[Optional[str], Optional[JSON]]:
        user_id = self._resolve_user(environ)
        if user_id is None:
            return None, to_json({"ok": False, "message": "unauthorized"}, 401)
        return user_id, None

    def _require_admin(self, environ: dict) -> Optional[JSON]:
        key = environ.get("HTTP_X_ADMIN_KEY", "")
        if not self.store.verify_admin_key(key):
            return to_json({"ok": False, "message": "forbidden"}, 403)
        return None

    @staticmethod
    def _query_params(environ: dict) -> dict[str, str]:
        qs = environ.get("QUERY_STRING", "")
        parsed = parse_qs(qs)
        return {k: v[0] for k, v in parsed.items()}

    # ── dispatch ──────────────────────────────────────────────

    def dispatch(self, method: str, path: str, environ: dict) -> JSON:
        if method == "GET" and path == "/healthz":
            return to_json({"ok": True, "service": "control-plane"})

        # ── public auth ──────────────────────────────────────
        if method == "POST" and path == "/v1/auth/register":
            body = parse_json_body(environ)
            err = require_fields(body, "user_id", "password")
            if err:
                return err
            data = self.control.register(
                user_id=body["user_id"],
                password=body["password"],
                plan=body.get("plan", "free"),
            )
            sc = 201 if data.get("ok") else 400
            return to_json(data, sc)

        if method == "POST" and path == "/v1/auth/token":
            body = parse_json_body(environ)
            err = require_fields(body, "user_id", "password", "device_id")
            if err:
                return err
            data = self.control.login(
                user_id=body["user_id"],
                password=body["password"],
                device_id=body["device_id"],
            )
            return to_json(data, status_code=200 if data.get("ok") else 401)

        if method == "POST" and path == "/v1/auth/logout":
            token = self._bearer_token(environ)
            if not token:
                return to_json({"ok": False, "message": "unauthorized"}, 401)
            data = self.control.logout(token)
            return to_json(data)

        # ── token-protected endpoints ────────────────────────
        if method == "POST" and path == "/v1/devices/bind":
            user_id, err = self._require_auth(environ)
            if err:
                return err
            body = parse_json_body(environ)
            err = require_fields(body, "device_id")
            if err:
                return err
            data = self.control.bind_device(
                user_id=user_id,
                device_id=body["device_id"],
                device_label=body.get("device_label", "unknown"),
            )
            return to_json(data, status_code=200 if data.get("ok") else 400)

        if method == "GET" and path == "/v1/devices":
            user_id, err = self._require_auth(environ)
            if err:
                return err
            return to_json(self.control.list_devices(user_id))

        if method == "DELETE" and re.match(r"^/v1/devices/[^/]+$", path):
            user_id, err = self._require_auth(environ)
            if err:
                return err
            device_id = path.split("/")[-1]
            data = self.control.unbind_device(user_id, device_id)
            return to_json(data, status_code=200 if data.get("ok") else 404)

        if method == "POST" and path == "/v1/nodes/heartbeat":
            body = parse_json_body(environ)
            err = require_fields(body, "node_id", "region", "endpoint", "capacity")
            if err:
                return err
            return to_json(self.control.report_node_heartbeat(body))

        if method == "GET" and path == "/v1/nodes":
            params = self._query_params(environ)
            return to_json(self.control.list_nodes(region=params.get("region")))

        if method == "GET" and path == "/v1/nodes/route":
            user_id, err = self._require_auth(environ)
            if err:
                return err
            params = self._query_params(environ)
            data = self.control.route_node(
                user_id=user_id, region=params.get("region")
            )
            return to_json(data, status_code=200 if data.get("ok") else 404)

        if method == "GET" and path == "/v1/users/me/policy":
            user_id, err = self._require_auth(environ)
            if err:
                return err
            data = self.control.get_policy(user_id)
            return to_json(data, status_code=200 if data.get("ok") else 404)

        if method == "POST" and path == "/v1/sessions/register":
            user_id, err = self._require_auth(environ)
            if err:
                return err
            body = parse_json_body(environ)
            err = require_fields(body, "node_id", "egress_ip")
            if err:
                return err
            return to_json(
                self.control.register_session(
                    user_id=user_id,
                    node_id=body["node_id"],
                    egress_ip=body["egress_ip"],
                )
            )

        # ── risk ─────────────────────────────────────────────
        if method == "POST" and path == "/v1/risk/evaluate":
            body = parse_json_body(environ)
            err = require_fields(
                body, "user_id", "session_id",
                "connection_count", "unique_dst_ports", "burst_bandwidth_mbps",
            )
            if err:
                return err
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
            elif result.action.value == "throttle":
                self.store.set_user_policy(signal.user_id, {
                    "throttle": True,
                    "bandwidth_limit_mbps": 50,
                    "reason": "risk_throttle",
                })

            return to_json({"ok": True, "risk": payload})

        if method == "POST" and path == "/v1/complaints/trace":
            body = parse_json_body(environ)
            err = require_fields(body, "egress_ip", "observed_at")
            if err:
                return err
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
            auto_action = body.get("auto_action", None)
            if auto_action == "ban":
                self.control.ban_user(hit.user_id)
            elif auto_action == "quarantine":
                self.control.quarantine_user(hit.user_id)
            return to_json(
                {
                    "ok": True,
                    "session_id": hit.session_id,
                    "user_id": hit.user_id,
                    "node_id": hit.node_id,
                    "auto_action": auto_action,
                }
            )

        # ── admin (requires X-Admin-Key) ─────────────────────
        ban_match = re.match(r"^/v1/admin/users/([^/]+)/ban$", path)
        if method == "POST" and ban_match:
            err = self._require_admin(environ)
            if err:
                return err
            user_id = ban_match.group(1)
            data = self.control.ban_user(user_id)
            return to_json(data, status_code=200 if data.get("ok") else 404)

        unban_match = re.match(r"^/v1/admin/users/([^/]+)/unban$", path)
        if method == "POST" and unban_match:
            err = self._require_admin(environ)
            if err:
                return err
            user_id = unban_match.group(1)
            data = self.control.unban_user(user_id)
            return to_json(data, status_code=200 if data.get("ok") else 404)

        policy_match = re.match(r"^/v1/admin/users/([^/]+)/policy$", path)
        if method == "POST" and policy_match:
            err = self._require_admin(environ)
            if err:
                return err
            user_id = policy_match.group(1)
            body = parse_json_body(environ)
            data = self.control.push_policy(user_id, body)
            return to_json(data)

        if method == "GET" and path == "/v1/admin/users":
            err = self._require_admin(environ)
            if err:
                return err
            return to_json(self.control.list_users())

        return to_json({"ok": False, "message": "not_found"}, 404)


def run_server(host: str = "0.0.0.0", port: int = 8080) -> None:
    app = ApiApplication()
    with make_server(host, port, app) as server:
        print(f"[control-plane] serving on http://{host}:{port}")
        server.serve_forever()


if __name__ == "__main__":
    run_server()
