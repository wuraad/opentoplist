from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Callable, Iterable, Optional
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server

from .alert import AlertManager
from .audit import AuditLogger
from .cache import MemoryCache, TokenCache
from .complaint_parser import parse_complaint_text
from .control_plane import ControlPlaneService
from .gateway_agent import GatewayAgent, WgNodeConfig
from .jwt_auth import create_jwt, verify_jwt
from .logging_config import setup_logging
from .metrics import MetricsRegistry
from .middleware import CORSMiddleware, RateLimitMiddleware, RequestLogMiddleware
from .models import AbuseComplaint, RiskSignal
from .risk import evaluate_risk, result_to_dict
from .store import InMemoryStore

JSON = tuple[str, list[tuple[str, str]], bytes]

logger = setup_logging(os.environ.get("LOG_LEVEL", "INFO"))


def parse_json_body(environ: dict) -> dict:
    content_length = int(environ.get("CONTENT_LENGTH", "0") or "0")
    body = environ["wsgi.input"].read(content_length) if content_length > 0 else b"{}"
    if not body:
        return {}
    return json.loads(body.decode("utf-8"))


def to_json(payload: dict, status_code: int = 200) -> JSON:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    status_map = {200: "200 OK", 201: "201 Created", 204: "204 No Content",
                  400: "400 Bad Request", 401: "401 Unauthorized",
                  403: "403 Forbidden", 404: "404 Not Found",
                  429: "429 Too Many Requests", 500: "500 Internal Server Error"}
    status_text = status_map.get(status_code, f"{status_code} ERROR")
    headers = [
        ("Content-Type", "application/json; charset=utf-8"),
        ("Content-Length", str(len(body))),
    ]
    return status_text, headers, body


def require_fields(body: dict, *fields: str) -> Optional[JSON]:
    missing = [f for f in fields if f not in body or body[f] is None]
    if missing:
        return to_json({"ok": False, "message": "missing_fields", "fields": missing}, 400)
    return None


class ApiApplication:
    def __init__(self, store: InMemoryStore | None = None) -> None:
        self.store = store or InMemoryStore()
        self.control = ControlPlaneService(self.store)
        self.audit = AuditLogger(self.store)
        self.alerts = AlertManager(webhook_url=os.environ.get("ALERT_WEBHOOK_URL"))
        self.metrics = MetricsRegistry()
        self._node_auth_key = os.environ.get("NODE_AUTH_KEY", "")
        self._jwt_secret = os.environ.get("JWT_SECRET", "change-me-in-production-use-a-64-char-random-string")
        self._use_jwt = os.environ.get("USE_JWT", "0") == "1"
        self._cache = TokenCache(MemoryCache())
        self.gateway = GatewayAgent()

    def __call__(
        self,
        environ: dict,
        start_response: Callable[[str, list[tuple[str, str]]], None],
    ) -> Iterable[bytes]:
        method = environ["REQUEST_METHOD"]
        path = environ["PATH_INFO"]
        t0 = time.monotonic()

        try:
            response = self.dispatch(method, path, environ)
        except json.JSONDecodeError:
            response = to_json({"ok": False, "message": "invalid_json"}, 400)
        except KeyError as exc:
            response = to_json({"ok": False, "message": "missing_field", "field": str(exc)}, 400)
        except (ValueError, TypeError) as exc:
            response = to_json({"ok": False, "message": str(exc)}, 400)
        except Exception as exc:  # pragma: no cover
            logger.exception("unhandled error")
            response = to_json({"ok": False, "error": str(exc)}, status_code=500)

        status, headers, body = response
        start_response(status, headers)

        status_code = status.split(" ")[0]
        elapsed = round((time.monotonic() - t0) * 1000, 2)
        self.metrics.http_requests.inc({"method": method, "path": path, "status": status_code})
        self.metrics.http_latency.observe(elapsed, {"method": method, "path": path})

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
        if self._use_jwt:
            payload = verify_jwt(token, self._jwt_secret)
            if payload:
                return payload.get("sub")
            return None
        cached = self._cache.get_user_for_token(token)
        if cached:
            return cached
        user_id = self.store.validate_token(token)
        if user_id:
            self._cache.cache_token(token, user_id, ttl=300)
        return user_id

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

    def _verify_node_auth(self, environ: dict) -> bool:
        if not self._node_auth_key:
            return True
        key = environ.get("HTTP_X_NODE_KEY", "")
        return key == self._node_auth_key

    @staticmethod
    def _query_params(environ: dict) -> dict[str, str]:
        qs = environ.get("QUERY_STRING", "")
        parsed = parse_qs(qs)
        return {k: v[0] for k, v in parsed.items()}

    # ── dispatch ──────────────────────────────────────────────

    def dispatch(self, method: str, path: str, environ: dict) -> JSON:
        if method == "GET" and path == "/healthz":
            return to_json({"ok": True, "service": "control-plane"})

        if method == "GET" and path == "/metrics":
            body = self.metrics.render().encode("utf-8")
            return "200 OK", [("Content-Type", "text/plain; charset=utf-8"), ("Content-Length", str(len(body)))], body

        # ── public auth ──────────────────────────────────────
        if method == "POST" and path == "/v1/auth/register":
            body = parse_json_body(environ)
            err = require_fields(body, "user_id", "password")
            if err:
                return err
            data = self.control.register(
                user_id=body["user_id"], password=body["password"],
                plan=body.get("plan", "free"),
            )
            if data.get("ok"):
                self.audit.log("user_register", user_id=body["user_id"])
            self.metrics.auth_attempts.inc({"result": "register_ok" if data.get("ok") else "register_fail"})
            return to_json(data, 201 if data.get("ok") else 400)

        if method == "POST" and path == "/v1/auth/token":
            body = parse_json_body(environ)
            err = require_fields(body, "user_id", "password", "device_id")
            if err:
                return err
            data = self.control.login(
                user_id=body["user_id"], password=body["password"],
                device_id=body["device_id"],
            )
            ok = data.get("ok")
            self.metrics.auth_attempts.inc({"result": "login_ok" if ok else "login_fail"})
            if ok:
                if self._use_jwt:
                    user = self.store.users.get(body["user_id"])
                    plan = user.plan if user else "free"
                    data["jwt"] = create_jwt(body["user_id"], plan=plan, secret=self._jwt_secret)
                self.audit.log("user_login", user_id=body["user_id"],
                               detail={"device_id": body["device_id"]})
            return to_json(data, status_code=200 if ok else 401)

        if method == "POST" and path == "/v1/auth/logout":
            token = self._bearer_token(environ)
            if not token:
                return to_json({"ok": False, "message": "unauthorized"}, 401)
            user_id = self.store.validate_token(token)
            data = self.control.logout(token)
            if user_id:
                self.audit.log("user_logout", user_id=user_id)
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
                user_id=user_id, device_id=body["device_id"],
                device_label=body.get("device_label", "unknown"),
            )
            if data.get("ok") and data.get("message") == "device_bound":
                self.audit.log("device_bind", user_id=user_id, detail={"device_id": body["device_id"]})
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
            if data.get("ok"):
                self.audit.log("device_unbind", user_id=user_id, detail={"device_id": device_id})
            return to_json(data, status_code=200 if data.get("ok") else 404)

        if method == "POST" and path == "/v1/nodes/heartbeat":
            if not self._verify_node_auth(environ):
                return to_json({"ok": False, "message": "node_unauthorized"}, 403)
            body = parse_json_body(environ)
            err = require_fields(body, "node_id", "region", "endpoint", "capacity")
            if err:
                return err
            data = self.control.report_node_heartbeat(body)
            self.metrics.node_health.set(
                1.0 if body.get("healthy", True) else 0.0,
                {"node_id": body["node_id"], "region": body["region"]},
            )
            return to_json(data)

        if method == "GET" and path == "/v1/nodes":
            params = self._query_params(environ)
            return to_json(self.control.list_nodes(region=params.get("region")))

        if method == "GET" and path == "/v1/nodes/route":
            user_id, err = self._require_auth(environ)
            if err:
                return err
            params = self._query_params(environ)
            data = self.control.route_node(user_id=user_id, region=params.get("region"))
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
            data = self.control.register_session(
                user_id=user_id, node_id=body["node_id"], egress_ip=body["egress_ip"],
            )
            self.metrics.active_sessions.inc()
            self.audit.log("session_register", user_id=user_id,
                           detail={"session_id": data.get("session_id"), "node_id": body["node_id"]})
            return to_json(data)

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
                user_id=body["user_id"], session_id=body["session_id"],
                connection_count=int(body["connection_count"]),
                unique_dst_ports=int(body["unique_dst_ports"]),
                burst_bandwidth_mbps=float(body["burst_bandwidth_mbps"]),
            )
            result = evaluate_risk(signal)
            payload = result_to_dict(result)
            self.metrics.risk_evaluations.inc({"action": result.action.value})

            if result.action.value == "ban":
                self.control.ban_user(signal.user_id)
                self.audit.log("risk_ban", user_id=signal.user_id, detail={"score": result.score})
            elif result.action.value == "quarantine":
                self.control.quarantine_user(signal.user_id)
                self.audit.log("risk_quarantine", user_id=signal.user_id, detail={"score": result.score})
            elif result.action.value == "throttle":
                self.store.set_user_policy(signal.user_id, {
                    "throttle": True, "bandwidth_limit_mbps": 50, "reason": "risk_throttle",
                })
                self.audit.log("risk_throttle", user_id=signal.user_id, detail={"score": result.score})

            self.alerts.evaluate_risk_action(signal.user_id, result.action.value, result.score)
            return to_json({"ok": True, "risk": payload})

        if method == "POST" and path == "/v1/complaints/trace":
            body = parse_json_body(environ)
            err = require_fields(body, "egress_ip", "observed_at")
            if err:
                return err
            complaint = AbuseComplaint(
                egress_ip=body["egress_ip"],
                observed_at=datetime.fromisoformat(body["observed_at"]).astimezone(timezone.utc),
                window_minutes=int(body.get("window_minutes", 15)),
            )
            hit = self.store.find_session_by_egress_ip_and_time(
                complaint.egress_ip, complaint.observed_at, complaint.window_minutes,
            )
            if not hit:
                return to_json({"ok": False, "message": "session_not_found"}, 404)
            auto_action = body.get("auto_action", None)
            if auto_action == "ban":
                self.control.ban_user(hit.user_id)
            elif auto_action == "quarantine":
                self.control.quarantine_user(hit.user_id)
            self.audit.log("complaint_trace", user_id=hit.user_id,
                           detail={"egress_ip": complaint.egress_ip, "auto_action": auto_action})
            return to_json({
                "ok": True, "session_id": hit.session_id,
                "user_id": hit.user_id, "node_id": hit.node_id,
                "auto_action": auto_action,
            })

        if method == "POST" and path == "/v1/complaints/parse":
            body = parse_json_body(environ)
            err = require_fields(body, "text")
            if err:
                return err
            parsed = parse_complaint_text(
                body["text"],
                source_email=body.get("source_email", ""),
                subject=body.get("subject", ""),
            )
            if not parsed:
                return to_json({"ok": False, "message": "no_ip_found"}, 400)
            return to_json({
                "ok": True,
                "egress_ip": parsed.egress_ip,
                "observed_at": parsed.observed_at.isoformat(),
                "source_email": parsed.source_email,
                "subject": parsed.subject,
            })

        # ── admin (requires X-Admin-Key) ─────────────────────
        ban_match = re.match(r"^/v1/admin/users/([^/]+)/ban$", path)
        if method == "POST" and ban_match:
            err = self._require_admin(environ)
            if err:
                return err
            user_id = ban_match.group(1)
            data = self.control.ban_user(user_id)
            if data.get("ok"):
                self.audit.log("admin_ban", user_id=user_id)
            return to_json(data, status_code=200 if data.get("ok") else 404)

        unban_match = re.match(r"^/v1/admin/users/([^/]+)/unban$", path)
        if method == "POST" and unban_match:
            err = self._require_admin(environ)
            if err:
                return err
            user_id = unban_match.group(1)
            data = self.control.unban_user(user_id)
            if data.get("ok"):
                self.audit.log("admin_unban", user_id=user_id)
            return to_json(data, status_code=200 if data.get("ok") else 404)

        policy_match = re.match(r"^/v1/admin/users/([^/]+)/policy$", path)
        if method == "POST" and policy_match:
            err = self._require_admin(environ)
            if err:
                return err
            user_id = policy_match.group(1)
            body = parse_json_body(environ)
            versions = self.store.get_policy_versions(user_id)
            next_ver = (versions[0]["version"] + 1) if versions else 1
            self.store.save_policy_version(user_id, body, next_ver)
            data = self.control.push_policy(user_id, body)
            self.audit.log("admin_push_policy", user_id=user_id,
                           detail={"version": next_ver})
            return to_json({**data, "version": next_ver})

        policy_ver_match = re.match(r"^/v1/admin/users/([^/]+)/policy/versions$", path)
        if method == "GET" and policy_ver_match:
            err = self._require_admin(environ)
            if err:
                return err
            user_id = policy_ver_match.group(1)
            versions = self.store.get_policy_versions(user_id)
            return to_json({"ok": True, "versions": versions})

        if method == "GET" and path == "/v1/admin/users":
            err = self._require_admin(environ)
            if err:
                return err
            return to_json(self.control.list_users())

        if method == "GET" and path == "/v1/admin/audit":
            err = self._require_admin(environ)
            if err:
                return err
            params = self._query_params(environ)
            logs = self.audit.query(
                user_id=params.get("user_id"),
                action=params.get("action"),
                limit=int(params.get("limit", "100")),
            )
            return to_json({"ok": True, "logs": logs})

        if method == "GET" and path == "/v1/admin/alerts":
            err = self._require_admin(environ)
            if err:
                return err
            params = self._query_params(environ)
            alerts = self.alerts.recent_alerts(limit=int(params.get("limit", "50")))
            return to_json({"ok": True, "alerts": alerts})

        if method == "POST" and path == "/v1/admin/alerts/evaluate-nodes":
            err = self._require_admin(environ)
            if err:
                return err
            nodes = [self.store.node_to_dict(n) for n in self.store.all_nodes()]
            events = self.alerts.evaluate_node_metrics(nodes)
            return to_json({
                "ok": True,
                "evaluated": len(nodes),
                "alerts_fired": len(events),
                "alerts": [{"rule": e.rule_name, "severity": e.severity, "message": e.message} for e in events],
            })

        # ── gateway management ────────────────────────────────
        if method == "POST" and path == "/v1/gateway/nodes/register":
            err = self._require_admin(environ)
            if err:
                return err
            body = parse_json_body(environ)
            err = require_fields(body, "node_id", "region", "endpoint", "public_key")
            if err:
                return err
            config = WgNodeConfig(
                node_id=body["node_id"], region=body["region"],
                endpoint=body["endpoint"], public_key=body["public_key"],
                subnet=body.get("subnet", "10.66.0.0/24"),
                listen_port=int(body.get("listen_port", 51820)),
            )
            data = self.gateway.register_node(config)
            self.audit.log("gateway_node_register", detail={"node_id": body["node_id"]})
            return to_json(data)

        if method == "POST" and path == "/v1/gateway/peers/allocate":
            user_id, err = self._require_auth(environ)
            if err:
                return err
            body = parse_json_body(environ)
            err = require_fields(body, "node_id", "client_public_key")
            if err:
                return err
            device_id = body.get("device_id", "default")
            result = self.gateway.allocate_peer(
                user_id=user_id, device_id=device_id,
                node_id=body["node_id"], client_public_key=body["client_public_key"],
            )
            if not result:
                return to_json({"ok": False, "message": "allocation_failed"}, 400)
            self.audit.log("peer_allocate", user_id=user_id,
                           detail={"node_id": body["node_id"]})
            return to_json(result)

        if method == "GET" and path == "/v1/gateway/peers":
            user_id, err = self._require_auth(environ)
            if err:
                return err
            peers = self.gateway.list_user_peers(user_id)
            return to_json({"ok": True, "peers": peers})

        if method == "POST" and path == "/v1/gateway/peers/revoke":
            user_id, err = self._require_auth(environ)
            if err:
                return err
            body = parse_json_body(environ)
            err = require_fields(body, "node_id")
            if err:
                return err
            device_id = body.get("device_id", "default")
            ok = self.gateway.revoke_peer(user_id, device_id, body["node_id"])
            return to_json({"ok": ok})

        # ── session end ──────────────────────────────────────
        if method == "POST" and path == "/v1/sessions/end":
            user_id, err = self._require_auth(environ)
            if err:
                return err
            body = parse_json_body(environ)
            err = require_fields(body, "session_id")
            if err:
                return err
            session = self.store.sessions.get(body["session_id"]) if hasattr(self.store, 'sessions') else None
            if session and session.user_id == user_id:
                session.ended_at = datetime.now(timezone.utc)
                self.metrics.active_sessions.inc(value=-1)
                self.audit.log("session_end", user_id=user_id,
                               detail={"session_id": body["session_id"]})
                return to_json({"ok": True})
            return to_json({"ok": False, "message": "session_not_found"}, 404)

        # ── password change ──────────────────────────────────
        if method == "POST" and path == "/v1/auth/change-password":
            user_id, err = self._require_auth(environ)
            if err:
                return err
            body = parse_json_body(environ)
            err = require_fields(body, "old_password", "new_password")
            if err:
                return err
            if not self.store.authenticate(user_id, body["old_password"]):
                return to_json({"ok": False, "message": "invalid_password"}, 401)
            from .store import hash_password as _hp
            user = self.store.users.get(user_id)
            if user:
                user.password_hash = _hp(body["new_password"])
                if hasattr(self.store, 'users') and isinstance(self.store.users, dict):
                    self.store.users[user_id] = user
            self.audit.log("password_change", user_id=user_id)
            return to_json({"ok": True})

        return to_json({"ok": False, "message": "not_found"}, 404)


def create_app(store=None) -> Callable:
    if store is None:
        from .server_config import create_store
        store = create_store()
    app: Callable = ApiApplication(store)
    log_fn = lambda entry: logger.info(
        f"{entry['method']} {entry['path']} {entry['status']} {entry['elapsed_ms']}ms"
    )
    app = RequestLogMiddleware(app, log_fn=log_fn)
    app = RateLimitMiddleware(app, requests_per_minute=600, burst=50)
    app = CORSMiddleware(app)
    return app


def run_server(host: str = "0.0.0.0", port: int = 8080) -> None:
    from .server_config import create_ssl_context
    app = create_app()
    with make_server(host, port, app) as server:
        ssl_ctx = create_ssl_context()
        if ssl_ctx:
            server.socket = ssl_ctx.wrap_socket(server.socket, server_side=True)
            proto = "https"
        else:
            proto = "http"
        logger.info(f"[control-plane] serving on {proto}://{host}:{port}")
        print(f"[control-plane] serving on {proto}://{host}:{port}")
        server.serve_forever()


if __name__ == "__main__":
    run_server()
