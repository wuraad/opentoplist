"""
End-to-end API tests running against the WSGI application directly.
Uses wsgiref validation and a test client approach without network.
"""
from __future__ import annotations

import json
import unittest
from io import BytesIO
from typing import Optional

from backend.app.api_server import ApiApplication


class WSGIClient:
    """Minimal WSGI test client that invokes the app in-process."""

    def __init__(self, app: ApiApplication) -> None:
        self.app = app
        self.token: Optional[str] = None

    def request(
        self,
        method: str,
        path: str,
        body: Optional[dict] = None,
        headers: Optional[dict] = None,
    ) -> tuple[int, dict]:
        data = json.dumps(body or {}).encode("utf-8")
        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "QUERY_STRING": "",
            "CONTENT_TYPE": "application/json",
            "CONTENT_LENGTH": str(len(data)),
            "wsgi.input": BytesIO(data),
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "8080",
        }
        if "?" in path:
            environ["PATH_INFO"], environ["QUERY_STRING"] = path.split("?", 1)

        hdrs = headers or {}
        if self.token and "HTTP_AUTHORIZATION" not in hdrs:
            hdrs["HTTP_AUTHORIZATION"] = f"Bearer {self.token}"
        environ.update(hdrs)

        status_holder: list[str] = []

        def start_response(status: str, response_headers: list) -> None:
            status_holder.append(status)

        result = self.app(environ, start_response)
        body_bytes = b"".join(result)
        status_code = int(status_holder[0].split(" ")[0])
        return status_code, json.loads(body_bytes)

    def get(self, path: str, **kw) -> tuple[int, dict]:
        return self.request("GET", path, **kw)

    def post(self, path: str, body: Optional[dict] = None, **kw) -> tuple[int, dict]:
        return self.request("POST", path, body=body, **kw)

    def delete(self, path: str, **kw) -> tuple[int, dict]:
        return self.request("DELETE", path, **kw)


class E2EHealthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = WSGIClient(ApiApplication())

    def test_healthz(self) -> None:
        code, data = self.client.get("/healthz")
        self.assertEqual(code, 200)
        self.assertTrue(data["ok"])

    def test_not_found(self) -> None:
        code, data = self.client.get("/nonexistent")
        self.assertEqual(code, 404)


class E2EAuthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = WSGIClient(ApiApplication())

    def test_register_and_login(self) -> None:
        code, data = self.client.post(
            "/v1/auth/register",
            {"user_id": "e2e_user", "password": "secure123"},
        )
        self.assertEqual(code, 201)
        self.assertTrue(data["ok"])

        code, data = self.client.post(
            "/v1/auth/token",
            {"user_id": "e2e_user", "password": "secure123", "device_id": "d1"},
        )
        self.assertEqual(code, 200)
        self.assertIn("token", data)

    def test_login_wrong_password(self) -> None:
        code, data = self.client.post(
            "/v1/auth/token",
            {"user_id": "demo", "password": "wrong", "device_id": "d1"},
        )
        self.assertEqual(code, 401)
        self.assertEqual(data["message"], "invalid_credentials")

    def test_login_missing_fields(self) -> None:
        code, data = self.client.post("/v1/auth/token", {"user_id": "demo"})
        self.assertEqual(code, 400)
        self.assertEqual(data["message"], "missing_fields")

    def test_logout(self) -> None:
        _, login = self.client.post(
            "/v1/auth/token",
            {"user_id": "demo", "password": "demo1234", "device_id": "d1"},
        )
        self.client.token = login["token"]

        code, data = self.client.post("/v1/auth/logout")
        self.assertEqual(code, 200)
        self.assertTrue(data["ok"])

        code, data = self.client.get("/v1/nodes/route?region=sg")
        self.assertEqual(code, 401)


class E2EDeviceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = WSGIClient(ApiApplication())
        _, login = self.client.post(
            "/v1/auth/token",
            {"user_id": "demo", "password": "demo1234", "device_id": "d0"},
        )
        self.client.token = login["token"]

    def test_bind_and_list(self) -> None:
        code, data = self.client.post(
            "/v1/devices/bind", {"device_id": "d1", "device_label": "Phone"}
        )
        self.assertEqual(code, 200)

        code, data = self.client.get("/v1/devices")
        self.assertEqual(code, 200)
        device_ids = [d["device_id"] for d in data["devices"]]
        self.assertIn("d1", device_ids)

    def test_unbind(self) -> None:
        self.client.post("/v1/devices/bind", {"device_id": "dx"})
        code, data = self.client.delete("/v1/devices/dx")
        self.assertEqual(code, 200)
        self.assertTrue(data["ok"])

    def test_bind_requires_auth(self) -> None:
        client = WSGIClient(ApiApplication())
        code, data = client.post("/v1/devices/bind", {"device_id": "d1"})
        self.assertEqual(code, 401)


class E2ENodeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = WSGIClient(ApiApplication())
        _, login = self.client.post(
            "/v1/auth/token",
            {"user_id": "demo", "password": "demo1234", "device_id": "d0"},
        )
        self.client.token = login["token"]

    def test_list_nodes_public(self) -> None:
        client = WSGIClient(ApiApplication())
        code, data = client.get("/v1/nodes")
        self.assertEqual(code, 200)
        self.assertEqual(len(data["nodes"]), 3)

    def test_route_requires_auth(self) -> None:
        client = WSGIClient(ApiApplication())
        code, data = client.get("/v1/nodes/route?region=sg")
        self.assertEqual(code, 401)

    def test_route_with_auth(self) -> None:
        code, data = self.client.get("/v1/nodes/route?region=sg")
        self.assertEqual(code, 200)
        self.assertEqual(data["node"]["region"], "sg")

    def test_heartbeat(self) -> None:
        code, data = self.client.post(
            "/v1/nodes/heartbeat",
            {
                "node_id": "e2e-1",
                "region": "eu",
                "endpoint": "e2e-1.vpn:51820",
                "capacity": 400,
            },
        )
        self.assertEqual(code, 200)


class E2EAdminTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = ApiApplication()
        self.client = WSGIClient(self.app)
        self.admin_headers = {"HTTP_X_ADMIN_KEY": "admin-secret-key"}

    def test_admin_ban_requires_key(self) -> None:
        code, data = self.client.post("/v1/admin/users/demo/ban")
        self.assertEqual(code, 403)

    def test_admin_ban_and_unban(self) -> None:
        code, data = self.client.post(
            "/v1/admin/users/demo/ban", headers=self.admin_headers
        )
        self.assertEqual(code, 200)
        self.assertTrue(data["ok"])

        code, data = self.client.post(
            "/v1/admin/users/demo/unban", headers=self.admin_headers
        )
        self.assertEqual(code, 200)
        self.assertTrue(data["ok"])

    def test_admin_list_users(self) -> None:
        code, data = self.client.get(
            "/v1/admin/users", headers=self.admin_headers
        )
        self.assertEqual(code, 200)
        self.assertGreaterEqual(len(data["users"]), 1)

    def test_admin_push_policy(self) -> None:
        code, data = self.client.post(
            "/v1/admin/users/demo/policy",
            {"throttle": True, "bandwidth_limit_mbps": 50},
            headers=self.admin_headers,
        )
        self.assertEqual(code, 200)


class E2ERiskTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = WSGIClient(ApiApplication())

    def test_risk_low(self) -> None:
        code, data = self.client.post(
            "/v1/risk/evaluate",
            {
                "user_id": "demo",
                "session_id": "s1",
                "connection_count": 50,
                "unique_dst_ports": 5,
                "burst_bandwidth_mbps": 20,
            },
        )
        self.assertEqual(code, 200)
        self.assertEqual(data["risk"]["action"], "allow")

    def test_risk_ban_triggers_user_ban(self) -> None:
        code, data = self.client.post(
            "/v1/risk/evaluate",
            {
                "user_id": "demo",
                "session_id": "s2",
                "connection_count": 2000,
                "unique_dst_ports": 240,
                "burst_bandwidth_mbps": 600,
            },
        )
        self.assertEqual(code, 200)
        self.assertEqual(data["risk"]["action"], "ban")

        _, login = self.client.post(
            "/v1/auth/token",
            {"user_id": "demo", "password": "demo1234", "device_id": "d1"},
        )
        self.assertFalse(login["ok"])

    def test_risk_throttle_sets_policy(self) -> None:
        code, data = self.client.post(
            "/v1/risk/evaluate",
            {
                "user_id": "demo",
                "session_id": "s3",
                "connection_count": 700,
                "unique_dst_ports": 65,
                "burst_bandwidth_mbps": 120,
            },
        )
        self.assertEqual(data["risk"]["action"], "throttle")
        policy = self.client.app.store.get_user_policy("demo")
        self.assertIsNotNone(policy)
        self.assertTrue(policy["throttle"])

    def test_risk_missing_fields(self) -> None:
        code, data = self.client.post(
            "/v1/risk/evaluate", {"user_id": "demo"}
        )
        self.assertEqual(code, 400)


class E2EComplaintTraceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = ApiApplication()
        self.client = WSGIClient(self.app)
        _, login = self.client.post(
            "/v1/auth/token",
            {"user_id": "demo", "password": "demo1234", "device_id": "d0"},
        )
        self.client.token = login["token"]

    def test_trace_hit(self) -> None:
        self.client.post(
            "/v1/sessions/register",
            {"node_id": "sg-1", "egress_ip": "203.0.113.50"},
        )
        self.client.token = None
        code, data = self.client.post(
            "/v1/complaints/trace",
            {
                "egress_ip": "203.0.113.50",
                "observed_at": "2026-03-09T12:30:00+00:00",
                "window_minutes": 60,
            },
        )
        self.assertEqual(code, 200)
        self.assertEqual(data["user_id"], "demo")

    def test_trace_miss(self) -> None:
        code, data = self.client.post(
            "/v1/complaints/trace",
            {
                "egress_ip": "10.0.0.1",
                "observed_at": "2020-01-01T00:00:00+00:00",
            },
        )
        self.assertEqual(code, 404)

    def test_trace_auto_ban(self) -> None:
        _, login = self.client.post(
            "/v1/auth/token",
            {"user_id": "demo", "password": "demo1234", "device_id": "d0"},
        )
        self.client.token = login["token"]

        self.client.post(
            "/v1/sessions/register",
            {"node_id": "sg-1", "egress_ip": "198.51.100.1"},
        )
        self.client.token = None

        code, data = self.client.post(
            "/v1/complaints/trace",
            {
                "egress_ip": "198.51.100.1",
                "observed_at": "2026-03-09T12:30:00+00:00",
                "window_minutes": 60,
                "auto_action": "ban",
            },
        )
        self.assertEqual(code, 200)
        self.assertEqual(data["auto_action"], "ban")
        self.assertEqual(
            self.app.store.users["demo"].status.value, "banned"
        )


class E2EFullFlowTests(unittest.TestCase):
    """Full user journey: register → login → route → session → risk."""

    def test_new_user_journey(self) -> None:
        client = WSGIClient(ApiApplication())

        _, reg = client.post(
            "/v1/auth/register",
            {"user_id": "journey_user", "password": "pass123", "plan": "pro"},
        )
        self.assertTrue(reg["ok"])

        _, login = client.post(
            "/v1/auth/token",
            {"user_id": "journey_user", "password": "pass123", "device_id": "phone-1"},
        )
        self.assertTrue(login["ok"])
        client.token = login["token"]

        _, route = client.get("/v1/nodes/route?region=sg")
        self.assertTrue(route["ok"])
        node_id = route["node"]["node_id"]

        _, session = client.post(
            "/v1/sessions/register",
            {"node_id": node_id, "egress_ip": "192.0.2.1"},
        )
        self.assertIn("session_id", session)

        _, policy = client.get("/v1/users/me/policy")
        self.assertFalse(policy["ok"])

        client.token = None
        _, risk = client.post(
            "/v1/risk/evaluate",
            {
                "user_id": "journey_user",
                "session_id": session["session_id"],
                "connection_count": 50,
                "unique_dst_ports": 5,
                "burst_bandwidth_mbps": 10,
            },
        )
        self.assertEqual(risk["risk"]["action"], "allow")


if __name__ == "__main__":
    unittest.main()
