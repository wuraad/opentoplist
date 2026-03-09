"""Tests for P0 features: JWT, cache, gateway agent, new endpoints."""
from __future__ import annotations

import json
import time
import unittest
from datetime import timedelta
from io import BytesIO
from typing import Optional

from backend.app.api_server import ApiApplication
from backend.app.cache import MemoryCache, TokenCache
from backend.app.gateway_agent import GatewayAgent, WgNodeConfig, NodeScheduler
from backend.app.jwt_auth import create_jwt, verify_jwt, decode_jwt_unsafe
from backend.app.store import InMemoryStore


class WSGIClient:
    def __init__(self, app) -> None:
        self.app = app
        self.token: Optional[str] = None

    def request(self, method, path, body=None, headers=None):
        data = json.dumps(body or {}).encode("utf-8")
        environ = {
            "REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": "",
            "CONTENT_TYPE": "application/json", "CONTENT_LENGTH": str(len(data)),
            "wsgi.input": BytesIO(data), "SERVER_NAME": "localhost", "SERVER_PORT": "8080",
        }
        if "?" in path:
            environ["PATH_INFO"], environ["QUERY_STRING"] = path.split("?", 1)
        hdrs = headers or {}
        if self.token and "HTTP_AUTHORIZATION" not in hdrs:
            hdrs["HTTP_AUTHORIZATION"] = f"Bearer {self.token}"
        environ.update(hdrs)
        status_holder = []
        def sr(status, headers):
            status_holder.append(status)
        result = self.app(environ, sr)
        body_bytes = b"".join(result)
        code = int(status_holder[0].split(" ")[0])
        return code, json.loads(body_bytes)

    def get(self, path, **kw): return self.request("GET", path, **kw)
    def post(self, path, body=None, **kw): return self.request("POST", path, body=body, **kw)


# ── JWT Tests ─────────────────────────────────────────────────

class JWTTests(unittest.TestCase):
    def test_create_and_verify(self):
        token = create_jwt("user1", plan="pro", secret="test-secret")
        payload = verify_jwt(token, secret="test-secret")
        self.assertIsNotNone(payload)
        self.assertEqual(payload["sub"], "user1")
        self.assertEqual(payload["plan"], "pro")

    def test_expired_token(self):
        token = create_jwt("user1", ttl=timedelta(seconds=-1), secret="test-secret")
        self.assertIsNone(verify_jwt(token, secret="test-secret"))

    def test_wrong_secret(self):
        token = create_jwt("user1", secret="real-secret")
        self.assertIsNone(verify_jwt(token, secret="wrong-secret"))

    def test_tampered_token(self):
        token = create_jwt("user1", secret="secret")
        parts = token.split(".")
        parts[1] = parts[1] + "x"
        self.assertIsNone(verify_jwt(".".join(parts), secret="secret"))

    def test_decode_unsafe(self):
        token = create_jwt("user1", secret="secret")
        payload = decode_jwt_unsafe(token)
        self.assertEqual(payload["sub"], "user1")

    def test_invalid_format(self):
        self.assertIsNone(verify_jwt("not.a.valid.jwt", secret="s"))
        self.assertIsNone(verify_jwt("", secret="s"))


# ── Cache Tests ───────────────────────────────────────────────

class MemoryCacheTests(unittest.TestCase):
    def test_set_get(self):
        c = MemoryCache()
        c.set("k1", "v1")
        self.assertEqual(c.get("k1"), "v1")

    def test_ttl_expiry(self):
        c = MemoryCache()
        c.set("k1", "v1", ttl_seconds=0)
        time.sleep(0.01)
        self.assertEqual(c.get("k1"), "v1")

    def test_delete(self):
        c = MemoryCache()
        c.set("k1", "v1")
        self.assertTrue(c.delete("k1"))
        self.assertIsNone(c.get("k1"))

    def test_delete_pattern(self):
        c = MemoryCache()
        c.set("tok:a", "1")
        c.set("tok:b", "2")
        c.set("sess:c", "3")
        self.assertEqual(c.delete_pattern("tok:"), 2)
        self.assertIsNone(c.get("tok:a"))
        self.assertEqual(c.get("sess:c"), "3")


class TokenCacheTests(unittest.TestCase):
    def test_cache_and_get_token(self):
        tc = TokenCache(MemoryCache())
        tc.cache_token("abc", "user1", ttl=60)
        self.assertEqual(tc.get_user_for_token("abc"), "user1")

    def test_invalidate_token(self):
        tc = TokenCache(MemoryCache())
        tc.cache_token("abc", "user1")
        tc.invalidate_token("abc")
        self.assertIsNone(tc.get_user_for_token("abc"))

    def test_session_cache(self):
        tc = TokenCache(MemoryCache())
        tc.cache_session("s1", '{"user":"u1"}', ttl=60)
        self.assertEqual(tc.get_session("s1"), '{"user":"u1"}')


# ── Gateway Agent Tests ───────────────────────────────────────

class GatewayAgentTests(unittest.TestCase):
    def setUp(self):
        self.gw = GatewayAgent()
        self.gw.register_node(WgNodeConfig(
            node_id="sg-1", region="sg", endpoint="sg-1.vpn.test",
            public_key="server-pubkey-sg1",
        ))

    def test_register_node(self):
        result = self.gw.register_node(WgNodeConfig(
            node_id="jp-1", region="jp", endpoint="jp-1.vpn.test",
            public_key="server-pubkey-jp1",
        ))
        self.assertTrue(result["ok"])

    def test_allocate_peer(self):
        result = self.gw.allocate_peer("user1", "phone-1", "sg-1", "client-pubkey")
        self.assertIsNotNone(result)
        self.assertTrue(result["ok"])
        self.assertIn("interface", result)
        self.assertIn("peer", result)
        self.assertEqual(result["peer"]["public_key"], "server-pubkey-sg1")

    def test_duplicate_allocation(self):
        r1 = self.gw.allocate_peer("user1", "phone-1", "sg-1", "client-pubkey")
        r2 = self.gw.allocate_peer("user1", "phone-1", "sg-1", "client-pubkey")
        self.assertEqual(r1["interface"]["address"], r2["interface"]["address"])

    def test_revoke_peer(self):
        self.gw.allocate_peer("user1", "phone-1", "sg-1", "client-pubkey")
        self.assertTrue(self.gw.revoke_peer("user1", "phone-1", "sg-1"))
        self.assertFalse(self.gw.revoke_peer("user1", "phone-1", "sg-1"))

    def test_list_user_peers(self):
        self.gw.allocate_peer("user1", "d1", "sg-1", "k1")
        peers = self.gw.list_user_peers("user1")
        self.assertEqual(len(peers), 1)
        self.assertEqual(peers[0]["device_id"], "d1")

    def test_revoke_all_user(self):
        self.gw.allocate_peer("user1", "d1", "sg-1", "k1")
        self.gw.allocate_peer("user1", "d2", "sg-1", "k2")
        count = self.gw.revoke_all_user_peers("user1")
        self.assertEqual(count, 2)

    def test_bandwidth_limit(self):
        result = self.gw.apply_bandwidth_limit("sg-1", "10.66.0.2", 50, 500)
        self.assertTrue(result["ok"])
        self.assertIn("command", result)

    def test_unknown_node(self):
        result = self.gw.allocate_peer("u1", "d1", "nonexistent", "key")
        self.assertIsNone(result)


class NodeSchedulerTests(unittest.TestCase):
    def test_mark_stale(self):
        store = InMemoryStore()
        gw = GatewayAgent()
        scheduler = NodeScheduler(store, gw)
        count = scheduler.mark_stale_nodes(threshold_minutes=0)
        self.assertEqual(count, 3)

    def test_probe_health(self):
        store = InMemoryStore()
        gw = GatewayAgent()
        scheduler = NodeScheduler(store, gw)
        result = scheduler.probe_node_health("sg-1")
        self.assertTrue(result["ok"])
        self.assertIn("load_ratio", result)


# ── New API Endpoint Tests ────────────────────────────────────

class GatewayAPITests(unittest.TestCase):
    def setUp(self):
        self.app = ApiApplication()
        self.client = WSGIClient(self.app)
        self.admin_headers = {"HTTP_X_ADMIN_KEY": "admin-secret-key"}
        _, login = self.client.post(
            "/v1/auth/token",
            {"user_id": "demo", "password": "demo1234", "device_id": "d0"},
        )
        self.client.token = login["token"]

    def test_register_gateway_node(self):
        code, data = self.client.post(
            "/v1/gateway/nodes/register",
            {"node_id": "test-gw-1", "region": "eu", "endpoint": "eu.vpn.test", "public_key": "pk1"},
            headers=self.admin_headers,
        )
        self.assertEqual(code, 200)
        self.assertTrue(data["ok"])

    def test_allocate_and_list_peers(self):
        self.client.post(
            "/v1/gateway/nodes/register",
            {"node_id": "sg-gw", "region": "sg", "endpoint": "sg.vpn.test", "public_key": "pk"},
            headers=self.admin_headers,
        )
        code, data = self.client.post(
            "/v1/gateway/peers/allocate",
            {"node_id": "sg-gw", "client_public_key": "my-key"},
        )
        self.assertEqual(code, 200)
        self.assertIn("interface", data)

        code, data = self.client.get("/v1/gateway/peers")
        self.assertEqual(code, 200)
        self.assertEqual(len(data["peers"]), 1)

    def test_revoke_peer(self):
        self.client.post(
            "/v1/gateway/nodes/register",
            {"node_id": "sg-gw2", "region": "sg", "endpoint": "sg2.vpn.test", "public_key": "pk"},
            headers=self.admin_headers,
        )
        self.client.post(
            "/v1/gateway/peers/allocate",
            {"node_id": "sg-gw2", "client_public_key": "k"},
        )
        code, data = self.client.post(
            "/v1/gateway/peers/revoke", {"node_id": "sg-gw2"}
        )
        self.assertEqual(code, 200)
        self.assertTrue(data["ok"])


class SessionEndTests(unittest.TestCase):
    def setUp(self):
        self.app = ApiApplication()
        self.client = WSGIClient(self.app)
        _, login = self.client.post(
            "/v1/auth/token",
            {"user_id": "demo", "password": "demo1234", "device_id": "d0"},
        )
        self.client.token = login["token"]

    def test_end_session(self):
        _, session = self.client.post(
            "/v1/sessions/register",
            {"node_id": "sg-1", "egress_ip": "1.2.3.4"},
        )
        session_id = session["session_id"]
        code, data = self.client.post("/v1/sessions/end", {"session_id": session_id})
        self.assertEqual(code, 200)
        self.assertTrue(data["ok"])

    def test_end_nonexistent_session(self):
        code, data = self.client.post("/v1/sessions/end", {"session_id": "ghost"})
        self.assertEqual(code, 404)


class PasswordChangeTests(unittest.TestCase):
    def setUp(self):
        self.app = ApiApplication()
        self.client = WSGIClient(self.app)
        _, login = self.client.post(
            "/v1/auth/token",
            {"user_id": "demo", "password": "demo1234", "device_id": "d0"},
        )
        self.client.token = login["token"]

    def test_change_password(self):
        code, data = self.client.post(
            "/v1/auth/change-password",
            {"old_password": "demo1234", "new_password": "newpass999"},
        )
        self.assertEqual(code, 200)
        self.assertTrue(data["ok"])

        self.client.token = None
        code, data = self.client.post(
            "/v1/auth/token",
            {"user_id": "demo", "password": "newpass999", "device_id": "d0"},
        )
        self.assertTrue(data["ok"])

    def test_change_password_wrong_old(self):
        code, data = self.client.post(
            "/v1/auth/change-password",
            {"old_password": "wrong", "new_password": "newpass"},
        )
        self.assertEqual(code, 401)


if __name__ == "__main__":
    unittest.main()
