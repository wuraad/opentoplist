import unittest

from backend.app.control_plane import ControlPlaneService
from backend.app.models import UserStatus
from backend.app.store import InMemoryStore


class ControlPlaneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryStore()
        self.control = ControlPlaneService(self.store)

    # ── auth ──────────────────────────────────────────────────

    def test_login_success(self) -> None:
        result = self.control.login("demo", "demo1234", "android-1")
        self.assertTrue(result["ok"])
        self.assertIn("token", result)

    def test_login_wrong_password(self) -> None:
        result = self.control.login("demo", "wrong", "android-1")
        self.assertFalse(result["ok"])
        self.assertEqual(result["message"], "invalid_credentials")

    def test_login_banned_user(self) -> None:
        self.store.update_user_status("demo", UserStatus.BANNED)
        result = self.control.login("demo", "demo1234", "android-1")
        self.assertFalse(result["ok"])

    def test_login_nonexistent_user(self) -> None:
        result = self.control.login("ghost", "pass", "d1")
        self.assertFalse(result["ok"])

    def test_register_new_user(self) -> None:
        result = self.control.register("newuser", "pass123")
        self.assertTrue(result["ok"])
        self.assertEqual(result["user_id"], "newuser")

    def test_register_duplicate_user(self) -> None:
        self.control.register("u1", "pass")
        result = self.control.register("u1", "pass2")
        self.assertFalse(result["ok"])
        self.assertEqual(result["message"], "user_already_exists")

    def test_logout(self) -> None:
        login = self.control.login("demo", "demo1234", "d1")
        token = login["token"]
        self.assertIsNotNone(self.store.validate_token(token))
        result = self.control.logout(token)
        self.assertTrue(result["ok"])
        self.assertIsNone(self.store.validate_token(token))

    # ── tokens ────────────────────────────────────────────────

    def test_token_validation(self) -> None:
        token = self.store.issue_token("demo")
        self.assertEqual(self.store.validate_token(token), "demo")

    def test_token_revocation(self) -> None:
        token = self.store.issue_token("demo")
        self.store.revoke_token(token)
        self.assertIsNone(self.store.validate_token(token))

    def test_banned_user_token_invalid(self) -> None:
        token = self.store.issue_token("demo")
        self.store.update_user_status("demo", UserStatus.BANNED)
        self.assertIsNone(self.store.validate_token(token))

    def test_ban_revokes_all_tokens(self) -> None:
        t1 = self.store.issue_token("demo")
        t2 = self.store.issue_token("demo")
        self.store.update_user_status("demo", UserStatus.BANNED)
        self.assertIsNone(self.store.validate_token(t1))
        self.assertIsNone(self.store.validate_token(t2))

    # ── devices ───────────────────────────────────────────────

    def test_device_binding_limit(self) -> None:
        self.control.bind_device("demo", "d1", "one")
        self.control.bind_device("demo", "d2", "two")
        self.control.bind_device("demo", "d3", "three")
        result = self.control.bind_device("demo", "d4", "four")
        self.assertFalse(result["ok"])
        self.assertEqual(result["message"], "device_limit_exceeded")

    def test_device_duplicate_bind(self) -> None:
        self.control.bind_device("demo", "d1", "one")
        result = self.control.bind_device("demo", "d1", "one-again")
        self.assertTrue(result["ok"])
        self.assertEqual(result["message"], "device_already_bound")

    def test_list_devices(self) -> None:
        self.control.bind_device("demo", "d1", "phone")
        self.control.bind_device("demo", "d2", "tablet")
        result = self.control.list_devices("demo")
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["devices"]), 2)

    def test_unbind_device(self) -> None:
        self.control.bind_device("demo", "d1", "phone")
        result = self.control.unbind_device("demo", "d1")
        self.assertTrue(result["ok"])
        devices = self.control.list_devices("demo")
        self.assertEqual(len(devices["devices"]), 0)

    def test_unbind_nonexistent_device(self) -> None:
        result = self.control.unbind_device("demo", "ghost")
        self.assertFalse(result["ok"])

    # ── nodes ─────────────────────────────────────────────────

    def test_route_node(self) -> None:
        result = self.control.route_node("demo", "sg")
        self.assertTrue(result["ok"])
        self.assertEqual(result["node"]["region"], "sg")

    def test_route_no_healthy_nodes(self) -> None:
        for n in self.store.node_status.values():
            n.healthy = False
        result = self.control.route_node("demo")
        self.assertFalse(result["ok"])
        self.assertEqual(result["message"], "no_healthy_nodes")

    def test_banned_user_cannot_route(self) -> None:
        self.store.update_user_status("demo", UserStatus.BANNED)
        result = self.control.route_node("demo", "sg")
        self.assertFalse(result["ok"])
        self.assertEqual(result["message"], "user_banned")

    def test_quarantined_user_cannot_route(self) -> None:
        self.store.update_user_status("demo", UserStatus.QUARANTINED)
        result = self.control.route_node("demo")
        self.assertFalse(result["ok"])
        self.assertEqual(result["message"], "user_quarantined")

    def test_list_nodes(self) -> None:
        result = self.control.list_nodes()
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["nodes"]), 3)

    def test_list_nodes_by_region(self) -> None:
        result = self.control.list_nodes(region="sg")
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["nodes"]), 1)

    def test_node_heartbeat(self) -> None:
        payload = {
            "node_id": "test-1",
            "region": "eu",
            "endpoint": "test-1.vpn.internal:51820",
            "capacity": 400,
            "current_load": 50,
        }
        result = self.control.report_node_heartbeat(payload)
        self.assertTrue(result["ok"])
        self.assertIn("test-1", self.store.node_status)

    # ── admin ─────────────────────────────────────────────────

    def test_ban_user(self) -> None:
        result = self.control.ban_user("demo")
        self.assertTrue(result["ok"])
        self.assertEqual(self.store.users["demo"].status, UserStatus.BANNED)

    def test_unban_user(self) -> None:
        self.control.ban_user("demo")
        result = self.control.unban_user("demo")
        self.assertTrue(result["ok"])
        self.assertEqual(self.store.users["demo"].status, UserStatus.ACTIVE)

    def test_push_and_get_policy(self) -> None:
        policy = {"bandwidth_limit_mbps": 50, "throttle": True}
        self.control.push_policy("demo", policy)
        result = self.control.get_policy("demo")
        self.assertTrue(result["ok"])
        self.assertEqual(result["policy"]["bandwidth_limit_mbps"], 50)

    def test_get_policy_not_set(self) -> None:
        result = self.control.get_policy("demo")
        self.assertFalse(result["ok"])

    def test_list_users(self) -> None:
        result = self.control.list_users()
        self.assertTrue(result["ok"])
        self.assertGreaterEqual(len(result["users"]), 1)

    def test_quarantine_user(self) -> None:
        result = self.control.quarantine_user("demo")
        self.assertTrue(result["ok"])
        self.assertEqual(self.store.users["demo"].status, UserStatus.QUARANTINED)

    # ── sessions ──────────────────────────────────────────────

    def test_register_session(self) -> None:
        data = self.control.register_session("demo", "sg-1", "1.2.3.4")
        self.assertIn("session_id", data)
        self.assertEqual(data["user_id"], "demo")


if __name__ == "__main__":
    unittest.main()
