import unittest

from backend.app.control_plane import ControlPlaneService
from backend.app.models import UserStatus
from backend.app.store import InMemoryStore


class ControlPlaneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryStore()
        self.control = ControlPlaneService(self.store)

    def test_login_success(self) -> None:
        result = self.control.login("demo", "demo1234", "android-1")
        self.assertTrue(result["ok"])
        self.assertIn("token", result)

    def test_device_binding_limit(self) -> None:
        self.control.bind_device("demo", "d1", "one")
        self.control.bind_device("demo", "d2", "two")
        self.control.bind_device("demo", "d3", "three")
        result = self.control.bind_device("demo", "d4", "four")
        self.assertFalse(result["ok"])
        self.assertEqual(result["message"], "device_limit_exceeded")

    def test_route_node(self) -> None:
        result = self.control.route_node("demo", "sg")
        self.assertTrue(result["ok"])
        self.assertEqual(result["node"]["region"], "sg")

    def test_banned_user_cannot_route(self) -> None:
        self.store.update_user_status("demo", UserStatus.BANNED)
        result = self.control.route_node("demo", "sg")
        self.assertFalse(result["ok"])
        self.assertEqual(result["message"], "user_banned")


if __name__ == "__main__":
    unittest.main()
