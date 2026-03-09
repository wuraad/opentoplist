"""Tests for new modules: audit, alert, complaint_parser, middleware, metrics, sqlite store."""
from __future__ import annotations

import unittest
from datetime import datetime, timezone

from backend.app.alert import AlertManager
from backend.app.audit import AuditLogger
from backend.app.complaint_parser import parse_complaint_text
from backend.app.metrics import Counter, Gauge, Histogram, MetricsRegistry
from backend.app.store import InMemoryStore


class AuditLoggerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryStore()
        self.audit = AuditLogger(self.store)

    def test_log_and_query(self) -> None:
        self.audit.log("test_action", user_id="demo", detail={"key": "val"})
        logs = self.audit.query()
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["action"], "test_action")

    def test_filter_by_user(self) -> None:
        self.audit.log("a", user_id="u1")
        self.audit.log("b", user_id="u2")
        logs = self.audit.query(user_id="u1")
        self.assertEqual(len(logs), 1)

    def test_filter_by_action(self) -> None:
        self.audit.log("login", user_id="u1")
        self.audit.log("logout", user_id="u1")
        logs = self.audit.query(action="login")
        self.assertEqual(len(logs), 1)

    def test_limit(self) -> None:
        for i in range(20):
            self.audit.log(f"action_{i}")
        logs = self.audit.query(limit=5)
        self.assertEqual(len(logs), 5)


class AlertManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mgr = AlertManager()

    def test_risk_ban_alert(self) -> None:
        evt = self.mgr.evaluate_risk_action("u1", "ban", 90)
        self.assertIsNotNone(evt)
        self.assertEqual(evt.severity, "critical")

    def test_risk_allow_no_alert(self) -> None:
        evt = self.mgr.evaluate_risk_action("u1", "allow", 10)
        self.assertIsNone(evt)

    def test_node_capacity_alert(self) -> None:
        nodes = [{"node_id": "n1", "current_load": 950, "capacity": 1000, "packet_loss_ratio": 0.0}]
        events = self.mgr.evaluate_node_metrics(nodes)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].rule_name, "node_capacity_high")

    def test_packet_loss_alert(self) -> None:
        nodes = [{"node_id": "n2", "current_load": 10, "capacity": 1000, "packet_loss_ratio": 0.12}]
        events = self.mgr.evaluate_node_metrics(nodes)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].severity, "critical")

    def test_recent_alerts(self) -> None:
        self.mgr.evaluate_risk_action("u1", "ban", 90)
        alerts = self.mgr.recent_alerts()
        self.assertEqual(len(alerts), 1)

    def test_callback(self) -> None:
        captured = []
        self.mgr.add_callback(lambda e: captured.append(e))
        self.mgr.evaluate_risk_action("u1", "quarantine", 60)
        self.assertEqual(len(captured), 1)


class ComplaintParserTests(unittest.TestCase):
    def test_basic_parse(self) -> None:
        text = "Abuse from 203.0.113.5 at 2026-03-09T12:00:00+00:00 please investigate"
        result = parse_complaint_text(text)
        self.assertIsNotNone(result)
        self.assertEqual(result.egress_ip, "203.0.113.5")

    def test_private_ip_skipped(self) -> None:
        result = parse_complaint_text("Internal issue at 192.168.1.1")
        self.assertIsNone(result)

    def test_no_ip(self) -> None:
        result = parse_complaint_text("Just a complaint with no IP")
        self.assertIsNone(result)

    def test_multiple_ips_first_public(self) -> None:
        text = "From 10.0.0.1 and 198.51.100.5 at 2026-01-01T00:00:00Z"
        result = parse_complaint_text(text)
        self.assertIsNotNone(result)
        self.assertEqual(result.egress_ip, "198.51.100.5")

    def test_iso_timestamp(self) -> None:
        text = "IP 203.0.113.10 seen at 2026-06-15T14:30:00+08:00"
        result = parse_complaint_text(text)
        self.assertIsNotNone(result)
        self.assertEqual(result.observed_at.year, 2026)

    def test_source_email(self) -> None:
        result = parse_complaint_text("IP 1.2.3.4", source_email="abuse@isp.com")
        self.assertIsNotNone(result)
        self.assertEqual(result.source_email, "abuse@isp.com")


class MetricsTests(unittest.TestCase):
    def test_counter(self) -> None:
        c = Counter("test_total", "test counter")
        c.inc({"method": "GET"})
        c.inc({"method": "GET"})
        lines = c.collect()
        self.assertTrue(any("2" in l for l in lines))

    def test_gauge(self) -> None:
        g = Gauge("test_gauge")
        g.set(42.0)
        lines = g.collect()
        self.assertTrue(any("42" in l for l in lines))

    def test_histogram(self) -> None:
        h = Histogram("test_hist")
        h.observe(15.0)
        h.observe(100.0)
        lines = h.collect()
        self.assertTrue(any("_count" in l and "2" in l for l in lines))

    def test_registry_render(self) -> None:
        reg = MetricsRegistry()
        reg.http_requests.inc({"method": "GET", "path": "/", "status": "200"})
        output = reg.render()
        self.assertIn("http_requests_total", output)


class SqliteStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        from backend.app.store_sqlite import SqliteStore
        self.store = SqliteStore(db_path=":memory:")
        self.store.register_user("demo", "demo1234", "pro")

    def test_register_and_auth(self) -> None:
        self.assertTrue(self.store.authenticate("demo", "demo1234"))
        self.assertFalse(self.store.authenticate("demo", "wrong"))

    def test_token_lifecycle(self) -> None:
        token = self.store.issue_token("demo")
        self.assertEqual(self.store.validate_token(token), "demo")
        self.store.revoke_token(token)
        self.assertIsNone(self.store.validate_token(token))

    def test_device_binding(self) -> None:
        from backend.app.models import DeviceBinding
        result = self.store.bind_device(DeviceBinding(user_id="demo", device_id="d1", device_label="phone"))
        self.assertTrue(result["ok"])
        devices = self.store.list_devices("demo")
        self.assertEqual(len(devices), 1)
        self.store.unbind_device("demo", "d1")
        self.assertEqual(len(self.store.list_devices("demo")), 0)

    def test_node_operations(self) -> None:
        from backend.app.models import NodeStatus
        node = NodeStatus(node_id="test-1", region="sg", endpoint="test:51820", capacity=500)
        self.store.upsert_node(node)
        nodes = self.store.all_nodes()
        self.assertEqual(len(nodes), 1)
        healthy = self.store.healthy_nodes(region="sg")
        self.assertEqual(len(healthy), 1)

    def test_session_and_trace(self) -> None:
        from backend.app.models import SessionSnapshot
        session = SessionSnapshot(
            session_id="s1", user_id="demo", node_id="sg-1",
            egress_ip="1.2.3.4", started_at=datetime.now(timezone.utc),
        )
        self.store.save_session(session)
        hit = self.store.find_session_by_egress_ip_and_time("1.2.3.4", datetime.now(timezone.utc), 15)
        self.assertIsNotNone(hit)

    def test_audit_log(self) -> None:
        self.store.append_audit_log({"action": "test", "user_id": "demo"})
        logs = self.store.query_audit_logs(user_id="demo")
        self.assertEqual(len(logs), 1)

    def test_policy_versions(self) -> None:
        self.store.save_policy_version("demo", {"bw": 100}, 1)
        self.store.save_policy_version("demo", {"bw": 200}, 2)
        versions = self.store.get_policy_versions("demo")
        self.assertEqual(len(versions), 2)
        self.assertEqual(versions[0]["version"], 2)

    def test_ban_user(self) -> None:
        from backend.app.models import UserStatus
        token = self.store.issue_token("demo")
        self.store.update_user_status("demo", UserStatus.BANNED)
        self.assertIsNone(self.store.validate_token(token))

    def test_user_proxy(self) -> None:
        user = self.store.users.get("demo")
        self.assertIsNotNone(user)
        self.assertEqual(user.user_id, "demo")
        self.assertIsNone(self.store.users.get("ghost"))


if __name__ == "__main__":
    unittest.main()
