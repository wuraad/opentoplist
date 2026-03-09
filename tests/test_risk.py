import unittest

from backend.app.models import RiskAction, RiskSignal, RiskThresholds
from backend.app.risk import evaluate_risk


class RiskModelTests(unittest.TestCase):
    def test_low_risk_allows(self) -> None:
        signal = RiskSignal(
            user_id="u1",
            session_id="s1",
            connection_count=80,
            unique_dst_ports=10,
            burst_bandwidth_mbps=30,
        )
        result = evaluate_risk(signal)
        self.assertEqual(result.action, RiskAction.ALLOW)
        self.assertEqual(result.score, 0)

    def test_medium_risk_throttles(self) -> None:
        signal = RiskSignal(
            user_id="u2",
            session_id="s2",
            connection_count=700,
            unique_dst_ports=65,
            burst_bandwidth_mbps=120,
        )
        result = evaluate_risk(signal)
        self.assertEqual(result.action, RiskAction.THROTTLE)
        self.assertGreaterEqual(result.score, 30)

    def test_high_risk_bans(self) -> None:
        signal = RiskSignal(
            user_id="u3",
            session_id="s3",
            connection_count=2000,
            unique_dst_ports=240,
            burst_bandwidth_mbps=600,
        )
        result = evaluate_risk(signal)
        self.assertEqual(result.action, RiskAction.BAN)
        self.assertGreaterEqual(result.score, 80)

    def test_quarantine_range(self) -> None:
        signal = RiskSignal(
            user_id="u4",
            session_id="s4",
            connection_count=1300,
            unique_dst_ports=70,
            burst_bandwidth_mbps=100,
        )
        result = evaluate_risk(signal)
        self.assertEqual(result.action, RiskAction.QUARANTINE)
        self.assertGreaterEqual(result.score, 55)
        self.assertLess(result.score, 80)

    def test_custom_thresholds(self) -> None:
        strict = RiskThresholds(
            conn_high=500,
            conn_elevated=200,
            score_ban=50,
            score_quarantine=35,
            score_throttle=15,
        )
        signal = RiskSignal(
            user_id="u5",
            session_id="s5",
            connection_count=600,
            unique_dst_ports=10,
            burst_bandwidth_mbps=10,
        )
        result = evaluate_risk(signal, thresholds=strict)
        self.assertEqual(result.action, RiskAction.QUARANTINE)

    def test_elevated_reasons(self) -> None:
        signal = RiskSignal(
            user_id="u6",
            session_id="s6",
            connection_count=700,
            unique_dst_ports=70,
            burst_bandwidth_mbps=250,
        )
        result = evaluate_risk(signal)
        self.assertIn("elevated_connection_count", result.reasons)
        self.assertIn("suspicious_port_spread", result.reasons)
        self.assertIn("high_burst_bandwidth", result.reasons)

    def test_zero_values_allow(self) -> None:
        signal = RiskSignal(
            user_id="u7",
            session_id="s7",
            connection_count=0,
            unique_dst_ports=0,
            burst_bandwidth_mbps=0,
        )
        result = evaluate_risk(signal)
        self.assertEqual(result.action, RiskAction.ALLOW)
        self.assertEqual(result.score, 0)
        self.assertEqual(len(result.reasons), 0)


if __name__ == "__main__":
    unittest.main()
