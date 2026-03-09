import unittest

from backend.app.models import RiskAction, RiskSignal
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


if __name__ == "__main__":
    unittest.main()
