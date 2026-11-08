"""Unit test regression suite for 506 primary adversarial attacks and 138 benign commands."""
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "scripts"))

import ethan_policy_bypass_suite as bypass_suite  # noqa: E402


class TestPrimaryPolicyBypassSuite(unittest.TestCase):
    """Assert zero unexpected allows in the 506 primary adversarial attacks."""

    def test_primary_suite_counts(self):
        """Verify the shape and test counts of primary dataset."""
        n_attacks = sum(1 for c in bypass_suite.VERIFIER_145 + bypass_suite.MINE if c[2] == "deny")
        n_benign = sum(1 for c in bypass_suite.VERIFIER_145 + bypass_suite.MINE if c[2] == "allow") + len(bypass_suite.BENIGN_EXTRA)
        self.assertEqual(n_attacks, 506, f"Expected 506 primary attacks, found {n_attacks}")
        self.assertEqual(n_benign, 138, f"Expected 138 primary benign commands, found {n_benign}")

    def test_primary_suite_user_mode(self):
        """Verify all 506 attacks denied and 138 benign allowed in user tier mode."""
        res = bypass_suite.run(mode="user", verbose=False)
        self.assertEqual(res["attempts"], 506)
        self.assertEqual(res["attempts_denied"], 506)
        self.assertEqual(res["benign"], 138)
        self.assertEqual(res["benign_allowed"], 138)
        self.assertEqual(res["unexpected_allows"], [], f"Unexpected allows detected: {res['unexpected_allows']}")
        self.assertEqual(res["unexpected_denies"], [], f"Unexpected denies detected: {res['unexpected_denies']}")

    def test_primary_suite_launcher_mode(self):
        """Verify all 506 attacks denied and 138 benign allowed in launcher admin-snapshot mode."""
        res = bypass_suite.run(mode="launcher", verbose=False)
        self.assertEqual(res["attempts"], 506)
        self.assertEqual(res["attempts_denied"], 506)
        self.assertEqual(res["benign"], 138)
        self.assertEqual(res["benign_allowed"], 138)
        self.assertEqual(res["unexpected_allows"], [], f"Unexpected allows detected: {res['unexpected_allows']}")
        self.assertEqual(res["unexpected_denies"], [], f"Unexpected denies detected: {res['unexpected_denies']}")


if __name__ == "__main__":
    unittest.main()
