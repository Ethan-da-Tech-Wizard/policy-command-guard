"""Unit test regression suite for 59 held-out adversarial attacks and 16 benign commands."""
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "scripts"))

import ethan_policy_heldout_suite as heldout_suite  # noqa: E402


class TestHeldoutPolicySuite(unittest.TestCase):
    """Assert zero unexpected allows in the 59 held-out adversarial attacks."""

    def test_heldout_suite_counts(self):
        """Verify the shape and test counts of held-out dataset."""
        self.assertEqual(len(heldout_suite.ATTACKS), 59, f"Expected 59 held-out attacks, found {len(heldout_suite.ATTACKS)}")
        self.assertEqual(len(heldout_suite.BENIGN), 16, f"Expected 16 held-out benign commands, found {len(heldout_suite.BENIGN)}")

    def test_heldout_suite_user_mode(self):
        """Verify all 59 attacks denied and 16 benign allowed in user tier mode."""
        res = heldout_suite.run(mode="user")
        self.assertEqual(res["attempts"], 59)
        self.assertEqual(res["attempts_denied"], 59)
        self.assertEqual(res["benign"], 16)
        self.assertEqual(res["benign_allowed"], 16)
        self.assertEqual(res["unexpected_allows"], [], f"Unexpected allows detected: {res['unexpected_allows']}")
        self.assertEqual(res["unexpected_denies"], [], f"Unexpected denies detected: {res['unexpected_denies']}")

    def test_heldout_suite_launcher_mode(self):
        """Verify all 59 attacks denied and 16 benign allowed in launcher admin-snapshot mode."""
        res = heldout_suite.run(mode="launcher")
        self.assertEqual(res["attempts"], 59)
        self.assertEqual(res["attempts_denied"], 59)
        self.assertEqual(res["benign"], 16)
        self.assertEqual(res["benign_allowed"], 16)
        self.assertEqual(res["unexpected_allows"], [], f"Unexpected allows detected: {res['unexpected_allows']}")
        self.assertEqual(res["unexpected_denies"], [], f"Unexpected denies detected: {res['unexpected_denies']}")


if __name__ == "__main__":
    unittest.main()
