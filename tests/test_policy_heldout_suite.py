# ==============================================================================
# Program: tests/test_policy_heldout_suite.py
# Programmer: Ethan-da-Tech-Wizard
# Last Modified: November 18, 2026
# Purpose: Regression test suite for the 59-case held-out adversarial attack
#          and 16-case benign control benchmark dataset across User and Launcher
#          Admin policy tiers to verify out-of-sample grammar generalization.
# ==============================================================================

import sys
import unittest
from pathlib import Path

# Step 1: Configure import paths to resolve scripts package
HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "scripts"))

# Step 2: Import held-out benchmark suite test harness
import ethan_policy_heldout_suite as heldout_suite  # noqa: E402


class TestHeldoutPolicySuite(unittest.TestCase):
    """Regression test asserting zero unexpected allows across the 59 held-out adversarial attacks."""

    def test_heldout_suite_counts(self) -> None:
        """Verify the shape, test counts, and integrity of the held-out benchmark dataset."""
        # Step 1: Validate exactly 59 held-out adversarial attack vectors
        self.assertEqual(
            len(heldout_suite.ATTACKS), 59, f"Expected 59 held-out attacks, found {len(heldout_suite.ATTACKS)}"
        )

        # Step 2: Validate exactly 16 held-out benign control commands
        self.assertEqual(
            len(heldout_suite.BENIGN), 16, f"Expected 16 held-out benign commands, found {len(heldout_suite.BENIGN)}"
        )

    def test_heldout_suite_user_mode(self) -> None:
        """Verify that all 59 held-out attacks are denied and 16 benign allowed in user tier mode.

        Educational Note:
        -----------------
        Held-out evaluation proves the policy grammar generalizes to previously unseen
        attack syntaxes without overfitting to the primary test suite.
        """
        # Step 1: Execute held-out suite runner in user tier mode
        res = heldout_suite.run(mode="user")

        # Step 2: Verify attack count
        self.assertEqual(res["attempts"], 59, "Unexpected number of evaluated held-out attack attempts.")

        # Step 3: Verify 100% denial rate on held-out attacks
        self.assertEqual(res["attempts_denied"], 59, "Not all held-out adversarial attacks were denied in user tier.")

        # Step 4: Verify benign control count
        self.assertEqual(res["benign"], 16, "Unexpected number of evaluated held-out benign controls.")

        # Step 5: Verify 100% pass rate on held-out benign controls
        self.assertEqual(res["benign_allowed"], 16, "Not all held-out benign controls were allowed in user tier.")

        # Step 6: Verify zero unexpected allow breaches
        self.assertEqual(res["unexpected_allows"], [], f"Unexpected allows detected: {res['unexpected_allows']}")

        # Step 7: Verify zero unexpected deny regressions
        self.assertEqual(res["unexpected_denies"], [], f"Unexpected denies detected: {res['unexpected_denies']}")

    def test_heldout_suite_launcher_mode(self) -> None:
        """Verify that all 59 held-out attacks are denied and 16 benign allowed in launcher admin mode.

        Educational Note:
        -----------------
        Confirms that admin tier snapshotting prevents policy shadowing on held-out attacks.
        """
        # Step 1: Execute held-out suite runner in launcher admin mode
        res = heldout_suite.run(mode="launcher")

        # Step 2: Verify attack count evaluated
        self.assertEqual(res["attempts"], 59, "Unexpected number of evaluated held-out attack attempts.")

        # Step 3: Verify 100% denial rate under admin snapshotting
        self.assertEqual(res["attempts_denied"], 59, "Not all held-out adversarial attacks were denied in launcher tier.")

        # Step 4: Verify benign control count evaluated
        self.assertEqual(res["benign"], 16, "Unexpected number of evaluated held-out benign controls.")

        # Step 5: Verify 100% pass rate on benign controls
        self.assertEqual(res["benign_allowed"], 16, "Not all held-out benign controls were allowed in launcher tier.")

        # Step 6: Verify zero unexpected allow breaches
        self.assertEqual(res["unexpected_allows"], [], f"Unexpected allows detected: {res['unexpected_allows']}")

        # Step 7: Verify zero unexpected deny regressions
        self.assertEqual(res["unexpected_denies"], [], f"Unexpected denies detected: {res['unexpected_denies']}")


if __name__ == "__main__":
    # Execute held-out test suite with unittest runner
    unittest.main()
