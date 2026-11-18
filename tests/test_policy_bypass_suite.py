# ==============================================================================
# Program: tests/test_policy_bypass_suite.py
# Programmer: Ethan-da-Tech-Wizard
# Course: CIS 156 / Advanced Systems
# Last Modified: November 18, 2026
# Purpose: Regression test suite for the primary 506-vector adversarial attack
#          and 138-vector benign developer control benchmark dataset across User
#          and Launcher Admin policy tiers.
# ==============================================================================

import sys
import unittest
from pathlib import Path

# Step 1: Configure import paths to access repository scripts directory
HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "scripts"))

# Step 2: Import primary bypass suite test engine
import ethan_policy_bypass_suite as bypass_suite  # noqa: E402


class TestPrimaryPolicyBypassSuite(unittest.TestCase):
    """Regression test asserting zero unexpected allows across the 506 primary adversarial attacks."""

    def test_primary_suite_counts(self) -> None:
        """Verify the shape, test counts, and integrity of the primary benchmark dataset."""
        # Step 1: Calculate the total number of attacks expecting DENY
        n_attacks = sum(1 for c in bypass_suite.VERIFIER_145 + bypass_suite.MINE if c[2] == "deny")

        # Step 2: Calculate the total number of controls expecting ALLOW
        n_benign = sum(1 for c in bypass_suite.VERIFIER_145 + bypass_suite.MINE if c[2] == "allow") + len(
            bypass_suite.BENIGN_EXTRA
        )

        # Step 3: Assert dataset cardinality stability
        self.assertEqual(n_attacks, 506, f"Expected 506 primary attacks, found {n_attacks}")
        self.assertEqual(n_benign, 138, f"Expected 138 primary benign commands, found {n_benign}")

    def test_primary_suite_user_mode(self) -> None:
        """Verify that all 506 attacks are denied and 138 benign allowed in user tier mode.

        Educational Note:
        -----------------
        Zero-trust principle: A single unexpected allow represents a security boundary breach.
        A single unexpected deny represents a broken developer workflow. Both must be zero.
        """
        # Step 1: Execute primary suite runner in user tier mode
        res = bypass_suite.run(mode="user", verbose=False)

        # Step 2: Verify total count of evaluated attacks
        self.assertEqual(res["attempts"], 506, "Unexpected number of evaluated attack attempts.")

        # Step 3: Verify 100% denial rate on attacks
        self.assertEqual(res["attempts_denied"], 506, "Not all adversarial attacks were denied in user tier.")

        # Step 4: Verify total count of evaluated benign controls
        self.assertEqual(res["benign"], 138, "Unexpected number of evaluated benign controls.")

        # Step 5: Verify 100% pass rate on benign controls
        self.assertEqual(res["benign_allowed"], 138, "Not all benign controls were allowed in user tier.")

        # Step 6: Verify zero unexpected allow breaches
        self.assertEqual(res["unexpected_allows"], [], f"Unexpected allows detected: {res['unexpected_allows']}")

        # Step 7: Verify zero unexpected deny regressions
        self.assertEqual(res["unexpected_denies"], [], f"Unexpected denies detected: {res['unexpected_denies']}")

    def test_primary_suite_launcher_mode(self) -> None:
        """Verify that all 506 attacks are denied and 138 benign allowed in launcher admin-snapshot mode.

        Educational Note:
        -----------------
        The launcher mode snapshots deny-rules into the immutable admin tier. This test
        confirms that admin tier elevation maintains 100% security coverage.
        """
        # Step 1: Execute primary suite runner in launcher admin-snapshot mode
        res = bypass_suite.run(mode="launcher", verbose=False)

        # Step 2: Verify attack count evaluated
        self.assertEqual(res["attempts"], 506, "Unexpected number of evaluated attack attempts.")

        # Step 3: Verify 100% denial rate under admin snapshot
        self.assertEqual(res["attempts_denied"], 506, "Not all adversarial attacks were denied in launcher tier.")

        # Step 4: Verify benign control count evaluated
        self.assertEqual(res["benign"], 138, "Unexpected number of evaluated benign controls.")

        # Step 5: Verify 100% pass rate for benign controls
        self.assertEqual(res["benign_allowed"], 138, "Not all benign controls were allowed in launcher tier.")

        # Step 6: Assert empty list of unexpected allows
        self.assertEqual(res["unexpected_allows"], [], f"Unexpected allows detected: {res['unexpected_allows']}")

        # Step 7: Assert empty list of unexpected denies
        self.assertEqual(res["unexpected_denies"], [], f"Unexpected denies detected: {res['unexpected_denies']}")


if __name__ == "__main__":
    # Execute primary test suite with unittest runner
    unittest.main()
