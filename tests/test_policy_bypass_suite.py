# ==============================================================================
# Policy-as-Code Shell Guard: Primary Suite (506 Attacks) Regression Tests
# ==============================================================================
# Copyright (c) 2026 Ethan-da-Tech-Wizard <noreply@users.noreply.github.com>, the author.
# Licensed under the MIT License. See LICENSE for details.
#
# Educational Architecture Overview:
# -----------------------------------
# This regression suite verifies the primary policy evaluation dataset:
#   - 506 Adversarial Shell Attacks (VERIFIER_145 + MINE)
#   - 138 Benign Developer Controls (VERIFIER Controls + BENIGN_EXTRA)
#
# Tested Dimensions:
#   1. Dataset Cardinality: Guarantees test count stability (506 attacks, 138 controls).
#   2. User Tier Execution: Verifies 100.0% denial rate on attacks and 100.0% pass rate
#      on controls under standard user-level policy evaluation.
#   3. Launcher Admin-Snapshot Tier: Verifies that admin snapshotting preserves all deny
#      rules and provides identical zero-trust guarantees against shadowed configurations.
# ==============================================================================

import sys
import unittest
from pathlib import Path

# Setup repository import paths
HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "scripts"))

import ethan_policy_bypass_suite as bypass_suite  # noqa: E402


class TestPrimaryPolicyBypassSuite(unittest.TestCase):
    """Regression test asserting zero unexpected allows across the 506 primary adversarial attacks."""

    def test_primary_suite_counts(self) -> None:
        """Verify the shape, test counts, and integrity of the primary benchmark dataset."""
        n_attacks = sum(1 for c in bypass_suite.VERIFIER_145 + bypass_suite.MINE if c[2] == "deny")
        n_benign = sum(1 for c in bypass_suite.VERIFIER_145 + bypass_suite.MINE if c[2] == "allow") + len(
            bypass_suite.BENIGN_EXTRA
        )
        self.assertEqual(n_attacks, 506, f"Expected 506 primary attacks, found {n_attacks}")
        self.assertEqual(n_benign, 138, f"Expected 138 primary benign commands, found {n_benign}")

    def test_primary_suite_user_mode(self) -> None:
        """Verify that all 506 attacks are denied and 138 benign allowed in user tier mode.

        Educational Note:
        -----------------
        Zero-trust principle: A single unexpected allow represents a security boundary breach.
        A single unexpected deny represents a broken developer workflow. Both must be zero.
        """
        res = bypass_suite.run(mode="user", verbose=False)
        self.assertEqual(res["attempts"], 506, "Unexpected number of evaluated attack attempts.")
        self.assertEqual(res["attempts_denied"], 506, "Not all adversarial attacks were denied in user tier.")
        self.assertEqual(res["benign"], 138, "Unexpected number of evaluated benign controls.")
        self.assertEqual(res["benign_allowed"], 138, "Not all benign controls were allowed in user tier.")
        self.assertEqual(res["unexpected_allows"], [], f"Unexpected allows detected: {res['unexpected_allows']}")
        self.assertEqual(res["unexpected_denies"], [], f"Unexpected denies detected: {res['unexpected_denies']}")

    def test_primary_suite_launcher_mode(self) -> None:
        """Verify that all 506 attacks are denied and 138 benign allowed in launcher admin-snapshot mode.

        Educational Note:
        -----------------
        The launcher mode snapshots deny-rules into the immutable admin tier. This test
        confirms that admin tier elevation maintains 100% security coverage.
        """
        res = bypass_suite.run(mode="launcher", verbose=False)
        self.assertEqual(res["attempts"], 506, "Unexpected number of evaluated attack attempts.")
        self.assertEqual(res["attempts_denied"], 506, "Not all adversarial attacks were denied in launcher tier.")
        self.assertEqual(res["benign"], 138, "Unexpected number of evaluated benign controls.")
        self.assertEqual(res["benign_allowed"], 138, "Not all benign controls were allowed in launcher tier.")
        self.assertEqual(res["unexpected_allows"], [], f"Unexpected allows detected: {res['unexpected_allows']}")
        self.assertEqual(res["unexpected_denies"], [], f"Unexpected denies detected: {res['unexpected_denies']}")


if __name__ == "__main__":
    unittest.main()
