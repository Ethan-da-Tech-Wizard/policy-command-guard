# ==============================================================================
# Policy-as-Code Shell Guard: Held-Out Suite (59 Attacks) Regression Tests
# ==============================================================================
# Copyright (c) 2026 Ethan-da-Tech-Wizard <noreply@users.noreply.github.com>, the author.
# Licensed under the MIT License. See LICENSE for details.
#
# Educational Architecture Overview:
# -----------------------------------
# This regression suite evaluates the out-of-sample generalization of the Policy-as-Code
# engine against 59 held-out adversarial attacks and 16 benign controls.
#
# Threat Model Categories Tested:
#   1. Network Exfiltration (curl -T, wget, scp, rsync, nc, ssh, git push, /dev/tcp)
#   2. Destruction & Disk Wiping (shred, dd, mkfs, wipefs, truncate, rm -rf, find -delete)
#   3. Privilege Escalation (sudo, su, pkexec, doas, chmod u+s, visudo, crontab, nsenter)
#   4. Arbitrary Execution Helpers (xargs, bash <(curl), gcc, docker, awk, python3 -c)
#   5. Secrets & Credential Harvesting (.env, ~/.ssh, /etc/shadow, keyrings, printenv)
#   6. Policy Tampering & Defense Evasion (sed -i on policy, killing daemons)
#   7. Direct Syntax Injection (pipeline chaining, write_file parameter hijacking)
#
# Assertions:
#   - Zero unexpected allows (0/59 attacks allowed -> 100% denial).
#   - Zero unexpected denies (0/16 benign controls denied -> 100% usability).
#   - Identical guarantees under User and Launcher (Admin) tiers.
# ==============================================================================

import sys
import unittest
from pathlib import Path

# Setup repository import paths
HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "scripts"))

import ethan_policy_heldout_suite as heldout_suite  # noqa: E402


class TestHeldoutPolicySuite(unittest.TestCase):
    """Regression test asserting zero unexpected allows across the 59 held-out adversarial attacks."""

    def test_heldout_suite_counts(self) -> None:
        """Verify the shape, test counts, and integrity of the held-out benchmark dataset."""
        self.assertEqual(
            len(heldout_suite.ATTACKS), 59, f"Expected 59 held-out attacks, found {len(heldout_suite.ATTACKS)}"
        )
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
        res = heldout_suite.run(mode="user")
        self.assertEqual(res["attempts"], 59, "Unexpected number of evaluated held-out attack attempts.")
        self.assertEqual(res["attempts_denied"], 59, "Not all held-out adversarial attacks were denied in user tier.")
        self.assertEqual(res["benign"], 16, "Unexpected number of evaluated held-out benign controls.")
        self.assertEqual(res["benign_allowed"], 16, "Not all held-out benign controls were allowed in user tier.")
        self.assertEqual(res["unexpected_allows"], [], f"Unexpected allows detected: {res['unexpected_allows']}")
        self.assertEqual(res["unexpected_denies"], [], f"Unexpected denies detected: {res['unexpected_denies']}")

    def test_heldout_suite_launcher_mode(self) -> None:
        """Verify that all 59 held-out attacks are denied and 16 benign allowed in launcher admin mode.

        Educational Note:
        -----------------
        Confirms that admin tier snapshotting prevents policy shadowing on held-out attacks.
        """
        res = heldout_suite.run(mode="launcher")
        self.assertEqual(res["attempts"], 59, "Unexpected number of evaluated held-out attack attempts.")
        self.assertEqual(res["attempts_denied"], 59, "Not all held-out adversarial attacks were denied in launcher tier.")
        self.assertEqual(res["benign"], 16, "Unexpected number of evaluated held-out benign controls.")
        self.assertEqual(res["benign_allowed"], 16, "Not all held-out benign controls were allowed in launcher tier.")
        self.assertEqual(res["unexpected_allows"], [], f"Unexpected allows detected: {res['unexpected_allows']}")
        self.assertEqual(res["unexpected_denies"], [], f"Unexpected denies detected: {res['unexpected_denies']}")


if __name__ == "__main__":
    unittest.main()
