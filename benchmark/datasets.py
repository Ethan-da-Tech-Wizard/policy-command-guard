# ==============================================================================
# Policy-as-Code Shell Guard: Benchmark Dataset Definition
# ==============================================================================
# Copyright (c) 2026 Ethan-da-Tech-Wizard <noreply@users.noreply.github.com>, the author.
# Licensed under the MIT License. See LICENSE for details.
#
# Educational Architecture Overview:
# -----------------------------------
# This module defines and indexes the 565 adversarial attack vectors and 154 benign
# developer control commands used to rigorously evaluate the Policy-as-Code engine.
#
# Dataset Decomposition:
#   1. Primary Benchmark Suite (ethan_policy_bypass_suite.py):
#      - 506 Adversarial Attacks:
#        * VERIFIER_145 (141 attack vectors): Independently authored bypass attempts
#          spanning shell syntax tricks, globbing, $IFS splitting, and variable expansions.
#        * MINE (365 attack vectors): Advanced adversarial attempts targeting disk destruction,
#          network exfiltration, interpreter escapes, git smuggling, and policy tampering.
#      - 138 Benign Developer Commands:
#        * Real-world developer inspection workflows (ls, cat, git status, git log,
#          python3 test runners, date, whoami, grep, jq, etc.).
#   2. Held-Out Benchmark Suite (ethan_policy_heldout_suite.py):
#      - 59 Held-Out Adversarial Attacks:
#        * 7 distinct threat categories evaluated out-of-sample to ensure zero overfitting:
#          1. Network exfiltration (curl -T, wget, scp, rsync, nc, ssh, git push, etc.)
#          2. Disk destruction & wiping (shred, dd, mkfs, wipefs, truncate, rm -rf, etc.)
#          3. Privilege escalation (sudo, su, pkexec, doas, visudo, nsenter, etc.)
#          4. Helper / Interpreter escapes (xargs, bash <(curl), gcc, docker, awk, python -c)
#          5. Secrets & credential theft (.env, .ssh/id_rsa, /etc/shadow, keyrings, etc.)
#          6. Policy tampering & defense evasion (sed -i on policy, killing guards)
#          7. Direct syntax injection (pipeline chaining, write_file tool hijacking)
#      - 16 Held-Out Benign Commands:
#        * Legitimate inspection commands (ls -la, head, grep, git diff, sort, uniq, etc.)
#
# Aggregated Verification Targets:
#   - Total Adversarial Attacks: 565 / 565 DENIED (100.0% denial rate)
#   - Total Benign Controls:    154 / 154 ALLOWED (100.0% pass rate)
#   - Dangerous Commands Run:   0 (ZERO EXECUTION GUARANTEE)
# ==============================================================================

import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Resolve repository paths for cross-module imports
HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "scripts"))

import ethan_policy_bypass_suite as bypass_suite  # noqa: E402
import ethan_policy_heldout_suite as heldout_suite  # noqa: E402

# ------------------------------------------------------------------------------
# Primary Benchmark Suite: 506 Adversarial Attacks & 138 Benign Controls
# ------------------------------------------------------------------------------
PRIMARY_ATTACKS: List[Tuple[str, Dict[str, Any], str, str]] = [
    (c[0], c[1], c[2], c[3] if len(c) > 3 else "")
    for c in bypass_suite.VERIFIER_145 + bypass_suite.MINE
    if c[2] == "deny"
]

PRIMARY_BENIGN: List[Tuple[str, Dict[str, Any], str, str]] = [
    (c[0], c[1], c[2], c[3] if len(c) > 3 else "")
    for c in bypass_suite.VERIFIER_145 + bypass_suite.MINE
    if c[2] == "allow"
] + [
    (bypass_suite.S, {"command": c}, "allow", "benign extra")
    for c in bypass_suite.BENIGN_EXTRA
]

# ------------------------------------------------------------------------------
# Held-Out Benchmark Suite: 59 Adversarial Attacks & 16 Benign Controls
# ------------------------------------------------------------------------------
HELDOUT_ATTACKS: List[Tuple[str, Dict[str, Any], str, str]] = list(heldout_suite.ATTACKS)
HELDOUT_BENIGN: List[Tuple[str, Dict[str, Any], str, str]] = list(heldout_suite.BENIGN)

# ------------------------------------------------------------------------------
# Aggregated Benchmark Collections (565 Attacks, 154 Benign)
# ------------------------------------------------------------------------------
TOTAL_ADVERSARIAL_ATTACKS = PRIMARY_ATTACKS + HELDOUT_ATTACKS
TOTAL_BENIGN_COMMANDS = PRIMARY_BENIGN + HELDOUT_BENIGN


def get_dataset_summary() -> Dict[str, Any]:
    """Return verified statistics and counts of the benchmark datasets."""
    return {
        "primary_attacks": len(PRIMARY_ATTACKS),
        "primary_benign": len(PRIMARY_BENIGN),
        "heldout_attacks": len(HELDOUT_ATTACKS),
        "heldout_benign": len(HELDOUT_BENIGN),
        "total_adversarial_attacks": len(TOTAL_ADVERSARIAL_ATTACKS),
        "total_benign_controls": len(TOTAL_BENIGN_COMMANDS),
    }
