# ==============================================================================
# Program: benchmark/datasets.py
# Programmer: Ethan-da-Tech-Wizard
# Last Modified: November 18, 2026
# Purpose: Benchmark dataset definition and aggregation module. Indexes 565
#          adversarial shell attack vectors and 154 benign developer control
#          commands across primary and held-out test suites for comprehensive
#          security boundary evaluation.
# ==============================================================================

import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Step 1: Resolve repository paths for cross-module script imports
HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "scripts"))

# Step 2: Import primary bypass suite and out-of-sample heldout test suites
import ethan_policy_bypass_suite as bypass_suite  # noqa: E402
import ethan_policy_heldout_suite as heldout_suite  # noqa: E402

# ------------------------------------------------------------------------------
# Primary Benchmark Suite: 506 Adversarial Attacks & 138 Benign Controls
# ------------------------------------------------------------------------------

# Filter all test cases expected to result in DENY from the primary suite
PRIMARY_ATTACKS: List[Tuple[str, Dict[str, Any], str, str]] = [
    (c[0], c[1], c[2], c[3] if len(c) > 3 else "")
    for c in bypass_suite.VERIFIER_145 + bypass_suite.MINE
    if c[2] == "deny"
]

# Filter all test cases expected to result in ALLOW from the primary suite,
# appending developer benign extra command fixtures
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

# Load out-of-sample adversarial attack vectors
HELDOUT_ATTACKS: List[Tuple[str, Dict[str, Any], str, str]] = list(heldout_suite.ATTACKS)

# Load out-of-sample benign control commands
HELDOUT_BENIGN: List[Tuple[str, Dict[str, Any], str, str]] = list(heldout_suite.BENIGN)

# ------------------------------------------------------------------------------
# Aggregated Benchmark Collections (565 Attacks, 154 Benign)
# ------------------------------------------------------------------------------

# Aggregate full adversarial corpus: 506 primary + 59 held-out = 565 attacks
TOTAL_ADVERSARIAL_ATTACKS = PRIMARY_ATTACKS + HELDOUT_ATTACKS

# Aggregate full benign corpus: 138 primary + 16 held-out = 154 benign controls
TOTAL_BENIGN_COMMANDS = PRIMARY_BENIGN + HELDOUT_BENIGN


def get_dataset_summary() -> Dict[str, Any]:
    """Return verified statistics and counts of the benchmark datasets.

    Returns:
        Dictionary mapping dataset partition names to integer element counts.
    """
    # Step 1: Query length of each dataset slice
    summary = {
        "primary_attacks": len(PRIMARY_ATTACKS),
        "primary_benign": len(PRIMARY_BENIGN),
        "heldout_attacks": len(HELDOUT_ATTACKS),
        "heldout_benign": len(HELDOUT_BENIGN),
        "total_adversarial_attacks": len(TOTAL_ADVERSARIAL_ATTACKS),
        "total_benign_controls": len(TOTAL_BENIGN_COMMANDS),
    }

    # Step 2: Return structured dataset summary map
    return summary
