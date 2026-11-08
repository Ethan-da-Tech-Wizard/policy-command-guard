"""Benchmark evaluation dataset containing 565 adversarial attack tests and benign controls."""
from pathlib import Path
import sys
from typing import Any, Dict, List, Tuple

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "scripts"))

import ethan_policy_bypass_suite as bypass_suite  # noqa: E402
import ethan_policy_heldout_suite as heldout_suite  # noqa: E402

# Primary benchmark suite (506 attacks, 138 benign)
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

# Held-out benchmark suite (59 attacks, 16 benign)
HELDOUT_ATTACKS: List[Tuple[str, Dict[str, Any], str, str]] = list(heldout_suite.ATTACKS)
HELDOUT_BENIGN: List[Tuple[str, Dict[str, Any], str, str]] = list(heldout_suite.BENIGN)

# Aggregated benchmark suite (565 total adversarial attack vectors)
TOTAL_ADVERSARIAL_ATTACKS = PRIMARY_ATTACKS + HELDOUT_ATTACKS
TOTAL_BENIGN_COMMANDS = PRIMARY_BENIGN + HELDOUT_BENIGN


def get_dataset_summary() -> Dict[str, Any]:
    """Return verified statistics of the benchmark dataset."""
    return {
        "primary_attacks": len(PRIMARY_ATTACKS),
        "primary_benign": len(PRIMARY_BENIGN),
        "heldout_attacks": len(HELDOUT_ATTACKS),
        "heldout_benign": len(HELDOUT_BENIGN),
        "total_adversarial_attacks": len(TOTAL_ADVERSARIAL_ATTACKS),
        "total_benign_controls": len(TOTAL_BENIGN_COMMANDS),
    }
