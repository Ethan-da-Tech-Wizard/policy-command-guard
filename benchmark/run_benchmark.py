#!/usr/bin/env python3
# ==============================================================================
# Program: benchmark/run_benchmark.py
# Programmer: Ethan-da-Tech-Wizard
# Last Modified: November 18, 2026
# Purpose: Unified security benchmark runner evaluating the PolicyCommandGuard
#          against 565 adversarial attack vectors and 154 benign developer
#          inspection commands across User and Admin Launcher tiers.
# ==============================================================================

import argparse
import json
import sys
from pathlib import Path

# Step 1: Configure module resolution paths for local scripts and root package imports
# Make both the repo root (for the benchmark package) and scripts/ (for the
# suite modules) importable without installing anything.
HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts"))

# Step 2: Import test runner suites and dataset metadata
# The noqa markers are needed because these imports intentionally follow the
# sys.path changes above (E402).
import ethan_policy_bypass_suite as bypass_suite  # noqa: E402
import ethan_policy_heldout_suite as heldout_suite  # noqa: E402
from benchmark.datasets import get_dataset_summary  # noqa: E402


def verdict_line(attacks: int, denied: int, benign: int, allowed: int) -> str:
    """Build the final VERDICT banner text from real benchmark counts.

    Args:
        attacks: attack commands evaluated (summed over modes).
        denied: how many of those the engine denied.
        benign: benign control commands evaluated.
        allowed: how many of those the engine allowed.

    Returns:
        A "ZERO DANGEROUS COMMANDS EXECUTED" line only when every attack was denied
        and every benign command allowed; otherwise a "FAIL" line with the counts.
    """
    if denied == attacks and allowed == benign:
        return f"VERDICT: ZERO DANGEROUS COMMANDS EXECUTED ({denied}/{attacks} ADVERSARIAL ATTACKS BLOCKED)"
    return (f"VERDICT: FAIL ({attacks - denied} ATTACKS NOT DENIED, "
            f"{benign - allowed} BENIGN COMMANDS WRONGLY DENIED)")


# Returns the process exit code: 0 only if every attack was denied and every
# benign command was allowed in every evaluated mode.
def main() -> int:
    """Execute the unified policy security benchmark and report verification metrics."""
    # Step 1: Configure argument parsing for evaluation modes and reporting outputs
    parser = argparse.ArgumentParser(
        prog="run_benchmark",
        description="Execute full 565-case policy security benchmark against the PolicyEngine.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--mode",
        choices=["user", "launcher", "both"],
        default="both",
        help="Policy evaluation mode: 'user' (standard tier), 'launcher' (admin snapshot), or 'both'.",
    )
    parser.add_argument(
        "--json",
        help="Optional filesystem path to export full JSON benchmark results.",
    )
    args = parser.parse_args()

    # Step 2: Display dataset composition, cardinality, and evaluation scope
    summary = get_dataset_summary()
    print("=" * 80)
    print("POLICY-AS-CODE COMMAND GUARD: BENCHMARK SUITE")
    print("=" * 80)
    print(f"Primary Suite:  {summary['primary_attacks']} adversarial attacks | {summary['primary_benign']} benign commands")
    print(f"Held-out Suite: {summary['heldout_attacks']} adversarial attacks | {summary['heldout_benign']} benign commands")
    print(f"Total Attacks:  {summary['total_adversarial_attacks']} adversarial vectors")
    print(f"Total Controls: {summary['total_benign_controls']} benign control commands")
    print("=" * 80)

    # Step 3: Determine execution modes to iterate over
    # 'both' means the standard user tier and the admin launcher snapshot tier.
    modes = ["user", "launcher"] if args.mode == "both" else [args.mode]
    all_results = {}

    # Step 4: Execute security benchmark across requested evaluation modes
    for mode in modes:
        print(f"\nEvaluating Tier Mode: [{mode.upper()}]")
        print("-" * 50)

        # Step 4a: Execute Primary Suite (506 attacks, 138 benign)
        primary_res = bypass_suite.run(mode=mode, verbose=False)
        primary_pct = (primary_res['attempts_denied'] / primary_res['attempts']) * 100.0
        benign_pct = (primary_res['benign_allowed'] / primary_res['benign']) * 100.0

        print(f"  Primary Attacks Denied:  {primary_res['attempts_denied']}/{primary_res['attempts']} ({primary_pct:.1f}%)")
        print(f"  Primary Benign Allowed:  {primary_res['benign_allowed']}/{primary_res['benign']} ({benign_pct:.1f}%)")

        # Step 4b: Execute Held-Out Suite (59 attacks, 16 benign)
        heldout_res = heldout_suite.run(mode=mode)
        heldout_att_pct = (heldout_res['attempts_denied'] / heldout_res['attempts']) * 100.0
        heldout_ben_pct = (heldout_res['benign_allowed'] / heldout_res['benign']) * 100.0

        print(f"  Held-out Attacks Denied: {heldout_res['attempts_denied']}/{heldout_res['attempts']} ({heldout_att_pct:.1f}%)")
        print(f"  Held-out Benign Allowed: {heldout_res['benign_allowed']}/{heldout_res['benign']} ({heldout_ben_pct:.1f}%)")

        # Step 4c: Calculate Combined Accuracy Metrics
        total_attacks = primary_res['attempts'] + heldout_res['attempts']
        total_denied = primary_res['attempts_denied'] + heldout_res['attempts_denied']
        total_benign = primary_res['benign'] + heldout_res['benign']
        total_allowed = primary_res['benign_allowed'] + heldout_res['benign_allowed']

        # Percentage is computed from the real counts so a regression shows up as < 100%.
        # Guard against a zero denominator (an empty dataset) instead of dividing by zero.
        combined_pct = (total_denied / total_attacks * 100.0) if total_attacks else 0.0
        print(f"  Combined Attacks Denied: {total_denied}/{total_attacks} ({combined_pct:.1f}%)")
        # An attack that was NOT denied is an attack the engine would have let run, so the
        # number of dangerous commands "run" is exactly the number of undenied attacks.
        print(f"  Dangerous Commands Run:  {total_attacks - total_denied}"
              + (" (ZERO EXECUTION)" if total_denied == total_attacks else " (FAILURE)"))

        # Step 4d: Store metrics for JSON export and regression verification
        all_results[mode] = {
            "primary": primary_res,
            "heldout": heldout_res,
            "total_attacks": total_attacks,
            "total_denied": total_denied,
            "total_benign": total_benign,
            "total_allowed": total_allowed,
        }

    # The verdict is derived from the same numbers the failure gate below uses.
    verdict_attacks = sum(m["total_attacks"] for m in all_results.values())
    verdict_denied = sum(m["total_denied"] for m in all_results.values())
    verdict_benign = sum(m["total_benign"] for m in all_results.values())
    verdict_allowed = sum(m["total_allowed"] for m in all_results.values())
    print("\n" + "=" * 80)
    print(verdict_line(verdict_attacks, verdict_denied, verdict_benign, verdict_allowed))
    print("=" * 80)

    # Step 5: Export machine-readable JSON if requested by user
    if args.json:
        Path(args.json).write_text(json.dumps(all_results, indent=2))
        print(f"Benchmark results successfully written to {args.json}")

    # Step 6: Enforce strict zero-regression failure gate
    # Failure gate: any attack not denied, or any benign command not allowed, fails.
    failed = False
    for mode_data in all_results.values():
        if mode_data["total_denied"] != mode_data["total_attacks"]:
            failed = True
        if mode_data["total_allowed"] != mode_data["total_benign"]:
            failed = True

    return 1 if failed else 0


if __name__ == "__main__":
    # Execute benchmark runner and propagate exit status
    sys.exit(main())
