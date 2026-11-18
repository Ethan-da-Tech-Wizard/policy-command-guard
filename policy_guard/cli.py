#!/usr/bin/env python3
# ==============================================================================
# Program: policy_guard/cli.py
# Programmer: Ethan-da-Tech-Wizard
# Course: CIS 156 / Advanced Systems
# Last Modified: November 18, 2026
# Purpose: Command-line interface for policy-as-code shell command evaluation.
#          Accepts shell command strings via CLI arguments, evaluates them
#          against zero-trust AST policies, and returns JSON or ANSI colored
#          verdicts with standard UNIX process exit codes.
# ==============================================================================

import argparse
import json
import sys
from .engine import PolicyCommandGuard
from .models import Decision


def main() -> int:
    """Parse command-line arguments and evaluate the given shell command string.

    Returns:
        0 if the command passed all zero-trust policy checks and is allowed.
        1 if the command was blocked or violated security constraints.
    """
    # Step 1: Configure command-line argument parser with descriptive documentation
    parser = argparse.ArgumentParser(
        prog="policy-guard",
        description=(
            "Policy-as-code command evaluation and shell execution guard.\n"
            "Evaluates shell commands against AST tokenization, path traversal, "
            "credential containment, and zero-trust allowlist policies."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # Positional argument: raw command string to evaluate
    parser.add_argument(
        "command",
        nargs="?",
        help="Raw shell command string to evaluate (e.g. 'ls -la && git status').",
    )
    # Optional flag: machine-readable JSON output for automated toolhooks
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output evaluation result as structured JSON for programmatic consumption.",
    )
    args = parser.parse_args()

    # Step 2: If no command argument was passed, display usage instructions and exit cleanly
    if not args.command:
        parser.print_help()
        return 0

    # Step 3: Instantiate the zero-trust command guard engine
    guard = PolicyCommandGuard()

    # Step 4: Perform multi-layered security evaluation on the input command
    res = guard.evaluate_shell_command(args.command)

    # Step 5: Format and present the evaluation outcome based on requested output mode
    if args.json:
        # Step 5a: Generate machine-readable JSON dictionary payload
        payload = {
            "command": args.command,
            "decision": res.decision.value,
            "is_allowed": res.is_allowed,
            "is_denied": res.is_denied,
            "message": res.message,
            "matched_pattern": res.matched_pattern,
            "subcommand_count": len(res.subcommand_results),
        }
        print(json.dumps(payload, indent=2))
    else:
        # Step 5b: Render human-readable terminal output with ANSI color highlighting
        status_prefix = "[\033[92mALLOWED\033[0m]" if res.is_allowed else "[\033[91mDENIED\033[0m]"
        print(f"{status_prefix} {args.command}")
        if res.message:
            print(f"  Reason: {res.message}")

    # Step 6: Return standard UNIX exit code (0 for allowed, 1 for blocked/denied)
    return 0 if res.decision == Decision.ALLOW else 1


if __name__ == "__main__":
    # Execute CLI entrypoint and propagate exit status to host shell
    sys.exit(main())
