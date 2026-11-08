#!/usr/bin/env python3
# ==============================================================================
# Policy-as-Code Shell Guard: Command-Line Interface (CLI)
# ==============================================================================
# Copyright (c) 2026 Ethan-da-Tech-Wizard <noreply@users.noreply.github.com>, the author.
# Licensed under the MIT License. See LICENSE for details.
#
# Educational Architecture Overview:
# -----------------------------------
# This CLI provides a lightweight, zero-dependency gateway for pre-execution
# shell command verification.
#
# Integration Use Cases:
#   1. Pre-Execution Hook in AI Agent Tool Runtimes:
#      Before an autonomous agent executes a command via `subprocess.run()`,
#      it queries `policy-guard --json "<command>"`. If the decision is DENY,
#      the tool invocation is immediately aborted without spawning a shell.
#   2. Git Pre-Commit / Pre-Push Security Gates:
#      Verify scripts and build steps before allowing code commits.
#   3. Interactive Developer Auditing:
#      Developers can test commands against the policy engine directly in the
#      terminal with colorized, human-readable feedback.
#
# Exit Code Convention:
#   - 0: Command is explicitly ALLOWED under the active policy.
#   - 1: Command is DENIED or an evaluation error occurred (fail-closed).
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
    parser = argparse.ArgumentParser(
        prog="policy-guard",
        description=(
            "Policy-as-code command evaluation and shell execution guard.\n"
            "Evaluates shell commands against AST tokenization, path traversal, "
            "credential containment, and zero-trust allowlist policies."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "command",
        nargs="?",
        help="Raw shell command string to evaluate (e.g. 'ls -la && git status').",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output evaluation result as structured JSON for programmatic consumption.",
    )
    args = parser.parse_args()

    # If no command argument was passed, display usage and exit cleanly
    if not args.command:
        parser.print_help()
        return 0

    # Instantiate the zero-trust command guard engine
    guard = PolicyCommandGuard()
    res = guard.evaluate_shell_command(args.command)

    # Machine-readable output format for automated runners and CI/CD
    if args.json:
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
        # Human-readable terminal output with ANSI color highlighting
        status_prefix = "[\033[92mALLOWED\033[0m]" if res.is_allowed else "[\033[91mDENIED\033[0m]"
        print(f"{status_prefix} {args.command}")
        if res.message:
            print(f"  Reason: {res.message}")

    # Enforce standard process exit code: 0 for allowed, 1 for blocked
    return 0 if res.decision == Decision.ALLOW else 1


if __name__ == "__main__":
    sys.exit(main())
