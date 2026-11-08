#!/usr/bin/env python3
"""Command-line interface for evaluating shell commands against policy."""
import argparse
import sys
from .engine import PolicyCommandGuard
from .models import Decision


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Policy-as-code command evaluation and shell execution guard."
    )
    parser.add_argument("command", nargs="?", help="Shell command to evaluate.")
    parser.add_argument("--json", action="store_true", help="Output evaluation result in JSON format.")
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    guard = PolicyCommandGuard()
    res = guard.evaluate_shell_command(args.command)

    if args.json:
        import json
        print(json.dumps({
            "command": args.command,
            "decision": res.decision.value,
            "message": res.message,
            "matched_pattern": res.matched_pattern,
        }, indent=2))
    else:
        status_prefix = "[\033[92mALLOWED\033[0m]" if res.is_allowed else "[\033[91mDENIED\033[0m]"
        print(f"{status_prefix} {args.command}")
        if res.message:
            print(f"  Reason: {res.message}")

    return 0 if res.decision == Decision.ALLOW else 1


if __name__ == "__main__":
    sys.exit(main())
