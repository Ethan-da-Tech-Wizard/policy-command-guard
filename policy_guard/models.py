# ==============================================================================
# Policy-as-Code Shell Guard: Data Models & Decision Structures
# ==============================================================================
# Copyright (c) 2026 Ethan-da-Tech-Wizard <noreply@users.noreply.github.com>, the author.
# Licensed under the MIT License. See LICENSE for details.
#
# Educational Architecture Overview:
# -----------------------------------
# This module defines the core data representations for declarative policy rules,
# hierarchical evaluation tiers, and structured evaluation outcomes.
#
# Key Concepts:
#   1. Zero-Trust Decision Outcomes (Decision):
#      - ALLOW: The command or tool call is strictly within the approved grammar.
#      - DENY: The command violates safety constraints or fails to match any allowlist.
#      - ASK_USER: Interactive confirmation required for high-impact bounded operations.
#   2. Two-Tier Hierarchical Enforcement (PolicyTier):
#      - ADMIN: Immutable, non-overridable security boundaries established at system
#        startup. In launcher mode, deny rules are snapshotted into this tier so no
#        user-level policy configuration can override an administrative restriction.
#      - USER: Workspace-level or developer-scoped rules governing everyday workflows.
#   3. AST Composite Result Propagation (EvaluationResult):
#      - When a compound pipeline command (e.g. `ls -la && rm -rf /`) is evaluated,
#        each individual AST subcommand produces an EvaluationResult.
#      - The root EvaluationResult aggregates all sub-verdicts under a fail-closed
#        policy: if any subcommand returns DENY, the entire pipeline is DENIED.
# ==============================================================================

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Decision(str, Enum):
    """Enumeration of policy evaluation decisions.

    Educational Note:
    -----------------
    In a zero-trust architecture, the default decision prior to rule evaluation
    is always DENY (fail-closed). A command is only granted ALLOW if an explicit,
    unambiguous rule validates every component of the requested operation.
    """

    ALLOW = "allow"
    DENY = "deny"
    ASK_USER = "ask_user"


class PolicyTier(str, Enum):
    """Hierarchical policy enforcement tiers.

    Educational Note:
    -----------------
    Policy engines often suffer from 'policy shadowing' or 'configuration override'
    vulnerabilities, where a project-local config disables global security rules.
    To prevent this, the engine enforces a strict two-tier hierarchy:
      - ADMIN: Immutable core constraints (e.g., banning `sudo`, disk formatters,
        reverse shells, credential access). Admin DENY rules take precedence over
        all User rules and cannot be bypassed.
      - USER: Contextual allowances (e.g., permitting `git status` or `pytest`
        within a specific repository workspace).
    """

    ADMIN = "admin"
    USER = "user"


@dataclass(frozen=True)
class PolicyRule:
    """A declarative policy rule defining permissions and constraints.

    Attributes:
        tool_name: The name of the tool or execution mechanism (e.g. 'run_shell_command').
        decision: The verdict to apply when the rule matches (ALLOW, DENY, ASK_USER).
        priority: Numerical priority (higher values evaluate first; Admin rules use >=900).
        args_pattern: Regular expression or grammar string matching serialized tool arguments.
                      Serialized arguments use NUL (\x00) boundary wrapping to prevent
                      parameter injection attacks.
        deny_message: Explanatory error message returned to the caller when a DENY rule triggers.
        allow_redirection: Boolean indicating if subshell splitting and AST decomposition
                           is permitted for downstream validation.
        metadata: Arbitrary contextual attributes (e.g. threat category, author, timestamp).
    """

    tool_name: str
    decision: Decision
    priority: int = 500
    args_pattern: Optional[str] = None
    deny_message: Optional[str] = None
    allow_redirection: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EvaluationResult:
    """The structured result of evaluating a shell command or tool invocation.

    Attributes:
        decision: The final verdict (ALLOW or DENY).
        rule: The specific PolicyRule that determined the verdict (if matched).
        message: Human-readable explanation of why the command was allowed or denied.
        matched_pattern: Identifier or name of the security pattern that triggered (e.g.
                         'path_traversal_dotdot', 'critical_binary_rm').
        subcommand_results: For compound pipelines (`cmd1 | cmd2 && cmd3`), contains the
                            individual EvaluationResult for each constituent AST segment.
    """

    decision: Decision
    rule: Optional[PolicyRule] = None
    message: Optional[str] = None
    matched_pattern: Optional[str] = None
    subcommand_results: List["EvaluationResult"] = field(default_factory=list)

    @property
    def is_allowed(self) -> bool:
        """Convenience property returning True if the command passed all policy checks."""
        return self.decision == Decision.ALLOW

    @property
    def is_denied(self) -> bool:
        """Convenience property returning True if the command was blocked."""
        return self.decision == Decision.DENY
