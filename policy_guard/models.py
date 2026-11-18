# ==============================================================================
# Program: policy_guard/models.py
# Programmer: Ethan-da-Tech-Wizard
# Course: CIS 156 / Advanced Systems
# Last Modified: November 18, 2026
# Purpose: Define zero-trust data representations, hierarchical policy tiers,
#          immutable declarative rule contracts, and composite evaluation result
#          structures for shell command execution gating.
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

    # Unconditionally approve command execution within approved grammar
    ALLOW = "allow"
    # Block execution due to security policy violation or unlisted command
    DENY = "deny"
    # Prompt the human operator for explicit confirmation before running
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

    # System-level root policy tier with immutable deny rules
    ADMIN = "admin"
    # Workspace-level developer policy tier for contextual workflows
    USER = "user"


@dataclass(frozen=True)
class PolicyRule:
    """A declarative policy rule defining permissions and constraints.

    Attributes:
        tool_name: The name of the tool or execution mechanism (e.g. 'run_shell_command').
        decision: The verdict to apply when the rule matches (ALLOW, DENY, ASK_USER).
        priority: Numerical priority (higher values evaluate first; Admin rules use >=900).
        args_pattern: Regular expression or grammar string matching serialized tool arguments.
                      Serialized arguments use NUL (\\x00) boundary wrapping to prevent
                      parameter injection attacks.
        deny_message: Explanatory error message returned to the caller when a DENY rule triggers.
        allow_redirection: Boolean indicating if subshell splitting and AST decomposition
                           is permitted for downstream validation.
        metadata: Arbitrary contextual attributes (e.g. threat category, author, timestamp).
    """

    # Target tool identifier (e.g., "run_shell_command", "ShellTool")
    tool_name: str
    # Evaluation verdict produced upon successful rule match
    decision: Decision
    # Evaluation precedence priority (higher integers evaluated first)
    priority: int = 500
    # Serialized argument regex pattern with zero-trust NUL delimiters
    args_pattern: Optional[str] = None
    # Descriptive explanation delivered to client upon policy block
    deny_message: Optional[str] = None
    # Flag enabling pipeline segmentation and recursive token inspection
    allow_redirection: bool = False
    # Contextual metadata dictionary for auditing and telemetry
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

    # Composite decision verdict for the command invocation
    decision: Decision
    # Reference to the matching policy rule that triggered the outcome
    rule: Optional[PolicyRule] = None
    # Informative audit reason or security diagnostic message
    message: Optional[str] = None
    # Specific vulnerability signature or pattern identifier that fired
    matched_pattern: Optional[str] = None
    # Nested evaluation results for all decomposed AST pipeline segments
    subcommand_results: List["EvaluationResult"] = field(default_factory=list)

    @property
    def is_allowed(self) -> bool:
        """Convenience property returning True if the command passed all policy checks."""
        # Step 1: Compare decision against ALLOW enum state
        return self.decision == Decision.ALLOW

    @property
    def is_denied(self) -> bool:
        """Convenience property returning True if the command was blocked."""
        # Step 1: Compare decision against DENY enum state
        return self.decision == Decision.DENY
