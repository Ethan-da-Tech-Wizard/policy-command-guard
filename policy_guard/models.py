"""Data models for policy-as-code evaluation and security gating."""
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Decision(str, Enum):
    """Policy evaluation decision outcomes."""
    ALLOW = "allow"
    DENY = "deny"
    ASK_USER = "ask_user"


class PolicyTier(str, Enum):
    """Evaluation tiers in hierarchical policy enforcement."""
    ADMIN = "admin"
    USER = "user"


@dataclass(frozen=True)
class PolicyRule:
    """A single declarative policy rule."""
    tool_name: str
    decision: Decision
    priority: int = 500
    args_pattern: Optional[str] = None
    deny_message: Optional[str] = None
    allow_redirection: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EvaluationResult:
    """The result of evaluating a tool call or shell command against policy."""
    decision: Decision
    rule: Optional[PolicyRule] = None
    message: Optional[str] = None
    matched_pattern: Optional[str] = None
    subcommand_results: List["EvaluationResult"] = field(default_factory=list)

    @property
    def is_allowed(self) -> bool:
        """Convenience check for allowed decisions."""
        return self.decision == Decision.ALLOW

    @property
    def is_denied(self) -> bool:
        """Convenience check for denied decisions."""
        return self.decision == Decision.DENY
