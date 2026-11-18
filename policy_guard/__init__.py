# Program: policy-command-guard - __init__.py
# Programmer: Ethan-da-Tech-Wizard (written with Claude, an AI assistant)
# Last Modified: 2026-11-18
# Purpose: Package marker for policy_guard; re-exports the engine classes and data models that make up the public interface.
#
# ==============================================================================
# Policy-as-Code Shell Guard Package
# ==============================================================================
# Copyright (c) 2026 Ethan-da-Tech-Wizard <noreply@users.noreply.github.com>, the author.
# Licensed under the MIT License. See LICENSE for details.
#
# Educational Architecture Overview:
# -----------------------------------
# This package exports the public interface for the Policy-as-Code Shell Guard:
#   - Decision: Enumeration of outcomes (ALLOW, DENY, ASK_USER).
#   - EvaluationResult: Composite decision container tracking AST subcommands.
#   - PolicyRule: Declarative rule specification with priority and args pattern.
#   - PolicyTier: Hierarchical enforcement tiers (ADMIN vs USER).
#   - PolicyCommandGuard: Primary evaluation engine.
#   - ShellTokenizer: Lexical AST tokenizer with quote context tracking.
#   - PathSecurityValidator: Traversal and sensitive credential containment validator.
# ==============================================================================
"""Public interface of the policy_guard package."""

from .engine import PathSecurityValidator, PolicyCommandGuard, ShellTokenizer
from .models import Decision, EvaluationResult, PolicyRule, PolicyTier

__version__ = "1.0.0"
__all__ = [
    "Decision",
    "EvaluationResult",
    "PolicyRule",
    "PolicyTier",
    "PolicyCommandGuard",
    "ShellTokenizer",
    "PathSecurityValidator",
]
