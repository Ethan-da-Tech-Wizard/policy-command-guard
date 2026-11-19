# ==============================================================================
# Program: policy_guard/__init__.py
# Programmer: Ethan-da-Tech-Wizard
# Last Modified: November 18, 2026
# Purpose: Package entrypoint exporting the public interface for the Policy-as-Code
#          Shell Guard system. Exposes AST evaluators, decision enumerations,
#          data models, tokenizers, and security path validators for zero-trust
#          command execution gating.
# ==============================================================================

# ------------------------------------------------------------------------------
# Import evaluation engine, path security validator, and shell tokenizer
# ------------------------------------------------------------------------------
from .engine import PathSecurityValidator, PolicyCommandGuard, ShellTokenizer

# ------------------------------------------------------------------------------
# Import core decision enums, evaluation containers, and policy models
# ------------------------------------------------------------------------------
from .models import Decision, EvaluationResult, PolicyRule, PolicyTier

# Semantic versioning identifier for release tracking
__version__ = "1.0.0"

# Explicit public API export manifest
__all__ = [
    "Decision",
    "EvaluationResult",
    "PolicyRule",
    "PolicyTier",
    "PolicyCommandGuard",
    "ShellTokenizer",
    "PathSecurityValidator",
]
