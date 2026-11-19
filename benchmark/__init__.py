# ==============================================================================
# Program: benchmark/__init__.py
# Programmer: Ethan-da-Tech-Wizard
# Last Modified: November 18, 2026
# Purpose: Benchmark package initialization exposing benchmark datasets, primary
#          and held-out attack suites, benign developer control datasets, and
#          summary diagnostic functions for evaluating policy guard accuracy.
# ==============================================================================

# ------------------------------------------------------------------------------
# Import primary and held-out attack suites, benign controls, and telemetry helpers
# ------------------------------------------------------------------------------
from .datasets import (
    HELDOUT_ATTACKS,
    HELDOUT_BENIGN,
    PRIMARY_ATTACKS,
    PRIMARY_BENIGN,
    TOTAL_ADVERSARIAL_ATTACKS,
    TOTAL_BENIGN_COMMANDS,
    get_dataset_summary,
)

# Export public package symbols
__all__ = [
    "PRIMARY_ATTACKS",
    "PRIMARY_BENIGN",
    "HELDOUT_ATTACKS",
    "HELDOUT_BENIGN",
    "TOTAL_ADVERSARIAL_ATTACKS",
    "TOTAL_BENIGN_COMMANDS",
    "get_dataset_summary",
]
