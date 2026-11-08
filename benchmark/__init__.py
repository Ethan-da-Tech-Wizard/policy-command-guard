# ==============================================================================
# Policy-as-Code Shell Guard: Benchmark Package
# ==============================================================================
# Copyright (c) 2026 Ethan-da-Tech-Wizard <noreply@users.noreply.github.com>, the author.
# Licensed under the MIT License. See LICENSE for details.
#
# Educational Architecture Overview:
# -----------------------------------
# This package exports datasets, metrics, and runners for the 565-vector
# adversarial security evaluation of the PolicyEngine.
# ==============================================================================

from .datasets import (
    HELDOUT_ATTACKS,
    HELDOUT_BENIGN,
    PRIMARY_ATTACKS,
    PRIMARY_BENIGN,
    TOTAL_ADVERSARIAL_ATTACKS,
    TOTAL_BENIGN_COMMANDS,
    get_dataset_summary,
)

__all__ = [
    "PRIMARY_ATTACKS",
    "PRIMARY_BENIGN",
    "HELDOUT_ATTACKS",
    "HELDOUT_BENIGN",
    "TOTAL_ADVERSARIAL_ATTACKS",
    "TOTAL_BENIGN_COMMANDS",
    "get_dataset_summary",
]
