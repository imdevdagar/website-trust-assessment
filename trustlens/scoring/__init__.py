"""Transparent rule scoring, optional calibration, and evidence-grounded text."""

from .aggregate import AggregateResult, aggregate, merge_evidence
from .calibration import Calibrator, load_calibrator
from .explanations import Explanation, compose
from .rules import ACTION_WEIGHTS, DIMENSIONS, coverage_for, risk_level

__all__ = [
    "ACTION_WEIGHTS",
    "DIMENSIONS",
    "AggregateResult",
    "Calibrator",
    "Explanation",
    "aggregate",
    "compose",
    "coverage_for",
    "load_calibrator",
    "merge_evidence",
    "risk_level",
]
