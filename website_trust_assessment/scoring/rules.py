"""Deterministic scoring constants and action-specific weighting."""

from __future__ import annotations

from ..schemas import Action, Dimension, RiskLevel, Severity

DIMENSIONS: tuple[Dimension, ...] = (
    Dimension.SECURITY,
    Dimension.IDENTITY,
    Dimension.PRIVACY,
    Dimension.MANIPULATION,
)

DIMENSION_CODES: dict[Dimension, str] = {
    Dimension.SECURITY: "sec",
    Dimension.IDENTITY: "idn",
    Dimension.PRIVACY: "pri",
    Dimension.MANIPULATION: "man",
}

ACTION_WEIGHTS: dict[Action, dict[Dimension, float]] = {
    Action.BROWSE: {
        Dimension.SECURITY: 0.45,
        Dimension.IDENTITY: 0.20,
        Dimension.PRIVACY: 0.15,
        Dimension.MANIPULATION: 0.20,
    },
    Action.SIGNUP: {
        Dimension.SECURITY: 0.30,
        Dimension.IDENTITY: 0.25,
        Dimension.PRIVACY: 0.30,
        Dimension.MANIPULATION: 0.15,
    },
    Action.PURCHASE: {
        Dimension.SECURITY: 0.35,
        Dimension.IDENTITY: 0.35,
        Dimension.PRIVACY: 0.15,
        Dimension.MANIPULATION: 0.15,
    },
}

COVERAGE_SOURCES: dict[Dimension, dict[str, float]] = {
    Dimension.SECURITY: {
        "url": 0.10,
        "page": 0.25,
        "headers": 0.15,
        "tls": 0.15,
        "dns": 0.10,
        "infrastructure_graph": 0.15,
        "hidden_content": 0.10,
    },
    Dimension.IDENTITY: {
        "url": 0.15,
        "page": 0.30,
        "rdap": 0.30,
        "dns": 0.10,
        "tls": 0.10,
        "privacy_policy": 0.05,
    },
    Dimension.PRIVACY: {
        "page": 0.20,
        "network": 0.25,
        "privacy_policy": 0.25,
        "ocr": 0.10,
        "hidden_content": 0.10,
        "infrastructure_graph": 0.10,
    },
    Dimension.MANIPULATION: {
        "page": 0.35,
        "url": 0.10,
        "hidden_content": 0.20,
        "ocr": 0.20,
        "network": 0.10,
        "infrastructure_graph": 0.05,
    },
}

SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

TRUST_CAP = 12.0
ABSTAIN_CONFIDENCE = 0.30
ABSTAIN_COVERAGE = 0.25
ABSTAIN_SCORE_CEILING = 35.0
STRONG_EVIDENCE_POINTS = 10.0
STRONG_EVIDENCE_CONFIDENCE = 0.7

CRITICAL_EVIDENCE_CONFIDENCE = 0.7
HIGH_EVIDENCE_POINTS = 20.0
HIGH_EVIDENCE_CONFIDENCE = 0.7
DIMENSION_CRITICAL_FLOOR = 65.0
DIMENSION_CRITICAL_MULTI_FLOOR = 75.0
DIMENSION_HIGH_FLOOR = 40.0
DIMENSION_HIGH_MULTI_FLOOR = 48.0
OVERALL_CRITICAL_FLOOR = 68.0
OVERALL_CRITICAL_MULTI_FLOOR = 82.0
OVERALL_HIGH_FLOOR = 42.0
OVERALL_HIGH_MULTI_FLOOR = 55.0

MALICIOUS_LABEL_FLOOR = 92.0
SUSPICIOUS_LABEL_FLOOR = 60.0
MALICIOUS_DIMENSION_FLOOR = 85.0
SUSPICIOUS_DIMENSION_FLOOR = 55.0


def risk_level(score: float, *, abstained: bool = False) -> RiskLevel:
    if abstained:
        return RiskLevel.UNKNOWN
    if score >= 75.0:
        return RiskLevel.CRITICAL
    if score >= 50.0:
        return RiskLevel.HIGH
    if score >= 25.0:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def coverage_for(dimension: Dimension, sources: dict[str, bool]) -> float:
    weights = COVERAGE_SOURCES[dimension]
    total = sum(weights.values())
    if total <= 0:
        return 0.0
    available = sum(weight for name, weight in weights.items() if sources.get(name))
    return round(min(1.0, available / total), 3)


def action_label(action: Action) -> str:
    return {
        Action.BROWSE: "browsing",
        Action.SIGNUP: "creating an account",
        Action.PURCHASE: "making a purchase",
    }[action]
