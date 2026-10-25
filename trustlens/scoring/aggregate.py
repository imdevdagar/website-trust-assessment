"""Evidence aggregation, abstention, and label floors."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from ..schemas import (
    DIMENSION_LABELS,
    Action,
    Dimension,
    DimensionAssessment,
    Evidence,
    RiskLevel,
    Severity,
)
from .calibration import Calibrator
from .rules import (
    ABSTAIN_CONFIDENCE,
    ABSTAIN_COVERAGE,
    ABSTAIN_SCORE_CEILING,
    ACTION_WEIGHTS,
    CRITICAL_EVIDENCE_CONFIDENCE,
    DIMENSION_CODES,
    DIMENSION_CRITICAL_FLOOR,
    DIMENSION_CRITICAL_MULTI_FLOOR,
    DIMENSION_HIGH_FLOOR,
    DIMENSION_HIGH_MULTI_FLOOR,
    DIMENSIONS,
    HIGH_EVIDENCE_CONFIDENCE,
    HIGH_EVIDENCE_POINTS,
    MALICIOUS_DIMENSION_FLOOR,
    MALICIOUS_LABEL_FLOOR,
    OVERALL_CRITICAL_FLOOR,
    OVERALL_CRITICAL_MULTI_FLOOR,
    OVERALL_HIGH_FLOOR,
    OVERALL_HIGH_MULTI_FLOOR,
    SEVERITY_RANK,
    STRONG_EVIDENCE_CONFIDENCE,
    STRONG_EVIDENCE_POINTS,
    SUSPICIOUS_DIMENSION_FLOOR,
    SUSPICIOUS_LABEL_FLOOR,
    TRUST_CAP,
    coverage_for,
    risk_level,
)


@dataclass
class AggregateResult:
    evidence: list[Evidence]
    dimensions: dict[str, DimensionAssessment]
    overall_risk: float
    overall_level: RiskLevel
    confidence: float
    calibrated_probability: float | None
    coverage: dict[str, float]
    action_weights: dict[str, float]
    floors: list[str]


def merge_evidence(items: Iterable[Evidence]) -> list[Evidence]:
    """Merge repeated codes, then assign stable per-assessment IDs.

    Extractors are independent by design, so the same phenomenon can surface in
    more than one module. Merging by (dimension, code) keeps the strongest
    observation without letting repetition inflate the score.
    """
    merged: dict[tuple[Dimension, str], Evidence] = {}
    for item in items:
        key = (item.dimension, item.code)
        existing = merged.get(key)
        if existing is None:
            merged[key] = item.model_copy(deep=True)
            continue
        if item.risk_points > existing.risk_points or (
            item.risk_points == existing.risk_points and item.trust_points > existing.trust_points
        ):
            existing.title = item.title
            existing.detail = item.detail
            existing.source = item.source
        existing.risk_points = max(existing.risk_points, item.risk_points)
        existing.trust_points = max(existing.trust_points, item.trust_points)
        existing.confidence = max(existing.confidence, item.confidence)
        if SEVERITY_RANK[item.severity] > SEVERITY_RANK[existing.severity]:
            existing.severity = item.severity
        for tag in item.tags:
            if tag not in existing.tags:
                existing.tags.append(tag)
        for name, value in item.provenance.items():
            existing.provenance.setdefault(name, value)
        existing.provenance["merged_instances"] = int(
            existing.provenance.get("merged_instances", 1)
        ) + 1

    ordered = sorted(
        merged.values(),
        key=lambda ev: (
            DIMENSIONS.index(ev.dimension),
            -ev.risk_points,
            -ev.trust_points,
            ev.code,
        ),
    )
    counters = {dimension: 0 for dimension in DIMENSIONS}
    for item in ordered:
        counters[item.dimension] += 1
        item.id = f"ev_{DIMENSION_CODES[item.dimension]}_{counters[item.dimension]:02d}"
    return ordered


def _dimension_summary(
    dimension: Dimension,
    score: float,
    level: RiskLevel,
    abstained: bool,
    risks: list[Evidence],
    trusts: list[Evidence],
    coverage: float,
) -> str:
    label = DIMENSION_LABELS[dimension]
    if abstained:
        return (
            f"{label}: not enough reliable evidence for a score "
            f"({coverage:.0%} source coverage)."
        )
    if not risks:
        if trusts:
            return f"{label}: no adverse findings; {len(trusts)} positive signal(s) observed."
        return f"{label}: no adverse findings in the evidence collected."
    top = sorted(risks, key=lambda ev: ev.risk_points * ev.confidence, reverse=True)[:2]
    titles = "; ".join(item.title for item in top)
    return f"{label} score {score:.0f}/100 ({level.value}). Primary signals: {titles}."


def _build_dimension(
    dimension: Dimension,
    items: list[Evidence],
    sources: dict[str, bool],
) -> DimensionAssessment:
    risks = [item for item in items if item.risk_points > 0]
    trusts = [item for item in items if item.trust_points > 0]
    weighted_risk = sum(item.risk_points * item.confidence for item in risks)
    weighted_trust = min(TRUST_CAP, sum(item.trust_points * item.confidence for item in trusts))
    score = round(max(0.0, min(100.0, weighted_risk - weighted_trust)), 1)
    coverage = coverage_for(dimension, sources)

    denominator = sum(
        (item.risk_points + item.trust_points) * item.confidence for item in items
    )
    if denominator > 0:
        reliability = (
            sum(
                (item.risk_points + item.trust_points) * item.confidence * item.confidence
                for item in items
            )
            / denominator
        )
    elif items:
        reliability = max(item.confidence for item in items) * 0.4
    else:
        reliability = 0.0
    confidence = (
        0.65 * reliability + 0.35 * coverage if items else 0.55 * coverage
    )
    confidence = round(max(0.0, min(0.97, confidence)), 3)

    critical = [
        item
        for item in risks
        if item.severity is Severity.CRITICAL
        and item.confidence >= CRITICAL_EVIDENCE_CONFIDENCE
    ]
    high = [
        item
        for item in risks
        if item.severity is Severity.HIGH
        and item.risk_points >= HIGH_EVIDENCE_POINTS
        and item.confidence >= HIGH_EVIDENCE_CONFIDENCE
    ]
    floor = 0.0
    if critical:
        floor = (
            DIMENSION_CRITICAL_MULTI_FLOOR
            if len(critical) > 1
            else DIMENSION_CRITICAL_FLOOR
        )
        confidence = max(confidence, CRITICAL_EVIDENCE_CONFIDENCE)
    elif high:
        floor = (
            DIMENSION_HIGH_MULTI_FLOOR if len(high) > 1 else DIMENSION_HIGH_FLOOR
        )
        confidence = max(confidence, HIGH_EVIDENCE_CONFIDENCE)
    floored = floor > score
    score = round(max(score, floor), 1)

    strong = any(
        item.risk_points >= STRONG_EVIDENCE_POINTS
        and item.confidence >= STRONG_EVIDENCE_CONFIDENCE
        for item in risks
    )
    abstained = (
        (confidence < ABSTAIN_CONFIDENCE or coverage < ABSTAIN_COVERAGE)
        and score < ABSTAIN_SCORE_CEILING
        and not strong
    )
    level = risk_level(score, abstained=abstained)
    summary = _dimension_summary(
        dimension, score, level, abstained, risks, trusts, coverage
    )
    if floored:
        trigger = "critical" if critical else "high-severity"
        summary += (
            f" The score is floored at {score:.0f} because {trigger} evidence was observed."
        )
    return DimensionAssessment(
        dimension=dimension,
        label=DIMENSION_LABELS[dimension],
        risk_score=score,
        risk_level=level,
        confidence=confidence,
        coverage=coverage,
        applicable=True,
        abstained=abstained,
        summary=summary,
        evidence_ids=[item.id for item in items],
        calibrated_probability=None,
    )


def aggregate(
    evidence_items: Iterable[Evidence],
    sources: dict[str, bool],
    action: Action,
    *,
    calibrator: Calibrator | None = None,
) -> AggregateResult:
    evidence = merge_evidence(evidence_items)
    by_dimension: dict[Dimension, list[Evidence]] = {dimension: [] for dimension in DIMENSIONS}
    for item in evidence:
        by_dimension[item.dimension].append(item)

    dimensions = {
        dimension: _build_dimension(dimension, by_dimension[dimension], sources)
        for dimension in DIMENSIONS
    }
    coverage = {dimension.value: dimensions[dimension].coverage for dimension in DIMENSIONS}
    weights = ACTION_WEIGHTS[action]
    floor_reasons: list[str] = []

    malicious = any(
        item.code == "known_malicious_label" and item.confidence >= 0.5
        for item in evidence
    )
    suspicious = any(
        item.code == "known_suspicious_label" and item.confidence >= 0.5
        for item in evidence
    )

    active = [dimension for dimension in DIMENSIONS if not dimensions[dimension].abstained]
    if active:
        active_weight = sum(weights[dimension] for dimension in active)
        overall_risk = (
            sum(dimensions[dimension].risk_score * weights[dimension] for dimension in active)
            / active_weight
        )
        active_confidence = (
            sum(dimensions[dimension].confidence * weights[dimension] for dimension in active)
            / active_weight
        )
        coverage_confidence = sum(
            coverage[dimension.value] * weights[dimension] for dimension in DIMENSIONS
        )
        confidence = 0.70 * active_confidence + 0.30 * coverage_confidence
    else:
        overall_risk = 0.0
        confidence = 0.0

    critical_all = [
        item
        for item in evidence
        if item.severity is Severity.CRITICAL
        and item.confidence >= CRITICAL_EVIDENCE_CONFIDENCE
    ]
    high_all = [
        item
        for item in evidence
        if item.severity is Severity.HIGH
        and item.risk_points >= HIGH_EVIDENCE_POINTS
        and item.confidence >= HIGH_EVIDENCE_CONFIDENCE
    ]
    evidence_floor = 0.0
    if critical_all:
        evidence_floor = (
            OVERALL_CRITICAL_MULTI_FLOOR
            if len(critical_all) > 1
            else OVERALL_CRITICAL_FLOOR
        )
        confidence = max(confidence, CRITICAL_EVIDENCE_CONFIDENCE)
        floor_reasons.append("critical_evidence")
    elif high_all:
        evidence_floor = (
            OVERALL_HIGH_MULTI_FLOOR if len(high_all) > 1 else OVERALL_HIGH_FLOOR
        )
        confidence = max(confidence, HIGH_EVIDENCE_CONFIDENCE)
        floor_reasons.append("high_evidence")
    overall_risk = max(overall_risk, evidence_floor)

    if malicious:
        dimensions[Dimension.SECURITY].risk_score = max(
            dimensions[Dimension.SECURITY].risk_score, MALICIOUS_DIMENSION_FLOOR
        )
        dimensions[Dimension.SECURITY].risk_level = RiskLevel.CRITICAL
        dimensions[Dimension.SECURITY].abstained = False
        dimensions[Dimension.SECURITY].summary = (
            "Security & Fraud score 85/100 (critical). The domain appears on a locally "
            "imported malicious-label list; this floor overrides the evidence-weighted score."
        )
        dimensions[Dimension.SECURITY].confidence = max(
            dimensions[Dimension.SECURITY].confidence, 0.8
        )
        overall_risk = max(overall_risk, MALICIOUS_LABEL_FLOOR)
        confidence = max(confidence, 0.82)
        floor_reasons.append("known_malicious_label")
    elif suspicious:
        dimensions[Dimension.SECURITY].risk_score = max(
            dimensions[Dimension.SECURITY].risk_score, SUSPICIOUS_DIMENSION_FLOOR
        )
        dimensions[Dimension.SECURITY].risk_level = RiskLevel.HIGH
        dimensions[Dimension.SECURITY].abstained = False
        dimensions[Dimension.SECURITY].summary = (
            "Security & Fraud score 55/100 (high). The domain appears on a locally "
            "imported suspicious-label list."
        )
        dimensions[Dimension.SECURITY].confidence = max(
            dimensions[Dimension.SECURITY].confidence, 0.7
        )
        overall_risk = max(overall_risk, SUSPICIOUS_LABEL_FLOOR)
        confidence = max(confidence, 0.68)
        floor_reasons.append("known_suspicious_label")

    overall_risk = round(max(0.0, min(100.0, overall_risk)), 1)
    confidence = round(max(0.0, min(0.99, confidence)), 3)
    if malicious:
        overall_level = RiskLevel.CRITICAL
    elif not active or confidence < ABSTAIN_CONFIDENCE:
        overall_level = RiskLevel.UNKNOWN
    else:
        overall_level = risk_level(overall_risk)

    calibrated = None
    if calibrator is not None and overall_level != RiskLevel.UNKNOWN:
        calibrated = calibrator.probability(overall_risk)

    return AggregateResult(
        evidence=evidence,
        dimensions={dimension.value: dimensions[dimension] for dimension in DIMENSIONS},
        overall_risk=overall_risk,
        overall_level=overall_level,
        confidence=confidence,
        calibrated_probability=calibrated,
        coverage=coverage,
        action_weights={dimension.value: weights[dimension] for dimension in DIMENSIONS},
        floors=floor_reasons,
    )
