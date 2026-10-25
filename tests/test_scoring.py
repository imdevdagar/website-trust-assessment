from __future__ import annotations

import pytest

from tests.factories import make_assessment
from trustlens.pipeline import guard_decision
from trustlens.schemas import Action, Dimension, Evidence, RiskLevel, Severity
from trustlens.scoring.aggregate import aggregate, merge_evidence
from trustlens.scoring.explanations import compose
from trustlens.scoring.rules import COVERAGE_SOURCES, risk_level


def make_evidence(
    dimension: Dimension,
    code: str,
    *,
    risk: float = 0.0,
    trust: float = 0.0,
    confidence: float = 0.9,
    severity: Severity = Severity.MEDIUM,
    source: str = "test",
    tags: list[str] | None = None,
    provenance: dict[str, object] | None = None,
) -> Evidence:
    return Evidence(
        dimension=dimension,
        code=code,
        title=f"{code} title",
        detail=f"{code} detail",
        severity=severity,
        risk_points=risk,
        trust_points=trust,
        confidence=confidence,
        source=source,
        tags=tags or [],
        provenance=provenance or {},
    )


def full_sources() -> dict[str, bool]:
    names = {name for weights in COVERAGE_SOURCES.values() for name in weights}
    return {name: True for name in names}


def test_merge_evidence_keeps_strongest_observation() -> None:
    weaker = make_evidence(
        Dimension.SECURITY,
        "login_form",
        risk=5,
        trust=1,
        confidence=0.6,
        severity=Severity.LOW,
        source="content",
        tags=["form"],
        provenance={"page": "home"},
    )
    stronger = make_evidence(
        Dimension.SECURITY,
        "login_form",
        risk=12,
        trust=2,
        confidence=0.9,
        severity=Severity.HIGH,
        source="forms",
        tags=["password"],
        provenance={"page": "login", "form_index": 2},
    )
    identity = make_evidence(Dimension.IDENTITY, "official_domain", trust=3, confidence=1.0)

    merged = merge_evidence([weaker, stronger, identity])

    assert [item.code for item in merged] == ["login_form", "official_domain"]
    login = merged[0]
    assert login.risk_points == 12
    assert login.trust_points == 2
    assert login.confidence == 0.9
    assert login.severity is Severity.HIGH
    assert login.source == "forms"
    assert login.tags == ["form", "password"]
    assert login.provenance == {
        "page": "home",
        "form_index": 2,
        "merged_instances": 2,
    }
    assert login.id == "ev_sec_01"
    assert merged[1].id == "ev_idn_01"


def test_critical_evidence_applies_dimension_and_overall_floors() -> None:
    single = aggregate(
        [make_evidence(Dimension.SECURITY, "seed_phrase", risk=45, severity=Severity.CRITICAL)],
        full_sources(),
        Action.BROWSE,
    )
    assert single.dimensions["security"].risk_score == 65.0
    assert single.overall_risk == 68.0
    assert single.overall_level is RiskLevel.HIGH
    assert single.floors == ["critical_evidence"]

    multiple = aggregate(
        [
            make_evidence(Dimension.SECURITY, "seed_phrase", risk=20, severity=Severity.CRITICAL),
            make_evidence(Dimension.SECURITY, "remote_access", risk=20, severity=Severity.CRITICAL),
        ],
        full_sources(),
        Action.BROWSE,
    )
    assert multiple.dimensions["security"].risk_score == 75.0
    assert multiple.overall_risk == 82.0
    assert multiple.overall_level is RiskLevel.CRITICAL


def test_high_evidence_applies_lower_floors() -> None:
    result = aggregate(
        [make_evidence(Dimension.SECURITY, "credential_form", risk=25, severity=Severity.HIGH)],
        full_sources(),
        Action.BROWSE,
    )
    assert result.dimensions["security"].risk_score == 40.0
    assert result.overall_risk == 42.0
    assert result.overall_level is RiskLevel.MEDIUM
    assert result.floors == ["high_evidence"]


def test_floor_headlines_do_not_conflate_evidence_with_imported_labels() -> None:
    evidence_floor = aggregate(
        [make_evidence(Dimension.SECURITY, "credential_form", risk=25, severity=Severity.HIGH)],
        full_sources(),
        Action.BROWSE,
    )
    explanation = compose(
        evidence_floor,
        action=Action.BROWSE,
        final_domain="example.test",
        missing_evidence=[],
    )
    assert explanation.headline == "Some risk signals warrant caution"
    assert "imported label" not in explanation.headline

    label_floor = aggregate(
        [
            make_evidence(
                Dimension.SECURITY,
                "known_malicious_label",
                risk=1,
                severity=Severity.LOW,
                confidence=0.8,
            )
        ],
        full_sources(),
        Action.BROWSE,
    )
    label_explanation = compose(
        label_floor,
        action=Action.BROWSE,
        final_domain="example.test",
        missing_evidence=[],
    )
    assert label_explanation.headline == "Domain is on the local malicious list"


def test_malicious_label_floor_overrides_weak_evidence() -> None:
    label = make_evidence(
        Dimension.SECURITY,
        "known_malicious_label",
        risk=1,
        severity=Severity.LOW,
        confidence=0.8,
    )
    result = aggregate([label], full_sources(), Action.PURCHASE)

    assert result.dimensions["security"].risk_score == 85.0
    assert result.dimensions["security"].risk_level is RiskLevel.CRITICAL
    assert result.overall_risk == 92.0
    assert result.overall_level is RiskLevel.CRITICAL
    assert result.confidence >= 0.82
    assert "known_malicious_label" in result.floors


def test_suspicious_label_floor_is_high_not_critical() -> None:
    label = make_evidence(
        Dimension.SECURITY,
        "known_suspicious_label",
        risk=1,
        severity=Severity.LOW,
        confidence=0.8,
    )
    result = aggregate([label], full_sources(), Action.BROWSE)

    assert result.dimensions["security"].risk_score == 55.0
    assert result.dimensions["security"].risk_level is RiskLevel.HIGH
    assert result.overall_risk == 60.0
    assert result.overall_level is RiskLevel.HIGH
    assert "known_suspicious_label" in result.floors


def test_no_evidence_abstains_instead_of_reporting_safe() -> None:
    result = aggregate([], {}, Action.SIGNUP)

    assert result.overall_risk == 0.0
    assert result.overall_level is RiskLevel.UNKNOWN
    assert result.confidence == 0.0
    assert result.calibrated_probability is None
    assert all(dimension.abstained for dimension in result.dimensions.values())
    assert all(
        dimension.risk_level is RiskLevel.UNKNOWN
        for dimension in result.dimensions.values()
    )


def test_action_weights_change_the_overall_score() -> None:
    evidence = [
        make_evidence(Dimension.SECURITY, "security_signal", risk=40, confidence=0.8),
        make_evidence(Dimension.IDENTITY, "identity_signal", risk=20, confidence=0.8),
        make_evidence(Dimension.PRIVACY, "privacy_signal", risk=10, confidence=0.8),
        make_evidence(Dimension.MANIPULATION, "manipulation_signal", risk=20, confidence=0.8),
    ]
    browse = aggregate(evidence, full_sources(), Action.BROWSE)
    signup = aggregate(evidence, full_sources(), Action.SIGNUP)
    purchase = aggregate(evidence, full_sources(), Action.PURCHASE)

    assert browse.overall_risk == 22.0
    assert signup.overall_risk == 18.4
    assert purchase.overall_risk == 20.4
    assert browse.action_weights == {
        "security": 0.45,
        "identity": 0.20,
        "privacy": 0.15,
        "manipulation": 0.20,
    }
    assert signup.action_weights["privacy"] == 0.30


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.0, RiskLevel.LOW),
        (24.9, RiskLevel.LOW),
        (25.0, RiskLevel.MEDIUM),
        (49.9, RiskLevel.MEDIUM),
        (50.0, RiskLevel.HIGH),
        (74.9, RiskLevel.HIGH),
        (75.0, RiskLevel.CRITICAL),
        (100.0, RiskLevel.CRITICAL),
    ],
)
def test_risk_level_boundaries(score: float, expected: RiskLevel) -> None:
    assert risk_level(score) is expected
    assert risk_level(score, abstained=True) is RiskLevel.UNKNOWN


def test_guard_decision_maps_levels_and_confidence() -> None:
    benign = make_assessment("example.com")
    verdict, reasons = guard_decision(benign)
    assert verdict == "allow"
    assert reasons == ["Synthetic positive signal"]

    unknown = benign.model_copy(update={"overall_level": RiskLevel.UNKNOWN, "confidence": 0.2})
    verdict, reasons = guard_decision(unknown)
    assert verdict == "warn"
    assert reasons[0] == "There is not enough reliable evidence to clear this site"

    medium = benign.model_copy(update={"overall_level": RiskLevel.MEDIUM, "confidence": 0.8})
    assert guard_decision(medium)[0] == "warn"

    high = make_assessment("risky.com", malicious=True)
    verdict, reasons = guard_decision(high)
    assert verdict == "block"
    assert "Synthetic adverse signal" in reasons

    tentative = high.model_copy(update={"confidence": 0.5})
    assert guard_decision(tentative)[0] == "warn"

    critical = high.model_copy(update={"overall_level": RiskLevel.CRITICAL})
    assert guard_decision(critical)[0] == "block"


def test_guard_decision_surfaces_reputation_floor() -> None:
    labelled = make_assessment(
        "risky.com",
        malicious=True,
        meta_extra={"floors": ["known_malicious_label"]},
    )
    verdict, reasons = guard_decision(labelled)
    assert verdict == "block"
    assert "A locally imported reputation label was applied" in reasons
