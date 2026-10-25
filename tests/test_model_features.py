from __future__ import annotations

import math

from website_trust_assessment.scoring.model import (
    FEATURE_GROUPS,
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    LEAKAGE_EVIDENCE_CODES,
    feature_dict,
    leakage_reasons,
    url_features,
)
from website_trust_assessment.schemas import Dimension, Evidence, Severity

from .factories import make_assessment


def test_feature_extraction_uses_actual_meta_paths() -> None:
    assessment = make_assessment("actual-meta.com", malicious=True)
    features = feature_dict(assessment)
    assert features["page_available"] == 1.0
    assert features["http_ok"] == 1.0
    assert features["has_login_form"] == 1.0
    assert features["has_payment_form"] == 1.0
    assert features["page_password_fields"] == 1.0
    assert math.isclose(features["domain_age_log"], math.log1p(3), rel_tol=1e-9)
    assert features["domain_age_unknown"] == 0.0
    assert features["tracker_total_log"] > 0


def test_missing_age_is_explicit() -> None:
    assessment = make_assessment("no-age.com")
    assessment.meta["notes"].pop("domain_intel")
    features = feature_dict(assessment)
    assert features["domain_age_unknown"] == 1.0
    assert features["domain_age_log"] == 0.0


def test_url_features_handle_obfuscation() -> None:
    features = url_features(
        "https://xn--pypal-4ve.example.co.uk/login?next=http%3A%2F%2Fevil.example"
    )
    assert features["url_https"] == 1.0
    assert features["url_has_punycode"] == 1.0
    assert features["url_encoded_redirect"] == 1.0
    assert features["url_risky_tokens"] >= 1.0
    assert features["url_host_labels"] == 4.0
    assert features["url_path_depth"] == 1.0
    ip_features = url_features("http://192.0.2.10/")
    assert ip_features["url_is_ip"] == 1.0
    assert ip_features["url_https"] == 0.0


def test_feature_groups_are_versioned_and_do_not_contain_label_flags() -> None:
    assert FEATURE_SCHEMA_VERSION == 3
    assert set(FEATURE_GROUPS["url"]).issubset(set(FEATURE_GROUPS["hybrid"]))
    assert set(FEATURE_GROUPS["rule"]).issubset(set(FEATURE_GROUPS["hybrid"]))
    assert "overall_rule_risk" not in FEATURE_GROUPS["url"]
    assert "url_https" in FEATURE_GROUPS["url"]
    assert "flag_known_malicious_label" not in FEATURE_NAMES
    assert "flag_malicious_infrastructure_overlap" not in FEATURE_NAMES
    for code in LEAKAGE_EVIDENCE_CODES:
        assert f"flag_{code}" not in FEATURE_NAMES
    for code in (
        "guaranteed_return_lure",
        "advance_fee_lure",
        "direct_upi_payment",
        "direct_bank_transfer",
        "messaging_only_contact",
        "ocr_guaranteed_return",
        "ocr_upi_payment",
    ):
        assert f"flag_{code}" in FEATURE_NAMES


def test_leakage_detection_covers_evidence_floors_and_runtime_labels() -> None:
    evidence = Evidence(
        dimension=Dimension.SECURITY,
        code="known_malicious_label",
        title="Known label",
        detail="Synthetic label evidence.",
        severity=Severity.CRITICAL,
        risk_points=50,
        confidence=1.0,
        source="synthetic",
    )
    assessment = make_assessment(
        "leaky.com",
        malicious=True,
        extra_evidence=[evidence],
        meta_extra={"floors": ["known_malicious_label"]},
    )
    assessment.meta["notes"]["infrastructure"]["known_label"] = "malicious"
    reasons = leakage_reasons(assessment)
    assert "evidence:known_malicious_label" in reasons
    assert "floor:known_malicious_label" in reasons
    assert "runtime_domain_label" in reasons


def test_feature_vectors_are_finite_and_group_specific() -> None:
    assessment = make_assessment("vectors.com")
    url_only = feature_dict(assessment, "url")
    rule_only = feature_dict(assessment, "rule")
    hybrid = feature_dict(assessment, "hybrid")
    assert set(url_only) == set(FEATURE_GROUPS["url"])
    assert set(rule_only) == set(FEATURE_GROUPS["rule"])
    assert set(hybrid) == set(FEATURE_NAMES)
    assert all(math.isfinite(value) for value in hybrid.values())
