"""Synthetic assessments for tests. No network access is used."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from trustlens.schemas import (
    Action,
    Assessment,
    Dimension,
    DimensionAssessment,
    Evidence,
    RiskLevel,
    Severity,
)


def make_assessment(
    domain: str,
    *,
    malicious: bool = False,
    risk: float | None = None,
    action: Action = Action.BROWSE,
    created_at: datetime | None = None,
    minutes_ago: int = 0,
    url: str | None = None,
    extra_evidence: list[Evidence] | None = None,
    meta_extra: dict[str, Any] | None = None,
) -> Assessment:
    if risk is None:
        risk = 78.0 if malicious else 8.0
    level = RiskLevel.HIGH if risk >= 50 else RiskLevel.LOW
    confidence = 0.8
    evidence_items = [
        Evidence(
            dimension=Dimension.SECURITY,
            code="unencrypted_http" if malicious else "official_domain",
            title="Synthetic adverse signal" if malicious else "Synthetic positive signal",
            detail="Synthetic observation used by the test suite.",
            severity=Severity.HIGH if malicious else Severity.INFO,
            risk_points=30.0 if malicious else 0.0,
            trust_points=0.0 if malicious else 2.0,
            confidence=confidence,
            source="synthetic",
        )
    ]
    if extra_evidence:
        evidence_items.extend(extra_evidence)
    dimensions = {}
    for dimension in Dimension:
        dimensions[dimension.value] = DimensionAssessment(
            dimension=dimension,
            label=dimension.value,
            risk_score=risk,
            risk_level=level,
            confidence=confidence,
            coverage=0.8,
            abstained=False,
            summary="Synthetic dimension.",
        )
    created = created_at or (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago))
    meta: dict[str, Any] = {
        "engine_version": "test",
        "http_status": 200,
        "page_fingerprint": {
            "status": 200,
            "forms": 2 if malicious else 0,
            "password_fields": 1 if malicious else 0,
            "links": 8,
            "scripts": 4,
            "iframes": 0,
            "images": 2,
            "network_requests": 6,
            "cookies": 1,
            "hidden_elements": 1 if malicious else 0,
            "screenshot": True,
        },
        "notes": {
            "has_login_form": malicious,
            "has_payment_form": malicious,
            "official_domain": not malicious,
            "trust_links": {
                "privacy": not malicious,
                "terms": not malicious,
                "contact": True,
            },
            "trackers": {
                "total": 6 if malicious else 1,
                "third_party": 4 if malicious else 0,
            },
            "prompt_injection": {"detected": False},
            "text_obfuscation": {"zero_width": 0},
            "ocr": {"image_heavy": False},
            "domain_intel": {
                "age_days": 3 if malicious else 4_000,
                "tls_trusted": not malicious,
                "tls_days_remaining": 90,
                "has_mx": True,
                "spf": True,
                "dmarc": not malicious,
            },
            "infrastructure": {"known_label": None, "neighbor_count": 0, "matched_on": []},
        },
        "redirected": False,
        "floors": [],
    }
    if meta_extra:
        for key, value in meta_extra.items():
            if isinstance(value, dict) and isinstance(meta.get(key), dict):
                meta[key] = {**meta[key], **value}
            else:
                meta[key] = value
    final_url = url or f"https://{domain}/"
    return Assessment(
        url=final_url,
        normalized_url=final_url,
        final_url=final_url,
        domain=domain,
        action=action,
        overall_risk=risk,
        overall_level=level,
        confidence=confidence,
        recommendation="Synthetic recommendation.",
        headline="Synthetic assessment.",
        rationale="Synthetic rationale.",
        dimensions=dimensions,
        evidence=evidence_items,
        missing_evidence=[],
        coverage={dimension.value: 0.8 for dimension in Dimension},
        meta=meta,
        created_at=created,
    )
