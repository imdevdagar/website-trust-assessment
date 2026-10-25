"""Feature export for offline baseline and learned-model research.

The API deliberately serves the transparent rule scorer. Learned models are
trained and evaluated offline against versioned feature exports so that a paper
can report a like-for-like comparison without making the live product opaque.

Feature groups make the comparison meaningful:

* ``url``     - lexical URL features only; computable before any crawl.
* ``signals`` - URL features plus page, domain, and extractor observations.
* ``rule``    - outputs of the transparent rule engine.
* ``hybrid``  - every feature above.

Reputation labels and the observations derived from them are *not* features.
They are recorded by :func:`leakage_reasons` so dataset builders can exclude
contaminated assessments instead of silently learning their own labels.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

from ..schemas import Assessment, Dimension
from .rules import DIMENSIONS

FEATURE_SCHEMA_VERSION = 3

LEAKAGE_EVIDENCE_CODES = frozenset(
    {
        "known_malicious_label",
        "known_suspicious_label",
        "malicious_infrastructure_overlap",
    }
)

KEY_EVIDENCE_FLAGS = (
    "unencrypted_http",
    "ip_literal_host",
    "punycode_host",
    "suspicious_tld",
    "brand_subdomain_impersonation",
    "brand_action_domain",
    "typosquatting_domain",
    "password_form_http",
    "cross_origin_login",
    "tls_certificate_invalid",
    "hidden_prompt_injection",
    "executable_download",
    "remote_access_request",
    "gift_card_payment",
    "seed_phrase_request",
    "no_consent_controls",
    "tracker_session_replay",
    "privacy_policy_missing",
    "free_subdomain_host",
    "file_host_destination",
    "cross_domain_redirect",
    "guaranteed_return_lure",
    "advance_fee_lure",
    "direct_upi_payment",
    "direct_bank_transfer",
    "messaging_only_contact",
    "ocr_guaranteed_return",
    "ocr_upi_payment",
)
SEVERITY_FEATURES = ("low", "medium", "high", "critical")

_RISKY_URL_TOKEN = re.compile(
    r"kyc|verif|login|sign[-\s]?in|secure|account|update|wallet|airdrop|claim|"
    r"prize|gift|bonus|unlock|recover|seed|winner|support",
    re.IGNORECASE,
)

URL_FEATURE_NAMES = (
    "url_https",
    "url_length_log",
    "url_host_length_log",
    "url_path_length_log",
    "url_query_length_log",
    "url_path_depth",
    "url_query_params",
    "url_host_labels",
    "url_hyphens",
    "url_dots",
    "url_digits_log",
    "url_digit_ratio",
    "url_host_digit_ratio",
    "url_special_log",
    "url_host_entropy",
    "url_has_port",
    "url_has_at",
    "url_has_punycode",
    "url_is_ip",
    "url_risky_tokens",
    "url_encoded_redirect",
)

OBSERVATION_FEATURE_NAMES = (
    "page_available",
    "http_ok",
    "redirected",
    "has_login_form",
    "has_payment_form",
    "page_forms_log",
    "page_password_fields",
    "page_links_log",
    "page_scripts_log",
    "page_iframes",
    "page_images_log",
    "page_network_log",
    "page_cookies_log",
    "page_hidden_elements_log",
    "domain_age_log",
    "domain_age_unknown",
    "tls_trusted",
    "tls_days_remaining_log",
    "has_mx",
    "spf_record",
    "dmarc_record",
    "tracker_total_log",
    "tracker_third_party_log",
    "trust_link_privacy",
    "trust_link_terms",
    "trust_link_contact",
    "official_domain",
    "prompt_injection_detected",
    "text_zero_width_log",
    "ocr_image_heavy",
    "screenshot_available",
)

RULE_FEATURE_NAMES = (
    "overall_rule_risk",
    "overall_confidence",
    "evidence_count_log",
    "missing_evidence_count",
    *(
        f"{dimension.value}_{suffix}"
        for dimension in DIMENSIONS
        for suffix in (
            "score",
            "confidence",
            "coverage",
            "abstained",
            "evidence_count",
            "risk_points",
            "trust_points",
        )
    ),
    *(f"risk_{severity}_count" for severity in SEVERITY_FEATURES),
)

FEATURE_GROUPS: dict[str, tuple[str, ...]] = {
    "url": URL_FEATURE_NAMES,
    "signals": tuple(
        dict.fromkeys(
            (
                *URL_FEATURE_NAMES,
                *OBSERVATION_FEATURE_NAMES,
                *(f"flag_{code}" for code in KEY_EVIDENCE_FLAGS),
            )
        )
    ),
    "rule": RULE_FEATURE_NAMES,
}
FEATURE_GROUPS["hybrid"] = tuple(
    dict.fromkeys(
        (
            *URL_FEATURE_NAMES,
            *OBSERVATION_FEATURE_NAMES,
            *RULE_FEATURE_NAMES,
            *(f"flag_{code}" for code in KEY_EVIDENCE_FLAGS),
        )
    )
)
FEATURE_NAMES = FEATURE_GROUPS["hybrid"]


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for character in text:
        counts[character] = counts.get(character, 0) + 1
    total = float(len(text))
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _number(value: Any, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        number = float(value)
        return number if math.isfinite(number) else default
    return default


def _log1p(value: Any) -> float:
    return math.log1p(max(0.0, _number(value)))


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def url_features(url: str) -> dict[str, float]:
    """Lexical URL features that require no network access."""
    zeros = {name: 0.0 for name in URL_FEATURE_NAMES}
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower().rstrip(".")
    except ValueError:
        return zeros
    path = parts.path or ""
    query = parts.query or ""
    host_labels = [label for label in host.split(".") if label]
    digits = sum(character.isdigit() for character in url)
    host_digits = sum(character.isdigit() for character in host)
    special = sum(character in "=&%?#_~" for character in url)
    try:
        has_port = parts.port is not None
    except ValueError:
        has_port = ":" in parts.netloc.rsplit("@", 1)[-1]
    try:
        query_params = len(parse_qsl(query, keep_blank_values=True, max_num_fields=60))
    except ValueError:
        query_params = query.count("&") + 1 if query else 0
    decoded_query = unquote(query).lower()
    is_ip = False
    try:
        import ipaddress

        ipaddress.ip_address(host.strip("[]"))
        is_ip = True
    except ValueError:
        pass
    return {
        "url_https": 1.0 if parts.scheme.lower() == "https" else 0.0,
        "url_length_log": _log1p(len(url)),
        "url_host_length_log": _log1p(len(host)),
        "url_path_length_log": _log1p(len(path)),
        "url_query_length_log": _log1p(len(query)),
        "url_path_depth": float(len([segment for segment in path.split("/") if segment])),
        "url_query_params": float(min(query_params, 60)),
        "url_host_labels": float(len(host_labels)),
        "url_hyphens": float(host.count("-")),
        "url_dots": float(host.count(".")),
        "url_digits_log": _log1p(digits),
        "url_digit_ratio": digits / max(1, len(url)),
        "url_host_digit_ratio": host_digits / max(1, len(host)),
        "url_special_log": _log1p(special),
        "url_host_entropy": round(_entropy(host), 4),
        "url_has_port": 1.0 if has_port else 0.0,
        "url_has_at": 1.0 if "@" in parts.netloc else 0.0,
        "url_has_punycode": 1.0 if any(label.startswith("xn--") for label in host_labels) else 0.0,
        "url_is_ip": 1.0 if is_ip else 0.0,
        "url_risky_tokens": float(len(_RISKY_URL_TOKEN.findall(path + "?" + query))),
        "url_encoded_redirect": 1.0
        if ("http://" in decoded_query or "https://" in decoded_query)
        else 0.0,
    }


def _evidence_by_dimension(assessment: Assessment) -> dict[Dimension, list]:
    by_dimension: dict[Dimension, list] = {dimension: [] for dimension in DIMENSIONS}
    id_to_dimension = {
        evidence_id: dimension
        for dimension, dimension_result in assessment.dimensions.items()
        for evidence_id in dimension_result.evidence_ids
    }
    for evidence_item in assessment.evidence:
        raw_dimension = id_to_dimension.get(evidence_item.id, evidence_item.dimension)
        if isinstance(raw_dimension, str):
            try:
                raw_dimension = Dimension(raw_dimension)
            except ValueError:
                continue
        by_dimension.setdefault(raw_dimension, []).append(evidence_item)
    return by_dimension


def _rule_features(assessment: Assessment) -> dict[str, float]:
    by_dimension = _evidence_by_dimension(assessment)
    severity_counts = {severity: 0 for severity in SEVERITY_FEATURES}
    for item in assessment.evidence:
        if item.risk_points > 0 and item.severity.value in severity_counts:
            severity_counts[item.severity.value] += 1
    values: dict[str, float] = {
        "overall_rule_risk": assessment.overall_risk / 100.0,
        "overall_confidence": assessment.confidence,
        "evidence_count_log": _log1p(len(assessment.evidence)),
        "missing_evidence_count": float(len(assessment.missing_evidence)),
    }
    for dimension in DIMENSIONS:
        result = assessment.dimensions.get(dimension.value)
        prefix = dimension.value
        if result is None:
            for suffix in (
                "score",
                "confidence",
                "coverage",
                "abstained",
                "evidence_count",
                "risk_points",
                "trust_points",
            ):
                values[f"{prefix}_{suffix}"] = 0.0
            continue
        items = by_dimension.get(dimension, [])
        values[f"{prefix}_score"] = result.risk_score / 100.0
        values[f"{prefix}_confidence"] = result.confidence
        values[f"{prefix}_coverage"] = result.coverage
        values[f"{prefix}_abstained"] = 1.0 if result.abstained else 0.0
        values[f"{prefix}_evidence_count"] = float(len(items))
        values[f"{prefix}_risk_points"] = min(
            1.0, sum(item.risk_points * item.confidence for item in items) / 100.0
        )
        values[f"{prefix}_trust_points"] = min(
            1.0, sum(item.trust_points * item.confidence for item in items) / 100.0
        )
    for severity, count in severity_counts.items():
        values[f"risk_{severity}_count"] = float(count)
    return values


def _observation_features(assessment: Assessment) -> dict[str, float]:
    meta = _mapping(assessment.meta)
    page = _mapping(meta.get("page_fingerprint"))
    notes = _mapping(meta.get("notes"))
    domain_intel = _mapping(notes.get("domain_intel")) or _mapping(meta.get("domain_intel"))
    trackers = _mapping(notes.get("trackers"))
    trust_links = _mapping(notes.get("trust_links"))
    prompt_injection = _mapping(notes.get("prompt_injection"))
    text_obfuscation = _mapping(notes.get("text_obfuscation"))
    ocr = _mapping(notes.get("ocr"))
    status = page.get("status", meta.get("http_status"))
    try:
        http_ok = 200 <= int(status) < 300
    except (TypeError, ValueError):
        http_ok = False
    age_days = domain_intel.get("age_days")
    has_age = isinstance(age_days, (int, float)) and math.isfinite(float(age_days))
    password_fields = _number(page.get("password_fields"))
    return {
        "page_available": 1.0 if page else 0.0,
        "http_ok": 1.0 if http_ok else 0.0,
        "redirected": 1.0 if meta.get("redirected") else 0.0,
        "has_login_form": 1.0
        if notes.get("has_login_form") or password_fields > 0
        else 0.0,
        "has_payment_form": 1.0 if notes.get("has_payment_form") else 0.0,
        "page_forms_log": _log1p(page.get("forms")),
        "page_password_fields": password_fields,
        "page_links_log": _log1p(page.get("links")),
        "page_scripts_log": _log1p(page.get("scripts")),
        "page_iframes": _number(page.get("iframes")),
        "page_images_log": _log1p(page.get("images")),
        "page_network_log": _log1p(page.get("network_requests")),
        "page_cookies_log": _log1p(page.get("cookies")),
        "page_hidden_elements_log": _log1p(page.get("hidden_elements")),
        "domain_age_log": math.log1p(max(0.0, float(age_days))) if has_age else 0.0,
        "domain_age_unknown": 0.0 if has_age else 1.0,
        "tls_trusted": 1.0 if domain_intel.get("tls_trusted") else 0.0,
        "tls_days_remaining_log": _log1p(domain_intel.get("tls_days_remaining")),
        "has_mx": 1.0 if domain_intel.get("has_mx") else 0.0,
        "spf_record": 1.0 if domain_intel.get("spf") else 0.0,
        "dmarc_record": 1.0 if domain_intel.get("dmarc") else 0.0,
        "tracker_total_log": _log1p(trackers.get("total")),
        "tracker_third_party_log": _log1p(trackers.get("third_party")),
        "trust_link_privacy": 1.0 if trust_links.get("privacy") else 0.0,
        "trust_link_terms": 1.0 if trust_links.get("terms") else 0.0,
        "trust_link_contact": 1.0 if trust_links.get("contact") else 0.0,
        "official_domain": 1.0 if notes.get("official_domain") else 0.0,
        "prompt_injection_detected": 1.0 if prompt_injection.get("detected") else 0.0,
        "text_zero_width_log": _log1p(text_obfuscation.get("zero_width")),
        "ocr_image_heavy": 1.0 if ocr.get("image_heavy") else 0.0,
        "screenshot_available": 1.0
        if meta.get("screenshot_file") or page.get("screenshot")
        else 0.0,
    }


def feature_dict(assessment: Assessment, group: str = "hybrid") -> dict[str, float]:
    """Return the requested versioned feature vector as a name -> value map."""
    if group not in FEATURE_GROUPS:
        raise ValueError(f"unknown feature group: {group}")
    values: dict[str, float] = {}
    values.update(url_features(assessment.final_url or assessment.url))
    values.update(_observation_features(assessment))
    values.update(_rule_features(assessment))
    codes = {item.code for item in assessment.evidence}
    for code in KEY_EVIDENCE_FLAGS:
        values[f"flag_{code}"] = 1.0 if code in codes else 0.0
    return {name: float(values.get(name, 0.0)) for name in FEATURE_GROUPS[group]}


def feature_vector(assessment: Assessment, group: str = "hybrid") -> list[float]:
    values = feature_dict(assessment, group)
    return [values[name] for name in FEATURE_GROUPS[group]]


def leakage_reasons(assessment: Assessment) -> list[str]:
    """Describe signals that would leak a known reputation label into training."""
    reasons: set[str] = set()
    codes = {item.code for item in assessment.evidence}
    for code in sorted(LEAKAGE_EVIDENCE_CODES & codes):
        reasons.add(f"evidence:{code}")
    meta = _mapping(assessment.meta)
    for floor in meta.get("floors") or []:
        if str(floor).startswith("known_"):
            reasons.add(f"floor:{floor}")
    notes = _mapping(meta.get("notes"))
    infrastructure = _mapping(notes.get("infrastructure"))
    if infrastructure.get("known_label"):
        reasons.add("runtime_domain_label")
    if infrastructure.get("neighbor_count") or infrastructure.get("matched_on"):
        reasons.add("labeled_infrastructure_neighbor")
    return sorted(reasons)


@dataclass(frozen=True)
class LinearModel:
    feature_names: tuple[str, ...]
    coefficients: tuple[float, ...]
    intercept: float
    metrics: dict[str, Any]
    feature_group: str = "hybrid"
    calibration: dict[str, Any] | None = None
    threshold: float = 0.5

    @classmethod
    def load(cls, path: Path) -> "LinearModel | None":
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            names = tuple(str(name) for name in payload["feature_names"])
            coefficients = tuple(float(value) for value in payload["coefficients"])
            intercept = float(payload["intercept"])
            threshold = float(payload.get("threshold") or 0.5)
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            return None
        if not names or len(names) != len(coefficients):
            return None
        if any(not math.isfinite(value) for value in (*coefficients, intercept)):
            return None
        if not math.isfinite(threshold) or not 0.0 < threshold < 1.0:
            threshold = 0.5
        calibration = payload.get("calibration")
        return cls(
            feature_names=names,
            coefficients=coefficients,
            intercept=intercept,
            metrics=dict(payload.get("metrics") or {}),
            feature_group=str(payload.get("feature_group") or "hybrid"),
            calibration=dict(calibration) if isinstance(calibration, dict) else None,
            threshold=threshold,
        )

    def raw_probability(self, features: dict[str, float]) -> float:
        score = self.intercept + sum(
            coefficient * float(features.get(name, 0.0))
            for name, coefficient in zip(self.feature_names, self.coefficients)
        )
        score = max(-60.0, min(60.0, score))
        return 1.0 / (1.0 + math.exp(-score))

    def probability(self, features: dict[str, float]) -> float:
        value = min(max(self.raw_probability(features), 1e-6), 1.0 - 1e-6)
        calibration = self.calibration or {}
        if calibration.get("fitted"):
            slope = float(calibration.get("slope", 1.0))
            intercept = float(calibration.get("intercept", 0.0))
            if calibration.get("input_transform", "logit") == "logit":
                value = math.log(value / (1.0 - value))
            value = 1.0 / (1.0 + math.exp(-max(-60.0, min(60.0, slope * value + intercept))))
        return round(value, 4)
