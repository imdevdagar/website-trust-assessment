"""Test-split error analysis for the feed-labeled evaluation.

Reproduces the per-sample probabilities of the stored logistic artifacts, isolates the
false positives and false negatives of each feature group, and classifies every error by
the observable mechanism behind it (page state, TLS, form presence, brand lookalike,
hosting shape) rather than by a hand-written verdict.

Categories are derived from recorded evidence and features only. No label is read from a
feed at scoring time and no label is changed here.

    PYTHONPATH=. python scripts/error_analysis.py \
        --dataset data/datasets/feed_v1/dataset.jsonl \
        --exports data/exports/feed/batch_0*.jsonl data/exports/main/batch_0*.jsonl \
        --out data/research/error_analysis_feed_v1.json
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any, Callable

# The dataset stores overall_rule_risk normalised to 0-1, so the band edges are fractions of that
# scale, not the 0-100 risk points the engine prints in its own report.
RISK_BANDS = {"medium": 0.25, "high": 0.50, "critical": 0.75}


def sigmoid(x: float) -> float:
    """Mirror website_trust_assessment.research.training._sigmoid so scores reproduce the run exactly."""
    x = min(max(x, -60.0), 60.0)
    return 1.0 / (1.0 + math.exp(-x))


def logit(p: float) -> float:
    """Mirror training._logit, whose 1e-6 clip is what makes the artifacts reproducible."""
    p = min(max(p, 1e-6), 1.0 - 1e-6)
    return math.log(p / (1.0 - p))


def risk_level(score: float) -> str:
    if score >= RISK_BANDS["critical"]:
        return "critical"
    if score >= RISK_BANDS["high"]:
        return "high"
    if score >= RISK_BANDS["medium"]:
        return "medium"
    return "low"


def mask_domain(domain: str) -> str:
    """Neutral handle for domains that must not be named in the paper."""
    return f"benign-{hashlib.sha256(domain.encode()).hexdigest()[:10]}"


# --- error categories -----------------------------------------------------------
# Each category is a mechanism the capture can show, not an opinion about the site.

def _f(row: dict[str, Any], name: str) -> float:
    return float(row["features"].get(name) or 0.0)


def _codes(row: dict[str, Any], codes: dict[str, set[str]]) -> set[str]:
    return codes.get(row["assessment_id"], set())


CATEGORIES: list[tuple[str, str, Callable[[dict[str, Any], dict[str, set[str]]], bool]]] = [
    (
        "unreachable_at_capture",
        "the capture did not return a usable page, so most signals are absent",
        lambda r, c: _f(r, "page_available") < 1 or _f(r, "http_ok") < 1,
    ),
    (
        "no_email_configuration",
        "the domain publishes no MX records, typical of short-lived campaign hosts",
        lambda r, c: _f(r, "has_mx") < 1,
    ),
    (
        "domain_age_unknown",
        "registration age could not be resolved, removing the oldest-legitimacy signal",
        lambda r, c: _f(r, "domain_age_unknown") >= 1,
    ),
    (
        "tls_absent_or_invalid",
        "served over plain HTTP or with an invalid certificate chain",
        lambda r, c: _f(r, "url_https") < 1 or _f(r, "flag_tls_certificate_invalid") >= 1,
    ),
    (
        "credential_form_present",
        "a login or password form is on the page",
        lambda r, c: (
            _f(r, "has_login_form") >= 1
            or _f(r, "page_password_fields") > 0
            or _f(r, "flag_password_form_http") >= 1
            or _f(r, "flag_cross_origin_login") >= 1
        ),
    ),
    (
        "payment_or_lure_language",
        "the page asks for a direct transfer, gift cards, UPI, or promises a return",
        lambda r, c: any(
            _f(r, k) >= 1
            for k in (
                "flag_direct_bank_transfer",
                "flag_direct_upi_payment",
                "flag_gift_card_payment",
                "flag_advance_fee_lure",
                "flag_guaranteed_return_lure",
                "flag_ocr_guaranteed_return",
                "flag_ocr_upi_payment",
            )
        ),
    ),
    (
        "hidden_iframe_present",
        "an iframe hidden from the rendered view was in the DOM",
        lambda r, c: "hidden_iframe" in _codes(r, c),
    ),
    (
        "hidden_prompt_injection",
        "hidden text carrying instruction-like content was detected, i.e. the injection surface itself",
        lambda r, c: (
            _f(r, "flag_hidden_prompt_injection") >= 1 or "hidden_prompt_injection" in _codes(r, c)
        ),
    ),
    (
        "established_host_appearance",
        "the capture shows an old, policy-bearing, conventionally structured site — the shape a "
        "payload hosted on a legitimate vendor looks like",
        lambda r, c: (
            "established_domain" in _codes(r, c)
            or "privacy_policy_accessible" in _codes(r, c)
            or (
                _f(r, "flag_privacy_policy_missing") < 1
                and _f(r, "identity_trust_points") >= 2
                and _f(r, "page_links_log") >= 3
            )
        ),
    ),
    (
        "brand_claim_mismatch",
        "the page claims a brand that the registrable domain does not own",
        lambda r, c: (
            "claimed_brand_mismatch" in _codes(r, c)
            or any(
                _f(r, k) >= 1
                for k in (
                    "flag_typosquatting_domain",
                    "flag_brand_subdomain_impersonation",
                    "flag_brand_action_domain",
                )
            )
        ),
    ),
    (
        "third_party_or_tracker_surface",
        "advertising, analytics, session-replay or large third-party footprint on the page",
        lambda r, c: bool(
            {
                "tracker_advertising",
                "tracker_analytics",
                "tracker_session_replay",
                "tracking_cookies",
                "large_third_party_footprint",
            }
            & _codes(r, c)
        )
        or _f(r, "flag_tracker_session_replay") >= 1,
    ),
    (
        "unsafe_delivery_mechanics",
        "mixed content, missing security headers, obfuscated script or unsafe form targets",
        lambda r, c: bool(
            {"mixed_content", "weak_security_headers", "obfuscated_javascript", "unsafe_form_action"}
            & _codes(r, c)
        ),
    ),
    (
        "email_authentication_missing",
        "the domain publishes no SPF/DMARC posture for its mail",
        lambda r, c: "email_auth_missing" in _codes(r, c) or (
            _f(r, "dmarc_record") < 1 and _f(r, "has_mx") >= 1
        ),
    ),
    (
        "unverified_authority_claim",
        "the page invokes an official or authority-adjacent identity the domain cannot verify",
        lambda r, c: "dark_unverified_authority" in _codes(r, c),
    ),
    (
        "remote_access_or_credential_request",
        "the page asks for remote access, a seed phrase or a credential-shaped action",
        lambda r, c: (
            "remote_access_request" in _codes(r, c)
            or _f(r, "flag_remote_access_request") >= 1
            or _f(r, "flag_seed_phrase_request") >= 1
        ),
    ),
    (
        "media_only_page",
        "the visible content is mostly images, so text-based signals cannot fire",
        lambda r, c: _f(r, "ocr_image_heavy") >= 1,
    ),
    (
        "thin_capture_low_evidence",
        "the crawler recorded almost no evidence at all",
        lambda r, c: _f(r, "evidence_count_log") <= 1.1 or _f(r, "missing_evidence_count") >= 3,
    ),
    (
        "file_host_or_payload_path",
        "the URL points at a hosted file or downloadable payload rather than a site",
        lambda r, c: (
            _f(r, "flag_file_host_destination") >= 1
            or _f(r, "flag_executable_download") >= 1
            or _f(r, "url_risky_tokens") > 0
            or "risky_path_keywords" in _codes(r, c)
        ),
    ),
    (
        "shared_or_free_hosting",
        "the site sits on a suspicious TLD, a deep subdomain or an IP-literal host",
        lambda r, c: (
            _f(r, "flag_free_subdomain_host") >= 1
            or _f(r, "flag_suspicious_tld") >= 1
            or _f(r, "flag_ip_literal_host") >= 1
            or "deep_subdomains" in _codes(r, c)
        ),
    ),
    (
        "cross_domain_redirect",
        "the visit left the submitted registrable domain",
        lambda r, c: _f(r, "flag_cross_domain_redirect") >= 1 or "cross_domain_redirect" in _codes(r, c),
    ),
]


def classify(row: dict[str, Any], codes: dict[str, set[str]]) -> list[str]:
    hits = [name for name, _, predicate in CATEGORIES if predicate(row, codes)]
    # The dominant miss mode is a granularity error, not a perception error: a feed reports a URL,
    # the sampling unit is the registrable domain, and the domain that hosts it looks legitimate.
    if int(row["target"]) == 1 and "established_host_appearance" in hits:
        hits.append("feed_reported_url_on_established_host")
    return hits or ["no_single_mechanism"]


def load_evidence(paths: list[str], wanted: set[str]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for pattern in paths:
        for path in sorted(glob.glob(pattern)) if any(ch in pattern for ch in "*?[") else [pattern]:
            with Path(path).open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    aid = row.get("id") or row.get("assessment_id")
                    if aid in wanted:
                        out[aid] = {
                            str(item.get("code", ""))
                            for item in row.get("evidence") or []
                            if isinstance(item, dict)
                        }
    return out


def score_row(artifact: dict[str, Any], row: dict[str, Any]) -> tuple[float, float]:
    """Return (raw probability, calibrated probability) from a stored logistic artifact."""
    names = artifact["feature_names"]
    coefficients = artifact["coefficients"]
    features = row["features"]
    z = float(artifact["intercept"]) + sum(
        c * float(features.get(name) or 0.0) for c, name in zip(coefficients, names)
    )
    raw = sigmoid(z)
    calib = artifact.get("calibration") or {}
    if not calib.get("fitted"):
        return raw, raw
    calibrated = sigmoid(float(calib["slope"]) * logit(raw) + float(calib["intercept"]))
    return raw, calibrated


def top_contributions(artifact: dict[str, Any], row: dict[str, Any], limit: int = 4) -> list[dict]:
    names = artifact["feature_names"]
    coefficients = artifact["coefficients"]
    features = row["features"]
    scored = [
        {
            "feature": name,
            "value": float(features.get(name) or 0.0),
            "contribution": c * float(features.get(name) or 0.0),
        }
        for c, name in zip(coefficients, names)
    ]
    positive = sorted(scored, key=lambda item: -item["contribution"])[:limit]
    negative = sorted(scored, key=lambda item: item["contribution"])[:limit]
    return [item for item in positive + negative if abs(item["contribution"]) > 1e-9]


def metrics(y: list[int], p: list[float], threshold: float) -> dict[str, Any]:
    tp = sum(1 for a, b in zip(y, p) if a == 1 and b >= threshold)
    fp = sum(1 for a, b in zip(y, p) if a == 0 and b >= threshold)
    fn = sum(1 for a, b in zip(y, p) if a == 1 and b < threshold)
    tn = sum(1 for a, b in zip(y, p) if a == 0 and b < threshold)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "n": len(y)}


def analyse_group(
    group: str,
    artifact_path: Path,
    test_rows: list[dict[str, Any]],
    codes: dict[str, set[str]],
) -> dict[str, Any]:
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    threshold = float(artifact.get("threshold") or 0.5)
    y = [int(row["target"]) for row in test_rows]
    raw = []
    cal = []
    per_row: dict[str, tuple[float, float]] = {}
    for row in test_rows:
        a, b = score_row(artifact, row)
        raw.append(a)
        cal.append(b)
        per_row[row["assessment_id"]] = (a, b)
    reported = (artifact.get("metrics") or {}).get("confusion") or {}
    reproduced = metrics(y, cal, threshold)
    errors = []
    for row in test_rows:
        probability = per_row[row["assessment_id"]][1]
        if int(row["target"]) == 1 and probability < threshold:
            kind = "false_negative"
        elif int(row["target"]) == 0 and probability >= threshold:
            kind = "false_positive"
        else:
            continue
        errors.append(
            {
                "kind": kind,
                "domain": row["domain"] if row["target"] == 1 else mask_domain(row["domain"]),
                "domain_named": int(row["target"]) == 1,
                "label": row["label"],
                "probability": round(probability, 4),
                "raw_probability": round(per_row[row["assessment_id"]][0], 4),
                "rule_risk": float(row["features"].get("overall_rule_risk") or 0.0),
                "rule_level": risk_level(float(row["features"].get("overall_rule_risk") or 0.0)),
                "categories": classify(row, codes),
                "top_contributions": top_contributions(artifact, row),
                "url_shape": {
                    "https": bool(row["features"].get("url_https")),
                    "final_domain_matches": (
                        re.sub(r"^www\.", "", str(row.get("final_url") or "").split("//")[-1].split("/")[0])
                        == row["domain"]
                    ),
                },
            }
        )
    counts = Counter(cat for item in errors for cat in item["categories"])
    by_kind = {
        kind: Counter(cat for item in errors if item["kind"] == kind for cat in item["categories"])
        for kind in ("false_positive", "false_negative")
    }
    return {
        "feature_group": group,
        "artifact": str(artifact_path),
        "threshold": threshold,
        "test_samples": len(test_rows),
        "confusion_reproduced": reproduced,
        "confusion_reported_by_artifact": reported,
        "reproduction_matches": {
            key: reproduced.get(key) == reported.get(key) for key in ("tp", "fp", "fn", "tn")
        },
        "error_count": len(errors),
        "category_counts": dict(counts.most_common()),
        "categories_by_kind": {kind: dict(value.most_common()) for kind, value in by_kind.items()},
        "errors": sorted(errors, key=lambda item: (item["kind"], -item["probability"])),
    }


def rule_engine_analysis(test_rows: list[dict[str, Any]], codes: dict[str, set[str]]) -> dict[str, Any]:
    """The shipped rule engine is the baseline, so its misses are the headline errors."""
    errors = []
    for row in test_rows:
        risk = float(row["features"].get("overall_rule_risk") or 0.0)
        level = risk_level(risk)
        escalated = risk >= RISK_BANDS["high"]  # high or critical, where a warning is shown
        if int(row["target"]) == 1 and not escalated:
            kind = "missed_positive"
        elif int(row["target"]) == 0 and escalated:
            kind = "false_alarm"
        else:
            continue
        errors.append(
            {
                "kind": kind,
                "domain": row["domain"] if row["target"] == 1 else mask_domain(row["domain"]),
                "label": row["label"],
                "rule_risk": round(risk, 2),
                "rule_level": level,
                "categories": classify(row, codes),
            }
        )
    positives = [row for row in test_rows if int(row["target"]) == 1]
    missed = sum(1 for item in errors if item["kind"] == "missed_positive")
    by_kind = {
        kind: Counter(cat for item in errors if item["kind"] == kind for cat in item["categories"])
        for kind in ("missed_positive", "false_alarm")
    }
    return {
        "escalation_threshold": "high or critical risk level (normalised score >= 0.50)",
        "positives": len(positives),
        "missed_positive": missed,
        "recall_at_escalation": round(1 - missed / len(positives), 4) if positives else None,
        "error_count": len(errors),
        "categories_by_kind": {kind: dict(value.most_common()) for kind, value in by_kind.items()},
        "errors": sorted(errors, key=lambda item: item["rule_risk"]),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", default="data/datasets/feed_v1/dataset.jsonl")
    parser.add_argument("--models", default="models/research")
    parser.add_argument("--exports", nargs="*", default=["data/exports/feed/batch_*.jsonl", "data/exports/main/batch_*.jsonl"])
    parser.add_argument("--out", default="data/research/error_analysis_feed_v1.json")
    parser.add_argument("--split", default="test")
    args = parser.parse_args()

    rows = [
        json.loads(line)
        for line in Path(args.dataset).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    test_rows = [row for row in rows if row.get("split") == args.split]
    codes = load_evidence(args.exports, {row["assessment_id"] for row in test_rows})

    groups = {}
    for group in ("url", "signals", "rule", "hybrid"):
        artifact_path = Path(args.models) / f"logistic_{group}.json"
        if artifact_path.exists():
            groups[group] = analyse_group(group, artifact_path, test_rows, codes)

    report = {
        "schema_version": 1,
        "dataset": args.dataset,
        "split": args.split,
        "reproduction_ok": all(
            all(value["reproduction_matches"].values()) for value in groups.values()
        ),
        "samples": len(test_rows),
        "positives": sum(1 for row in test_rows if int(row["target"]) == 1),
        "negatives": sum(1 for row in test_rows if int(row["target"]) == 0),
        "category_definitions": {
            **{name: description for name, description, _ in CATEGORIES},
            "feed_reported_url_on_established_host": (
                "derived: a feed reported a URL on this domain while the domain itself presents as an "
                "established site, so the label and the observable unit disagree"
            ),
            "no_single_mechanism": "the capture shows none of the listed mechanisms; the error is not explicable from the recorded evidence",
        },
        "naming_rule": (
            "Domains labelled malicious by feed membership are named; domains carrying the derived "
            "benign label are hashed to a neutral handle, because naming a small legitimate site that "
            "a false alarm flagged adds risk without adding evidence."
        ),
        "rule_engine": rule_engine_analysis(test_rows, codes),
        "models": groups,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="")

    print(f"{args.split} split: {len(test_rows)} samples ({report['positives']}/{report['negatives']})")
    for group, value in groups.items():
        print(
            f"  {group:8s} errors={value['error_count']:3d} "
            f"reproduced={value['reproduction_matches']} "
            f"top={list(value['category_counts'])[:3]}"
        )
    print(f"  rule engine missed_positive={report['rule_engine']['missed_positive']}/"
          f"{report['rule_engine']['positives']} "
          f"top={list(report['rule_engine']['categories_by_kind']['missed_positive'])[:3]}")
    print(f"Report: {out}")
    if not report["reproduction_ok"]:
        print(
            "ERROR: a stored artifact did not reproduce its own recorded test confusion; "
            "the per-sample scores behind these errors are not the scores that were measured.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
