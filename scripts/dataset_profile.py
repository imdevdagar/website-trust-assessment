"""Profiles a built dataset: class split, HTTPS prevalence, padlock-only test baselines, and the
shipped rule engine's escalation behaviour over every labelled sample.

The engine numbers are reported over dataset rows rather than over raw crawl output so the figure
quoted in the paper is reproducible from the published artifact with one command.

Usage:
    PYTHONPATH=. python scripts/dataset_profile.py \
        --dataset data/datasets/feed_v2/dataset.jsonl \
        --out data/research/profile_feed_v2.json
"""

from __future__ import annotations

import argparse
import glob
import json
import random
from collections import Counter
from pathlib import Path
from website_trust_assessment.research.metrics import roc_auc
from typing import Any

# overall_rule_risk is stored normalised to 0-1, so the bands are fractions of that scale.
BAND_EDGES = (("medium", 0.25), ("high", 0.50), ("critical", 0.75))


def band(risk: float) -> str:
    level = "low"
    for name, edge in BAND_EDGES:
        if risk >= edge:
            level = name
    return level


def _auroc(items: list[dict[str, Any]], score) -> float | None:
    positives = [score(r) for r in items if int(r["target"]) == 1]
    negatives = [score(r) for r in items if int(r["target"]) == 0]
    if not positives or not negatives:
        return None
    pairs = sum((p > n) + 0.5 * (p == n) for p in positives for n in negatives)
    return pairs / (len(positives) * len(negatives))


def _f1(items: list[dict[str, Any]], predict) -> float:
    tp = sum(1 for r in items if predict(r) and int(r["target"]) == 1)
    fp = sum(1 for r in items if predict(r) and int(r["target"]) == 0)
    fn = sum(1 for r in items if not predict(r) and int(r["target"]) == 1)
    return 2 * tp / (2 * tp + fp + fn) if tp else 0.0


def _percentile(values: list[float]) -> list[float]:
    ordered = sorted(values)
    low = ordered[int(0.025 * len(ordered))]
    high = ordered[min(int(0.975 * len(ordered)), len(ordered) - 1)]
    return [round(low, 3), round(high, 3)]


def transport_rule_baselines(
    rows: list[dict[str, Any]], resamples: int = 1000, seed: int = 42
) -> dict[str, Any]:
    """Padlock-only rules on the untouched test split.

    The HTTPS-only rule is the baseline pre-registered in the research plan; the trusted-chain rule is
    a descriptive companion. Scores are binary, so ties are handled explicitly in the AUC.
    """
    test = [r for r in rows if r["split"] == "test"]
    if not test:
        return {}
    by_domain: dict[str, list[dict[str, Any]]] = {}
    for row in test:
        by_domain.setdefault(row["domain"], []).append(row)
    domains = sorted(by_domain)

    def https(row: dict[str, Any]) -> float:
        return float(row["features"]["url_https"])

    def trusted(row: dict[str, Any]) -> float:
        return float(row["features"]["tls_trusted"])

    rules = {
        "https_only": (
            lambda r: 1 - https(r),
            lambda r: https(r) < 1,
        ),
        "https_and_trusted_chain": (
            lambda r: 1 - min(https(r), trusted(r)),
            lambda r: not (https(r) >= 1 and trusted(r) >= 1),
        ),
    }
    rng = random.Random(seed)
    out: dict[str, Any] = {
        "split": "test",
        "bootstrap": {
            "resamples": resamples,
            "unit": "registrable domain",
            "seed": seed,
            "interval": "percentile 95%",
        },
        "rules": {},
    }
    for name, (score, predict) in rules.items():
        auroc = _auroc(test, score)
        f1 = _f1(test, predict)
        auc_resamples: list[float] = []
        f1_resamples: list[float] = []
        for _ in range(resamples):
            sample = [
                row for domain in (rng.choice(domains) for _ in domains) for row in by_domain[domain]
            ]
            resampled_auc = _auroc(sample, score)
            if resampled_auc is not None:
                auc_resamples.append(resampled_auc)
            f1_resamples.append(_f1(sample, predict))
        tp = sum(1 for r in test if predict(r) and int(r["target"]) == 1)
        fp = sum(1 for r in test if predict(r) and int(r["target"]) == 0)
        fn = sum(1 for r in test if not predict(r) and int(r["target"]) == 1)
        tn = sum(1 for r in test if not predict(r) and int(r["target"]) == 0)
        out["rules"][name] = {
            "n": len(test),
            "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
            "auroc": round(auroc, 3) if auroc is not None else None,
            "auroc_ci": _percentile(auc_resamples),
            "precision": round(tp / (tp + fp), 3) if tp + fp else None,
            "recall": round(tp / (tp + fn), 3) if tp + fn else None,
            "f1": round(f1, 3),
            "f1_ci": _percentile(f1_resamples),
        }
    out["note"] = (
        "https_only is the pre-registered padlock baseline; https_and_trusted_chain is descriptive and "
        "was not pre-registered. Both are fixed rules, not trained models."
    )
    return out


def profile(path: Path) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))

    out: dict[str, Any] = {
        "dataset": str(path),
        "samples": len(rows),
        "domains": len({r["domain"] for r in rows}),
        "labels": dict(Counter(str(r["label"]) for r in rows)),
        "splits": {
            split: dict(Counter(str(r["label"]) for r in rows if r["split"] == split))
            for split in ("train", "val", "test")
        },
    }

    for scope, subset in (
        ("all", rows),
        ("malicious", [r for r in rows if int(r["target"]) == 1]),
        ("benign", [r for r in rows if int(r["target"]) == 0]),
    ):
        if not subset:
            continue
        risks = [float(r["features"]["overall_rule_risk"]) for r in subset]
        bands = Counter(band(x) for x in risks)
        escalated = bands["high"] + bands["critical"]
        out[scope] = {
            "n": len(subset),
            "https_share": round(
                sum(1 for r in subset if float(r["features"]["url_https"]) >= 1) / len(subset), 4
            ),
            "tls_trusted_share": round(
                sum(1 for r in subset if float(r["features"]["tls_trusted"]) >= 1) / len(subset), 4
            ),
            "rule_bands": {k: bands.get(k, 0) for k in ("low", "medium", "high", "critical")},
            "recall_at_medium_or_above": round((len(subset) - bands["low"]) / len(subset), 4),
            "recall_at_high_or_critical": round(escalated / len(subset), 4),
            "mean_rule_risk": round(sum(risks) / len(risks), 4),
            "max_rule_risk": round(max(risks), 4),
        }

    positives = out["malicious"]["n"]
    positive_bands = out["malicious"]["rule_bands"]
    out["rule_engine_escalation"] = {
        "positives": positives,
        "missed": positives - positive_bands["high"] - positive_bands["critical"],
        "false_alarms_on_benign": out["benign"]["rule_bands"]["high"] + out["benign"]["rule_bands"]["critical"]
        if "benign" in out
        else 0,
    }
    # The same score is also given a discrimination reading. Split-level AUROC is noisy at these
    # sample sizes, so the full labelled set is the number the paper quotes.
    out["rule_engine_auc"] = {
        "all_labelled": round(
            roc_auc([int(r["target"]) for r in rows], [float(r["features"]["overall_rule_risk"]) for r in rows]), 3
        ),
        **{
            split: round(
                roc_auc(
                    [int(r["target"]) for r in rows if r["split"] == split],
                    [float(r["features"]["overall_rule_risk"]) for r in rows if r["split"] == split],
                ),
                3,
            )
            for split in ("train", "val", "test")
        },
    }
    out["transport_rule_baselines"] = transport_rule_baselines(rows)
    return out


INJECTION_CODES = ("hidden_prompt_injection", "hidden_iframe")


def injection_surface(rows: list[dict[str, Any]], assessment_paths: list[str]) -> dict[str, Any]:
    """Natural prevalence of the hidden-text surface across everything that was crawled, not only
    the test split. Counts occurrences and distinct domains; it says nothing about attack success."""
    positive_domains = {r["domain"] for r in rows if int(r["target"]) == 1}
    assessed = {r["domain"] for r in rows}
    seen: dict[str, set[str]] = {code: set() for code in INJECTION_CODES}
    occurrences = {code: 0 for code in INJECTION_CODES}
    positives_hit: dict[str, set[str]] = {code: set() for code in INJECTION_CODES}
    n_assessments = 0
    for pattern in assessment_paths:
        for path in sorted(glob.glob(pattern)):
            with Path(path).open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    domain = row.get("domain")
                    if domain not in assessed:
                        continue
                    n_assessments += 1
                    codes = [str(item.get("code", "")) for item in row.get("evidence", []) or []]
                    for code in INJECTION_CODES:
                        hits = sum(1 for c in codes if c == code)
                        if hits:
                            occurrences[code] += hits
                            seen[code].add(domain)
                            if domain in positive_domains:
                                positives_hit[code].add(domain)
    return {
        "assessments_in_dataset_scope": n_assessments,
        "dataset_domains": len(assessed),
        "codes": {
            code: {
                "occurrences": occurrences[code],
                "domains": len(seen[code]),
                "malicious_domains": len(positives_hit[code]),
                "share_of_labelled_positives": round(len(positives_hit[code]) / max(len(positive_domains), 1), 4),
            }
            for code in INJECTION_CODES
        },
        "note": "prevalence of the surface only; detection and attack-success claims come from the controlled set",
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--assessments", nargs="*", default=[], help="export jsonl paths or globs")
    args = ap.parse_args()

    data = profile(args.dataset)
    if args.assessments:
        rows = [
            json.loads(line)
            for line in args.dataset.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        data["injection_surface"] = injection_surface(rows, args.assessments)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="")

    for scope in ("all", "malicious", "benign"):
        d = data.get(scope)
        if d:
            print(
                f"{scope:9s} n={d['n']:4d} https={d['https_share']:.3f} "
                f"bands={d['rule_bands']} recall>=medium={d['recall_at_medium_or_above']:.3f} "
                f"recall>=high={d['recall_at_high_or_critical']:.3f} mean={d['mean_rule_risk']:.3f}"
            )
    print(f"Report: {data['samples']} samples over {data['domains']} domains -> {args.out}")
    print("engine AUROC:", data["rule_engine_auc"])
    if "transport_rule_baselines" in data:
        print(
            "transport rules:",
            {name: (rule["auroc"], rule["f1"]) for name, rule in data["transport_rule_baselines"]["rules"].items()},
        )
    if "injection_surface" in data:
        print("injection surface:", data["injection_surface"]["codes"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
