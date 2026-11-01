"""Extract the feed_v3 primary comparison from training runs and place it beside feed_v2.

Reads run.json artifacts only. The primary comparison is the ``signals`` feature group against
``url`` on domain-grouped test AUROC and AUPRC; the hybrid and HistGradientBoosting results are
reported as secondary evidence.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GROUPS = ("url", "signals", "rule", "hybrid")
MODELS = ("logistic_regression", "hist_gradient_boosting")
METRICS = ("roc_auc", "average_precision", "ece", "brier", "accuracy", "precision", "recall", "f1")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _run_summary(path: Path) -> dict:
    run = _load(path)
    first_group = next(iter(run["groups"].values()))
    summary = {
        "run_id": run.get("run_id"),
        "created_at": run.get("created_at"),
        "seed": run.get("seed"),
        "dataset": run.get("dataset", {}),
        "protocol": run.get("protocol", {}),
        "splits": first_group.get("splits", {}),
        "groups": {},
    }
    for group in GROUPS:
        entry = run["groups"].get(group)
        if not entry:
            continue
        models = {}
        for name in MODELS:
            model = entry["models"].get(name)
            if not model:
                continue
            test = model.get("test", {})
            models[name] = {
                **{metric: test.get(metric) for metric in METRICS},
                "n": test.get("n"),
                "positives": test.get("positives"),
                "negatives": test.get("negatives"),
                "threshold": test.get("threshold"),
                "confusion": test.get("confusion"),
                "bootstrap": model.get("bootstrap", {}),
            }
        summary["groups"][group] = {
            "feature_count": entry.get("feature_count"),
            "models": models,
        }
    return summary


def _delta(new: float | None, old: float | None) -> float | None:
    if new is None or old is None:
        return None
    return round(new - old, 6)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--feed-v2", default="data/research/runs/feed_v2/run.json")
    parser.add_argument("--feed-v3", default="data/research/runs/feed_v3/run.json")
    parser.add_argument("--sensitivity", default="data/research/runs/feed_v3_s43/run.json")
    parser.add_argument("--out", default="data/research/feed_v3_comparison.json")
    args = parser.parse_args(argv)

    runs = {"feed_v2": _run_summary(ROOT / args.feed_v2)}
    v3_path = ROOT / args.feed_v3
    if not v3_path.exists():
        raise SystemExit(f"feed_v3 run not found: {v3_path}")
    runs["feed_v3"] = _run_summary(v3_path)
    sens_path = ROOT / args.sensitivity
    if sens_path.exists():
        runs["feed_v3_s43"] = _run_summary(sens_path)

    comparison: dict = {"runs": runs, "primary": {}}
    for model_name in MODELS:
        v2 = runs["feed_v2"]["groups"].get("signals", {}).get("models", {}).get(model_name, {})
        v3 = runs["feed_v3"]["groups"].get("signals", {}).get("models", {}).get(model_name, {})
        url3 = runs["feed_v3"]["groups"].get("url", {}).get("models", {}).get(model_name, {})
        comparison["primary"][model_name] = {
            "feed_v2_signals": {m: v2.get(m) for m in ("roc_auc", "average_precision")},
            "feed_v3_signals": {m: v3.get(m) for m in ("roc_auc", "average_precision")},
            "feed_v3_url": {m: url3.get(m) for m in ("roc_auc", "average_precision")},
            "signals_minus_url_feed_v3": {
                "roc_auc": _delta(v3.get("roc_auc"), url3.get("roc_auc")),
                "average_precision": _delta(
                    v3.get("average_precision"), url3.get("average_precision")
                ),
            },
        }

    out = ROOT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(comparison, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    for run_name, run in runs.items():
        splits = run["splits"]
        print(
            f"{run_name}: train={splits.get('train', {}).get('samples')} "
            f"val={splits.get('val', {}).get('samples')} test={splits.get('test', {}).get('samples')}"
        )
        for group in ("url", "signals", "hybrid"):
            entry = run["groups"].get(group, {}).get("models", {}).get("logistic_regression", {})
            print(
                f"  {group:<8} logistic AUROC={entry.get('roc_auc')} "
                f"AUPRC={entry.get('average_precision')} ECE={entry.get('ece')}"
            )
    print(f"Report: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
