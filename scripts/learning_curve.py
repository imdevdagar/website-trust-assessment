"""Builds the train-only learning curve for the hybrid models.

The curve is computed with domain-grouped cross-validation inside the training split.
The validation and test splits are never scored, so the paper's single-use test claim
remains true. Each point is the pooled out-of-fold AUROC/AUPRC over repeated grouped
folds; whole domains are subsampled per class, never individual samples.

Usage:
    PYTHONPATH=. python scripts/learning_curve.py \
        --dataset data/datasets/feed_v2/dataset.jsonl \
        --out data/research/learning_curve.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from website_trust_assessment.research.dataset import load_dataset
from website_trust_assessment.research.training import learning_curve

FRACTIONS = (0.1, 0.25, 0.5, 0.75, 1.0)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--group", default="hybrid")
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--repeats", type=int, default=20, help="logistic repeats")
    parser.add_argument("--hgb-repeats", type=int, default=10)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--anchor-run", type=Path, default=None)
    args = parser.parse_args()

    rows, meta = load_dataset(args.dataset)
    train = [row for row in rows if row["split"] == "train"]
    if not train:
        raise SystemExit("dataset has no training rows")
    labels = [int(row["target"]) for row in train]

    payload = {
        "dataset": str(args.dataset),
        "dataset_sha256": _sha256(args.dataset),
        "feature_schema_version": meta.get("feature_schema_version"),
        "train": {
            "samples": len(train),
            "domains": len({row["domain"] for row in train}),
            "positives": sum(labels),
        },
        "fractions": list(FRACTIONS),
        "curves": {},
        "note": (
            "Train-only: domain-grouped cross-validation inside the training split; "
            "validation and test are never scored. Fractions are shares of the domains "
            "available to a fold, and 1.0 reproduces ordinary grouped cross-validation."
        ),
    }
    for model, repeats in (("logistic", args.repeats), ("hgb", args.hgb_repeats)):
        payload["curves"][model] = learning_curve(
            train,
            group=args.group,
            model=model,
            fractions=FRACTIONS,
            repeats=repeats,
            folds=args.folds,
            seed=args.seed,
        )

    if args.anchor_run and args.anchor_run.exists():
        run = json.loads(args.anchor_run.read_text(encoding="utf-8"))
        anchor = run["groups"][args.group]["models"]["logistic_regression"]["cv"]["mean"]
        full = payload["curves"]["logistic"]["points"][-1]["auroc"]["mean"]
        payload["anchor"] = {
            "run": str(args.anchor_run),
            "cv_mean_roc_auc": anchor["roc_auc"],
            "learning_curve_full_auroc": full,
            "difference": round(float(full) - float(anchor["roc_auc"]), 6),
        }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline=""
    )

    for model, curve in payload["curves"].items():
        print(f"{model}: {curve['repeats']} repeats x {curve['folds']} folds")
        for point in curve["points"]:
            auroc = point["auroc"]
            auprc = point["average_precision"]
            print(
                f"  {point['fraction']:.2f}  n~{point['n_train_domains_mean']:6.1f} dom  "
                f"AUROC {auroc['mean']:.3f} [{auroc['ci'][0]:.3f}, {auroc['ci'][1]:.3f}]  "
                f"AUPRC {auprc['mean']:.3f}"
            )
    if "anchor" in payload:
        print("anchor:", payload["anchor"])
    print(f"Report: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
