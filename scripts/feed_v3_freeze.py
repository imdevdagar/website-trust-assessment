"""Freeze the feed_v3 artifacts a citation depends on, with a SHA-256 manifest.

Large inputs (dataset, exports, model weights) are recorded by digest only; the small JSON/CSV
reports the paper quotes are copied next to the manifest so a cited number can be re-verified
without re-running the crawl.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

COPIES = [
    "data/labels/feed_v3/eval_labels.csv",
    "data/labels/feed_v3/eval_labels.json",
    "data/labels/feed_v3/leakage_check.json",
    "data/labels/feed_v3/provenance.json",
    "data/labels/feed_v3/validation.json",
    "data/labels/feed_v3/topup_selection.json",
    "data/candidates/feed_v3/collection_approval.json",
    "data/candidates/feed_v3/collection_amendment_01.json",
    "data/candidates/feed_v3/collection_outcome.json",
    "data/candidates/feed_v3/collection_checkpoint_complete.json",
    "data/exports/feed_v3/analysis/exclusions.json",
    "data/research/gate_compliance_feed_v3.json",
    "data/research/profile_feed_v3.json",
    "data/research/profile_feed_v3_s43.json",
    "data/research/error_analysis_feed_v3.json",
    "data/research/learning_curve_feed_v3.json",
    "data/research/feed_v3_comparison.json",
]

DIGESTS = [
    "data/datasets/feed_v3/dataset.jsonl",
    "data/datasets/feed_v3/manifest.json",
    "data/datasets/feed_v3_s43/dataset.jsonl",
    "data/research/runs/feed_v3/run.json",
    "data/research/runs/feed_v3/report.md",
    "data/research/runs/feed_v3_s43/run.json",
    "data/research/runs/feed_v3_s43/report.md",
    "models/research/feed_v3/logistic_hybrid.json",
    "models/research/feed_v3/logistic_signals.json",
    "models/research/feed_v3/logistic_url.json",
    "models/research/feed_v3/logistic_rule.json",
]

RUN_COPIES = [
    "data/research/runs/feed_v3/run.json",
    "data/research/runs/feed_v3/report.md",
    "data/research/runs/feed_v3_s43/run.json",
    "data/research/runs/feed_v3_s43/report.md",
]


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out", default="data/datasets/feed_v3/artifacts_snapshot", help="snapshot directory"
    )
    args = parser.parse_args(argv)
    out = ROOT / args.out
    out.mkdir(parents=True, exist_ok=True)

    missing: list[str] = []
    copied: dict[str, str] = {}
    for rel in COPIES + RUN_COPIES:
        src = ROOT / rel
        if not src.exists():
            missing.append(rel)
            continue
        dst = out / rel.removeprefix("data/")
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        copied[rel] = digest(dst)

    digested: dict[str, str] = {}
    for rel in DIGESTS:
        src = ROOT / rel
        if not src.exists():
            missing.append(rel)
            continue
        digested[rel] = digest(src)

    manifest = {
        "dataset": "feed_v3",
        "frozen_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "copied_artifacts": copied,
        "digest_only": digested,
        "missing": sorted(missing),
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", "utf-8")
    print(json.dumps({"copied": len(copied), "digest_only": len(digested), "missing": missing}, indent=2))
    print(f"Snapshot: {out / 'manifest.json'}")
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
