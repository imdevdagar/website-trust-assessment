"""Check every feed_v3 crawl against the gate its candidate row declared.

Positive selected, reserve, top-up, and root-retry exports must only contain scored rows from
candidates marked gated; the batch command could only open them with ``--allow-gated``. Negative
exports must contain no gated row at all. Reads local files only.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from gate_compliance import analyse  # noqa: E402

from website_trust_assessment.research.candidates import CANDIDATE_FIELDS  # noqa: E402

POSITIVE_DIRS = {
    "selected": (ROOT / "data/candidates/feed_v3", "feed_batch", 30),
    "reserve": (ROOT / "data/candidates/feed_v3/reserve", "feed_reserve", 15),
    "topup": (ROOT / "data/candidates/feed_v3/topup", "feed_topup", 40),
}
NEGATIVE_DIRS = {
    "negative": (ROOT / "data/candidates/feed_v3/negatives", "neg", 30),
    "negative_reserve": (ROOT / "data/candidates/feed_v3/negatives", "neg_reserve", 10),
}


def _union(paths: list[Path], out: Path) -> Path:
    seen: set[str] = set()
    rows: list[dict[str, str]] = []
    for path in paths:
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                key = str(row.get("url") or "").strip().lower().rstrip("/")
                if key and key not in seen:
                    seen.add(key)
                    rows.append(row)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CANDIDATE_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return out


def _positive_pairs() -> list[dict]:
    pairs: list[dict] = []
    tmp = ROOT / ".tmp-ptest/feed_v3_gate_compliance"
    for group, (directory, prefix, count) in POSITIVE_DIRS.items():
        for n in range(1, count + 1):
            name = f"{prefix}_{n:02d}"
            candidate = directory / f"{name}.csv"
            export = ROOT / f"data/exports/feed_v3/{name}.jsonl"
            if not candidate.exists() or not export.exists():
                continue
            pairs.append(
                {
                    "group": group,
                    "kind": "batch",
                    "item": analyse(candidate, export, ungated=False),
                    "approval_scope": "2026-10-26 gated approval (positive set)",
                }
            )
            retry_csv = ROOT / f"data/exports/feed_v3/retry/{name}_retry.csv"
            retry_export = ROOT / f"data/exports/feed_v3/retry/{name}_retry.jsonl"
            if retry_csv.exists() and retry_export.exists():
                union = _union([candidate, retry_csv], tmp / f"{name}_union.csv")
                pairs.append(
                    {
                        "group": group,
                        "kind": "retry",
                        "item": analyse(union, retry_export, ungated=False),
                        "approval_scope": "2026-10-26 gated approval and amendment 01 (root retry)",
                    }
                )
    return pairs


def _negative_pairs() -> list[dict]:
    pairs: list[dict] = []
    for group, (directory, prefix, count) in NEGATIVE_DIRS.items():
        for n in range(1, count + 1):
            name = f"{prefix}_{n:02d}"
            candidate = directory / f"{name}.csv"
            export = ROOT / f"data/exports/feed_v3/{name}.jsonl"
            if candidate.exists() and export.exists():
                pairs.append(
                    {
                        "group": group,
                        "kind": "batch",
                        "item": analyse(candidate, export, ungated=True),
                        "approval_scope": "standard collection; no gated row permitted",
                    }
                )
    return pairs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="data/research/gate_compliance_feed_v3.json")
    args = parser.parse_args(argv)

    pairs = _positive_pairs() + _negative_pairs()
    payload = {
        "schema_version": 1,
        "meaning": (
            "Every scored positive row must map to a candidate marked gated, which the batch "
            "command opens only with --allow-gated. Retry exports are checked against the union "
            "of the original batch and its retry rows. A scored gated row in an ungated pair, or "
            "an export row outside its candidate file, fails the check."
        ),
        "pairs": pairs,
        "batches_checked": len(pairs),
        "passed": all(
            pair["item"]["passed"] and pair["item"]["scope_ok"] for pair in pairs
        ),
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    for group in ("selected", "reserve", "topup", "negative", "negative_reserve"):
        items = [p for p in pairs if p["group"] == group]
        gated = sum(p["item"]["gated_rows_scored"] for p in items)
        off_scope = sum(p["item"]["rows_not_in_this_candidate_file"] for p in items)
        violations = sum(len(p["item"]["scope_violations"]) for p in items)
        print(
            f"{group:<17} pairs={len(items):>2} gated_scored={gated:>5} "
            f"off_scope={off_scope:>3} violations={violations:>2}"
        )
    print(f"Report: {out}")
    print("Gate compliance passed." if payload["passed"] else "Gate compliance FAILED.")
    return 0 if payload["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
