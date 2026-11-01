"""Summarise the feed_v3 collection outcome from candidate CSVs and export JSONL.

Reports usable registrable domains by approval group (selected, reserve, top-up, negative),
retry recoveries, and failure reasons. Reads local files only; opens no pages.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from website_trust_assessment.research.candidates import UnsafeURLError, sanitize_candidate_url

ROOT = Path(__file__).resolve().parents[1]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _candidate_sources() -> list[tuple[str, Path]]:
    sources: list[tuple[str, Path]] = []
    for n in range(1, 31):
        sources.append(("selected", ROOT / f"data/candidates/feed_v3/feed_batch_{n:02d}.csv"))
    for n in range(1, 16):
        sources.append(
            ("reserve", ROOT / f"data/candidates/feed_v3/reserve/feed_reserve_{n:02d}.csv")
        )
    for n in range(1, 41):
        sources.append(("topup", ROOT / f"data/candidates/feed_v3/topup/feed_topup_{n:02d}.csv"))
    for n in range(1, 31):
        sources.append(("negative", ROOT / f"data/candidates/feed_v3/negatives/neg_{n:02d}.csv"))
    for n in range(1, 11):
        sources.append(
            ("negative_reserve", ROOT / f"data/candidates/feed_v3/negatives/neg_reserve_{n:02d}.csv")
        )
    return [(group, path) for group, path in sources if path.exists()]


def _export_files() -> list[Path]:
    base = ROOT / "data/exports/feed_v3"
    files = sorted(base.glob("*.jsonl"))
    files += sorted((base / "retry").glob("*.jsonl"))
    return [path for path in files if path.stat().st_size > 0]


def summarise() -> dict:
    domain_group: dict[str, str] = {}
    candidate_counts: Counter[str] = Counter()
    candidate_hashes: dict[str, str] = {}
    for group, path in _candidate_sources():
        candidate_hashes[str(path.relative_to(ROOT)).replace("\\", "/")] = _sha256(path)
        for row in _rows(path):
            domain = str(row.get("domain") or "").strip().lower()
            if domain:
                domain_group.setdefault(domain, group)
                candidate_counts[group] += 1

    usable: dict[str, set[str]] = defaultdict(set)
    retry_usable: set[str] = set()
    failures: Counter[str] = Counter()
    failure_examples: dict[str, list[str]] = defaultdict(list)
    rows_total = 0
    for path in _export_files():
        is_retry = path.parent.name == "retry"
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            rows_total += 1
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                failures["unparseable_export_row"] += 1
                continue
            domain = str(row.get("domain") or "").strip().lower()
            if row.get("error"):
                reason = str(row["error"]).split(":", 1)[0].strip()
                failures[reason] += 1
                if len(failure_examples[reason]) < 5:
                    failure_examples[reason].append(str(row.get("url") or ""))
                continue
            if not domain or "overall_risk" not in row:
                failures["not_an_assessment"] += 1
                continue
            try:
                _, candidate = sanitize_candidate_url(str(row.get("url") or ""))
            except UnsafeURLError:
                failures["candidate_url_failed_sanitising"] += 1
                continue
            if candidate != domain:
                failures["cross_domain_redirect_excluded"] += 1
                continue
            group = domain_group.get(domain, "unknown")
            usable[group].add(domain)
            if is_retry:
                retry_usable.add(domain)

    positives = usable["selected"] | usable["reserve"] | usable["topup"]
    negatives = usable["negative"] | usable["negative_reserve"]
    return {
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "rows_read": rows_total,
        "candidate_rows_by_group": dict(sorted(candidate_counts.items())),
        "usable_domains_by_group": {
            group: len(domains) for group, domains in sorted(usable.items())
        },
        "usable_positives": len(positives),
        "usable_positives_before_topup": len(usable["selected"] | usable["reserve"]),
        "usable_negatives": len(negatives),
        "usable_total": len(positives) + len(negatives),
        "domains_with_usable_retry_assessment": len(retry_usable),
        "failure_reasons": dict(failures.most_common()),
        "failure_examples": dict(failure_examples),
        "candidate_file_sha256": candidate_hashes,
        "unknown_domain_assessments": sorted(usable.get("unknown", set()))[:20],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out", default="data/candidates/feed_v3/collection_outcome.json"
    )
    args = parser.parse_args(argv)
    payload = summarise()
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
