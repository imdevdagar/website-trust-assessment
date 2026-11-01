"""Split feed_v3 exports into same-domain analysis files and a redirect exclusion report.

The label unit is the registrable domain of the candidate. When a crawl lands on a different
registrable domain, the assessment describes the redirect target, not the labelled domain, so it
cannot be used as a sample for either class. This script keeps only rows whose final registrable
domain equals the candidate's, writes them to two analysis JSONL files, and records every exclusion
with its reason. It reads local files only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from website_trust_assessment.research.candidates import UnsafeURLError, sanitize_candidate_url

ROOT = Path(__file__).resolve().parents[1]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _files() -> list[Path]:
    base = ROOT / "data/exports/feed_v3"
    files = sorted(base.glob("feed_batch_*.jsonl"))
    files += sorted(base.glob("feed_reserve_*.jsonl"))
    files += sorted(base.glob("feed_topup_*.jsonl"))
    files += sorted(base.glob("neg_*.jsonl"))
    files += sorted((base / "retry").glob("feed_*.jsonl"))
    return [path for path in files if path.exists() and path.stat().st_size > 0]


def _classify(path: Path) -> str:
    name = path.name
    if name.startswith("neg_"):
        return "negative"
    return "positive"


def _hash_domain(domain: str) -> str:
    return "target-" + hashlib.sha256(domain.encode("utf-8")).hexdigest()[:10]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", default="data/exports/feed_v3/analysis")
    args = parser.parse_args(argv)
    out_dir = ROOT / args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    handles = {
        "positive": (out_dir / "positive.jsonl").open("w", encoding="utf-8"),
        "negative": (out_dir / "negative.jsonl").open("w", encoding="utf-8"),
    }
    stats = Counter()
    excluded: list[dict] = []
    sources: dict[str, str] = {}
    try:
        for path in _files():
            kind = _classify(path)
            sources[str(path.relative_to(ROOT)).replace("\\", "/")] = _sha256(path)
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    stats[f"{kind}_unparseable"] += 1
                    continue
                if row.get("error") or "overall_risk" not in row:
                    stats[f"{kind}_failed_crawl"] += 1
                    continue
                final = str(row.get("domain") or "").strip().lower()
                try:
                    _, candidate = sanitize_candidate_url(str(row.get("url") or ""))
                except UnsafeURLError:
                    stats[f"{kind}_unsafe_url"] += 1
                    excluded.append(
                        {
                            "class": kind,
                            "source": path.name,
                            "reason": "candidate_url_failed_sanitising",
                            "url": str(row.get("url") or ""),
                        }
                    )
                    continue
                if not final:
                    stats[f"{kind}_missing_final_domain"] += 1
                    continue
                if final != candidate:
                    stats[f"{kind}_cross_domain_redirect"] += 1
                    excluded.append(
                        {
                            "class": kind,
                            "source": path.name,
                            "reason": "cross_domain_redirect",
                            "candidate_domain": candidate if kind == "positive" else _hash_domain(candidate),
                            "final_domain": final if kind == "positive" else _hash_domain(final),
                            "url": str(row.get("url") or "") if kind == "positive" else "",
                        }
                    )
                    continue
                handles[kind].write(json.dumps(row) + "\n")
                stats[f"{kind}_kept"] += 1
    finally:
        for handle in handles.values():
            handle.close()

    report = {
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "rule": (
            "A row is kept only when the final registrable domain equals the candidate's "
            "registrable domain. Cross-domain redirects describe a different site and are "
            "excluded from the primary dataset; they are never relabelled."
        ),
        "counts": dict(sorted(stats.items())),
        "exclusions": excluded,
        "negative_targets_are_hashed": True,
        "sources_sha256": sources,
        "outputs": {
            kind: {
                "path": str(path.relative_to(ROOT)).replace("\\", "/"),
                "sha256": _sha256(path),
                "rows": sum(1 for _ in path.open(encoding="utf-8")),
            }
            for kind, path in (
                ("positive", out_dir / "positive.jsonl"),
                ("negative", out_dir / "negative.jsonl"),
            )
        },
    }
    (out_dir / "exclusions.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(report["counts"], indent=2, sort_keys=True))
    print(f"Report: {out_dir / 'exclusions.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
