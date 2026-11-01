"""Re-retrieve the feed_v3 feeds and measure label drift against the frozen label set.

Collection ran across several days after the single 2026-10-25 retrieval, so the derived negative class
could contain domains that were listed after that retrieval — silent false negatives. This fetches the
same two feeds with the same reduction rules into a separate artifact and compares. It never touches
`labels.csv`, the snapshots it is scoped against, or any dataset.

Run:  python scripts/feed_v3_churn.py && python scripts/feed_churn.py data/labels/feed_v3
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import feed_v3_build as build  # noqa: E402  (reuses the frozen reduction rules)
from website_trust_assessment.research import feed_labels as fl  # noqa: E402

CHURN_DIR = build.LABEL_DIR / "churn"
BACKOFF_SECONDS = (0, 30, 60, 120, 240)


def fetch_with_backoff(url: str, name: str, snapshot_dir: Path):
    """PhishTank answers 429 under load; a partial feed must never be read as delisting."""
    import time

    original = build.SNAPSHOT_DIR
    build.SNAPSHOT_DIR = snapshot_dir
    try:
        last: Exception | None = None
        for delay in BACKOFF_SECONDS:
            if delay:
                print(f"{name}: retrying after {delay}s")
                time.sleep(delay)
            try:
                return build._fetch(url, name=name)
            except Exception as exc:  # noqa: BLE001 - report, then retry or abort
                last = exc
        raise SystemExit(f"{name} unavailable after {len(BACKOFF_SECONDS)} attempts: {last}")
    finally:
        build.SNAPSHOT_DIR = original


def main() -> int:
    snapshot_dir = CHURN_DIR / "snapshots"
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    primary_retrieved = datetime.fromisoformat(
        json.loads((build.LABEL_DIR / "provenance.json").read_text(encoding="utf-8"))["created_at"]
    )

    phish_raw, phish_meta = fetch_with_backoff(
        build.PHISHTANK_URL, "phishtank_online_valid.csv", snapshot_dir
    )
    open_raw, open_meta = fetch_with_backoff(
        build.OPENPHISH_URL, "openphish_feed.txt", snapshot_dir
    )

    phish_text = phish_raw.decode("utf-8-sig", errors="replace")
    per_domain, _, _ = build._parse_phish(phish_text)
    heavy = {d for d, urls in per_domain.items() if len(urls) >= build.HEAVY_URL_THRESHOLD}
    phish_urls = [build._choose_url(u) for d, u in sorted(per_domain.items()) if d not in heavy]
    excluded, _ = build.collect_exclusions()

    sources = [
        fl.FeedSource(
            name="phishtank_online_valid",
            text="\n".join(phish_urls),
            retrieved_at=phish_meta["retrieved_at"],
            source_date=phish_meta["source_date"],
            sha256=phish_meta["sha256"],
            url=build.PHISHTANK_URL,
            snapshot_file=phish_meta["snapshot_file"],
        ),
        fl.FeedSource(
            name="openphish_public_feed",
            text=open_raw.decode("utf-8-sig", errors="replace"),
            retrieved_at=open_meta["retrieved_at"],
            source_date=open_meta["source_date"],
            sha256=open_meta["sha256"],
            url=build.OPENPHISH_URL,
            snapshot_file=open_meta["snapshot_file"],
        ),
    ]
    rows, stats = fl.build_feed_labels(
        sources, excluded_domains=excluded | heavy, now=datetime.now(timezone.utc)
    )
    out = CHURN_DIR / "labels_t2.csv"
    fl.write_labels(rows, out)

    interval_hours = (datetime.now(timezone.utc) - primary_retrieved).total_seconds() / 3600
    manifest = {
        "dataset": "feed_v3",
        "purpose": "label drift between the frozen retrieval and a later one",
        "primary_retrieved_at": primary_retrieved.isoformat(),
        "second_retrieved_at": stats.get("created_at"),
        "interval_hours": round(interval_hours, 2),
        "labeled_domains": stats.get("labeled_domains"),
        "primary_labels_untouched": True,
        "sources": stats.get("sources"),
    }
    (CHURN_DIR / "provenance_t2.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(manifest, indent=2, sort_keys=True)[:900])
    print(f"Second retrieval written: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
