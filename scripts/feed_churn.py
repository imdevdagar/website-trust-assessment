"""Measure feed-label churn between two retrievals of the public abuse feeds.

Compares the frozen primary label set against a later snapshot and reports, per
source and overall, how many labelled domains persist, how many dropped out
(offline now), and how many are newly listed. Transience is a measured result
for the paper, not a caveat: a feed label is only valid at its retrieval time.

Metadata-only. Opens no pages and writes nothing into the primary artifacts.
"""

from __future__ import annotations

import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def load(path: Path) -> dict[str, str]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return {
            row["domain"].strip().lower(): row["source"].strip()
            for row in csv.DictReader(handle)
            if row.get("domain")
        }


def split_source(source: str) -> set[str]:
    parts = set()
    for token in source.replace("+", ",").split(","):
        token = token.strip()
        if "@" in token:
            token = token.split("@", 1)[0]
        if token:
            parts.add(token)
    return parts


def compare(primary: dict[str, str], second: dict[str, str]) -> dict:
    still = set(primary) & set(second)
    dropped = set(primary) - set(second)
    added = set(second) - set(primary)
    total = len(primary)
    return {
        "primary_domains": total,
        "second_domains": len(second),
        "retained": len(still),
        "retained_share": round(len(still) / total, 4) if total else 0.0,
        "dropped": len(dropped),
        "dropped_share": round(len(dropped) / total, 4) if total else 0.0,
        "newly_listed": len(added),
        "newly_listed_share_of_primary": round(
            len(added) / total, 4
        )
        if total
        else 0.0,
        "dropped_domains": sorted(dropped),
        "newly_listed_domains": sorted(added),
    }


def by_source(primary: dict[str, str], second: dict[str, str]) -> dict:
    out = {}
    for source in sorted({s for v in primary.values() for s in split_source(v)}):
        p = {d for d, s in primary.items() if source in split_source(s)}
        q = {d for d, s in second.items() if source in split_source(s)}
        out[source] = {
            "primary_domains": len(p),
            "second_domains": len(q),
            "retained": len(p & q),
            "retained_share": round(len(p & q) / len(p), 4) if p else 0.0,
        }
    return out


def manifest(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8-sig"))


def provenance(primary_m: dict, second_m: dict) -> dict:
    def digest(payload: dict, source: str) -> str:
        return str((payload.get("sources") or {}).get(source, {}).get("sha256", ""))

    interval = None
    try:
        a = datetime.fromisoformat(str(primary_m["created_at"]))
        b = datetime.fromisoformat(str(second_m["created_at"]))
        interval = round((b - a).total_seconds() / 3600, 2)
    except (KeyError, TypeError, ValueError):
        pass
    sources = set(primary_m.get("sources") or {}) | set(second_m.get("sources") or {})
    return {
        "primary_created_at": primary_m.get("created_at"),
        "second_created_at": second_m.get("created_at"),
        "interval_hours": interval,
        "raw_feed_digests_changed": {
            source: digest(primary_m, source) != digest(second_m, source)
            for source in sorted(sources)
        },
    }


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("data/labels/feed")
    primary_path = root / "labels.csv"
    second_path = root / "churn" / "labels_t2.csv"
    out_path = root / "churn" / "churn_report.json"

    primary = load(primary_path)
    second = load(second_path)

    overall = compare(primary, second)
    eval_path = root / "eval_labels.csv"
    assessed = None
    if eval_path.exists():
        with eval_path.open("r", encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))

        def domains_for(label: str) -> set[str]:
            return {
                row["domain"].strip().lower()
                for row in rows
                if row.get("domain")
                and (row.get("label") or "").strip().lower() == label
            }

        positive = domains_for("malicious")
        negative = domains_for("benign")
        listed = positive & set(second)
        newly_listed_negative = negative & set(second)
        assessed = {
            "assessed_feed_positive_domains": len(positive),
            "still_listed": len(listed),
            "still_listed_share": round(len(listed) / len(positive), 4) if positive else 0.0,
            "no_longer_listed": len(positive) - len(listed),
            "derived_benign_domains": len(negative),
            "derived_benign_now_listed": len(newly_listed_negative),
            "derived_benign_now_listed_domains": sorted(newly_listed_negative),
            "meaning": (
                "share of the domains the primary evaluation labelled positive that a "
                "later retrieval still lists; the rest had already been delisted. "
                "derived_benign_now_listed counts negatives that a feed has since "
                "reported, i.e. how far the 'absent means benign' assumption decays."
            ),
        }

    report = {
        "schema_version": 1,
        "name": "wtas-feed-label-churn",
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "primary_labels": {
            "file": str(primary_path),
            "domains": len(primary),
        },
        "second_labels": {
            "file": str(second_path),
            "domains": len(second),
        },
        "reading": (
            "A feed label asserts membership at one retrieval time. This report "
            "quantifies how much of that membership survives to a later retrieval; "
            "it is not a re-label or a correction of the frozen set."
        ),
        "overall": overall,
        "by_source": by_source(primary, second),
        "provenance": provenance(
            manifest(primary_path.with_suffix(".json")),
            manifest(second_path.with_suffix(".json")),
        ),
        "collected_assessments": assessed,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline=""
    )
    print(f"retained {overall['retained']}/{overall['primary_domains']} "
          f"({overall['retained_share']:.1%}), dropped {overall['dropped']}, "
          f"newly listed {overall['newly_listed']} -> {out_path}")
    for source, stats in report["by_source"].items():
        print(f"  {source}: {stats['retained']}/{stats['primary_domains']} retained")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
