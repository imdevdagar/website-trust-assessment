"""Write the fixed-ranking feed_v3 positive top-up batches (protocol amendment 01).

Only domains already in the 9,764-domain feed_v3 positive pool are eligible. The ranking and
the seed are the same ones used for the selected and reserve sets, so this is a deterministic
continuation of the pre-registered order, not a new sample.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from website_trust_assessment.research import candidates as cand
from website_trust_assessment.research import feed_labels as fl

ROOT = Path(__file__).resolve().parents[1]
LABEL_DIR = ROOT / "data/labels/feed_v3"
POSITIVE_CANDIDATES = ROOT / "data/candidates/feed_v3"
TOPUP_DIR = POSITIVE_CANDIDATES / "topup"
SEED = 42
BATCH_SIZE = 100


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _rel(path: Path) -> str:
    try:
        return Path(path).resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def _read_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _used_domains() -> set[str]:
    paths: list[Path] = []
    paths += sorted(POSITIVE_CANDIDATES.glob("feed_batch_*.csv"))
    paths += sorted((POSITIVE_CANDIDATES / "reserve").glob("feed_reserve_*.csv"))
    paths += sorted(TOPUP_DIR.glob("feed_topup_*.csv"))
    used: set[str] = set()
    for path in paths:
        used.update(str(row.get("domain") or "").lower() for row in _read_rows(path))
    used.discard("")
    return used


def _rank(domain: str) -> str:
    return hashlib.sha256(f"feed_v3-positive:{SEED}:{domain}".encode("utf-8")).hexdigest()


def build(*, force: bool = False) -> dict[str, Any]:
    labels = _read_rows(LABEL_DIR / "labels.csv")
    used = _used_domains()
    remaining = sorted(
        (row for row in labels if row["domain"] not in used),
        key=lambda row: _rank(row["domain"]),
    )
    topup_labels = LABEL_DIR / "topup_labels.csv"
    if topup_labels.exists() and not force:
        selected = _read_rows(topup_labels)
    else:
        selected = remaining
        fl.write_labels(selected, topup_labels)

    manifest_path = TOPUP_DIR / "feed_topup_manifest.json"
    batches: list[dict[str, Any]] = []
    if force or not manifest_path.exists():
        for path in TOPUP_DIR.glob("feed_topup_*.csv"):
            path.unlink()
        manifest = cand.build_feed_candidates(
            labels_path=topup_labels,
            out_dir=TOPUP_DIR,
            seed=SEED,
            batch_size=BATCH_SIZE,
            batch_prefix="feed_topup",
        )
        manifest["labels_file"] = _rel(topup_labels)
        for batch in manifest["batches"]:
            batch["file"] = _rel(Path(batch["file"]))
        manifest["approval"] = (
            "protocol amendment 01: fixed-ranking top-up within the approved 2026-10-26 pool; "
            "batches remain gated and require --allow-gated"
        )
        manifest["approval_record"] = _rel(
            POSITIVE_CANDIDATES / "collection_amendment_01.json"
        )
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        batches = manifest["batches"]

    selection = {
        "amendment": "feed_v3_topup_01",
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "seed": SEED,
        "ranking": "sha256('feed_v3-positive:42:' + domain) ascending",
        "pool_domains": len(labels),
        "used_before_topup": len(used),
        "remaining_pool": len(remaining),
        "topup_selected": len(selected),
        "topup_batches": len(batches) if batches else len(
            list(TOPUP_DIR.glob("feed_topup_*.csv"))
        ),
        "labels_file": _rel(topup_labels),
        "labels_sha256": _sha256(topup_labels),
        "manifest": _rel(manifest_path),
        "manifest_sha256": _sha256(manifest_path) if manifest_path.exists() else "",
    }
    (LABEL_DIR / "topup_selection.json").write_text(
        json.dumps(selection, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return selection


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="regenerate existing top-up files")
    args = parser.parse_args(argv)
    print(json.dumps(build(force=args.force), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
