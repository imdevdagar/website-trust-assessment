"""Count usable feed_v3 assessments per class from the export JSONL files."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _usable_domains(paths: list[Path]) -> set[str]:
    domains: set[str] = set()
    for path in paths:
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("error") or not row.get("domain"):
                continue
            if "overall_risk" in row:
                domains.add(str(row["domain"]).lower())
    return domains


def count(exports: Path) -> dict[str, object]:
    positive = sorted(exports.glob("feed_batch_*.jsonl"))
    positive += sorted(exports.glob("feed_reserve_*.jsonl"))
    positive += sorted(exports.glob("feed_topup_*.jsonl"))
    positive += sorted((exports / "retry").glob("feed_*.jsonl"))
    negative = sorted(
        p for p in exports.glob("neg_*.jsonl") if not p.name.startswith("neg_reserve_")
    )
    negative_reserve = sorted(exports.glob("neg_reserve_*.jsonl"))
    return {
        "positive_domains": len(_usable_domains(positive)),
        "negative_domains": len(_usable_domains(negative)),
        "negative_reserve_domains": len(_usable_domains(negative_reserve)),
        "positive_files": len(positive),
        "negative_files": len(negative) + len(negative_reserve),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exports", default=str(ROOT / "data/exports/feed_v3"))
    args = parser.parse_args(argv)
    print(json.dumps(count(Path(args.exports)), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
