"""Prove which collection gate each crawl honoured.

A candidate row carries `collection_gate`; the gated value is only opened with `--allow-gated`.
This checks a candidate CSV against its export file and counts, per gate, how many rows produced a
scored assessment, an error row, or nothing at all. For a run that was launched without
`--allow-gated`, every scored row must come from an ungated candidate — one scored gated row means
the approval scope was exceeded, and this script exists so that claim is checked rather than
remembered.

    PYTHONPATH=. python scripts/gate_compliance.py \
        --pair data/candidates/main_reserve.csv=data/exports/main/reserve.jsonl \
        --ungated data/candidates/main_reserve.csv=data/exports/main/reserve.jsonl \
        --out data/research/gate_compliance.json
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

GATED = "malicious_page_requires_explicit_confirmation"


def norm(url: str) -> str:
    return str(url or "").strip().rstrip("/").lower()


def analyse(candidates_path: Path, exports_path: Path, *, ungated: bool) -> dict:
    candidates = [
        dict(row)
        for row in csv_rows(candidates_path)
    ]
    by_gate = Counter()
    urls: dict[str, str] = {}
    for row in candidates:
        gate = GATED if row.get("collection_gate") == GATED else "standard"
        by_gate[gate] += 1
        urls[norm(row.get("url"))] = gate

    scored = Counter()
    errored = Counter()
    violations: list[str] = []
    unknown: list[str] = []
    if exports_path.exists():
        for line in exports_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            gate = urls.get(norm(row.get("url")))
            if gate is None:
                unknown.append(norm(row.get("url")))
                continue
            if "overall_risk" in row:
                scored[gate] += 1
                if ungated and gate == GATED:
                    violations.append(norm(row.get("url")))
            else:
                errored[gate] += 1

    return {
        "candidates": str(candidates_path),
        "exports": str(exports_path),
        "launched_without_allow_gated": ungated,
        "candidate_rows_by_gate": dict(by_gate),
        "scored_by_gate": dict(scored),
        "error_rows_by_gate": dict(errored),
        "gated_rows_scored": scored.get(GATED, 0),
        "scope_violations": sorted(set(violations)),
        "rows_not_in_this_candidate_file": len(set(unknown)),
        "scope_ok": not unknown,
        "passed": not violations,
    }


def csv_rows(path: Path):
    import csv

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        yield from csv.DictReader(handle)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--pair",
        action="append",
        default=[],
        metavar="CANDIDATES=EXPORTS",
        help="candidate CSV and the export JSONL produced from it (repeatable)",
    )
    parser.add_argument(
        "--ungated",
        action="append",
        default=[],
        metavar="CANDIDATES=EXPORTS",
        help="pairs whose crawl was launched without --allow-gated; any scored gated row fails",
    )
    parser.add_argument(
        "--allow-gated",
        action="append",
        default=[],
        metavar="CANDIDATES=EXPORTS",
        help="pairs whose crawl carried --allow-gated under an explicit approval; scored gated rows "
        "are expected here and are reported without the label of violation",
    )
    parser.add_argument("--out", default="data/research/gate_compliance.json")
    args = parser.parse_args()

    ungated_pairs = set(args.ungated)
    approved_pairs = set(args.allow_gated)
    results = []
    for pair in args.pair:
        candidates, exports = pair.split("=", 1)
        item = analyse(
            Path(candidates),
            Path(exports),
            ungated=pair in ungated_pairs,
        )
        if pair in approved_pairs:
            item["approval_scope"] = "gated crawl covered by the recorded approval"
        results.append(item)

    payload = {
        "schema_version": 1,
        "gated_collection": GATED,
        "meaning": (
            "scored_by_gate counts assessments per candidate gate. For an ungated run the gated count "
            "must be zero: it is the evidence that no page was opened beyond the approved scope. "
            "scope_ok confirms that every scored export row came from this candidate file."
        ),
        "pairs": results,
        "passed": all(item["passed"] and item["scope_ok"] for item in results),
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="")

    for item in results:
        print(
            f"{item['candidates']} -> {item['exports']}: "
            f"scored {item['scored_by_gate']} gated_scored={item['gated_rows_scored']} "
            f"off_scope={item['rows_not_in_this_candidate_file']} "
            f"{'PASS' if item['passed'] and item['scope_ok'] else 'FAIL'}"
        )
    print(f"Report: {out}")
    return 0 if payload["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
