"""Build a root-URL retry batch for feed_v3 positive candidates that did not resolve.

The label unit is the registrable domain. When the recorded URL (often a phishing
subdomain) no longer resolves but the registrable root does, retrying ``scheme://domain/``
recovers an assessable page without changing the domain, its label, or the collection
gate. No page is opened here; the retry batch is collected through the normal command.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

from website_trust_assessment.research import candidates as cand

ROOT = Path(__file__).resolve().parents[1]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _failed_urls(export: Path) -> set[str]:
    failed: set[str] = set()
    if not export.exists():
        return failed
    for line in export.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = str(row.get("url") or "").strip().lower()
        if url and row.get("error"):
            failed.add(url)
    return failed


def build_retry(batch: Path, export: Path, out: Path) -> dict[str, int]:
    failed = _failed_urls(export)
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in _read_rows(batch):
        raw = str(row.get("url") or "").strip()
        if raw.lower() not in failed:
            continue
        try:
            _, domain = cand.sanitize_candidate_url(raw)
        except cand.UnsafeURLError:
            continue
        if domain in seen:
            continue
        scheme = urlsplit(raw).scheme.lower() or "https"
        root_url = f"{scheme}://{domain}/"
        if root_url.lower() == raw.lower():
            continue
        seen.add(domain)
        retry = dict(row)
        retry["url"] = root_url
        retry["candidate_id"] = "r_" + hashlib.sha256(
            f"feed_v3-root:{domain}".encode("utf-8")
        ).hexdigest()[:10]
        retry["notes"] = (
            f"{row.get('notes', '').strip()} Root-URL retry after the recorded URL did not "
            "resolve; domain and label are unchanged."
        ).strip()
        rows.append(retry)

    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=cand.CANDIDATE_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    summary = {
        "batch": str(batch),
        "export": str(export),
        "batch_sha256": _sha256(batch),
        "export_sha256": _sha256(export) if export.exists() else "",
        "failed_urls": len(failed),
        "retry_rows": len(rows),
        "retry_sha256": _sha256(out),
        "out": str(out),
    }
    out.with_suffix(".json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", required=True)
    parser.add_argument("--export", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    summary = build_retry(Path(args.batch), Path(args.export), Path(args.out))
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
