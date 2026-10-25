"""Record the batch 1 domains that were never visually inspected.

Some annotator notes describe a failed load rather than an observation of the page. The
transport triage classifies those rows mechanically: the server refused this client
(HTTP 403/423) or gave no response at all. Their labels stay exactly as the annotator
wrote them; this record only marks them as not-inspectable so dataset construction can
exclude them from both the primary binary task and the suspicious sensitivity analysis,
and so the paper can report them as a reachability limitation instead of a judgement.
"""

from __future__ import annotations

import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

BATCH_DIR = Path("data/annotations/main/batch_01")
TRIAGE = BATCH_DIR / "reachability_triage.json"
FROZEN_DIR = BATCH_DIR / "frozen"
LABELS = BATCH_DIR / "annotator_a.csv"
OUT_CSV = BATCH_DIR / "non_inspections.csv"
OUT_JSON = BATCH_DIR / "amendments" / "main_batch_01_non_inspections.json"

REFUSAL_STATUSES = {403, 423, 451}


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    triage = json.loads(TRIAGE.read_text(encoding="utf-8"))
    labels = {
        row["sample_id"]: row
        for row in csv.DictReader(LABELS.open(encoding="utf-8"))
    }
    freeze_records = sorted(FROZEN_DIR.glob("*.freeze.json"))
    if not freeze_records:
        raise SystemExit("no freeze record found; freeze the sheet before classifying")
    record_path = freeze_records[-1]
    record = json.loads(record_path.read_text(encoding="utf-8"))

    rows = []
    for item in triage["results"]:
        if item["outcome"] == "no_http_response":
            classification = "no_response"
        elif item["outcome"] == "reachable" and item.get("status") in REFUSAL_STATUSES:
            classification = "server_refusal"
        else:
            continue
        label_row = labels.get(item["sample_id"], {})
        rows.append(
            {
                "sample_id": item["sample_id"],
                "domain": item["domain"],
                "label": label_row.get("label", ""),
                "confidence": label_row.get("confidence", ""),
                "annotator_note": label_row.get("notes", ""),
                "classification": classification,
                "transport_status": item.get("status", "") if classification == "server_refusal" else "",
                "transport_detail": item.get("detail", "") or item.get("last_error", ""),
                "final_url": item.get("final_url", ""),
                "triage_generated_at": triage["generated_at"],
            }
        )
    rows.sort(key=lambda row: (row["classification"], row["domain"]))

    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with OUT_CSV.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    payload = {
        "schema_version": 1,
        "record_id": "main_batch_01_non_inspections",
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "batch": "01",
        "annotator": "a",
        "type": "analysis_exclusion_record",
        "changes_labels": False,
        "purpose": (
            "Mark rows whose annotator note records a failed load rather than an observation, "
            "so they are excluded from the primary binary task and the suspicious sensitivity "
            "analysis and reported as a reachability limitation."
        ),
        "prepared_by": "assistant; mechanical transport triage, no trust judgement",
        "approved_by": "User instruction to re-attempt group A and then freeze batch 1",
        "method": {
            "triage_file": TRIAGE.as_posix(),
            "triage_sha256": _sha(TRIAGE),
            "scope": "DNS, TCP, TLS and HTTP status only; no page content was read",
            "classes": {
                "server_refusal": f"HTTP {sorted(REFUSAL_STATUSES)} from the live server",
                "no_response": "connection or read timeout, no HTTP response",
            },
        },
        "frozen_sheet": {
            "archive": record["archive"],
            "archive_sha256": record["sha256"],
            "record": record_path.as_posix(),
            "record_sha256": _sha(record_path),
            "frozen_at": record.get("frozen_at", ""),
        },
        "counts": {
            "labelled_sites": len(labels),
            "flagged_for_triage": len(triage["results"]),
            "non_inspectable": len(rows),
            "by_classification": {
                key: sum(1 for row in rows if row["classification"] == key)
                for key in sorted({row["classification"] for row in rows})
            },
            "by_label": {
                key: sum(1 for row in rows if row["label"] == key)
                for key in sorted({row["label"] for row in rows})
            },
        },
        "excluded_domains": sorted(row["domain"] for row in rows),
        "rows": rows,
    }
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"Non-inspectable rows: {len(rows)} of {len(labels)} labelled sites")
    for key, value in payload["counts"]["by_classification"].items():
        print(f"  {key}: {value}")
    print(f"CSV:   {OUT_CSV}")
    print(f"JSON:  {OUT_JSON}")


if __name__ == "__main__":
    main()
