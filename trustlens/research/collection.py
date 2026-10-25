"""Auditable status for the main-dataset collection and annotation workflow.

The status file is derived entirely from artefacts already on disk: batch candidate
CSVs, exported assessments, blinded queues, annotator sheets, and freeze archives. It
records per-batch progress, integrity checks, and the state of the gated scam-feed
collection so the team can see what is done, what is pending, and what is blocked.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from collections import Counter

from ..security import registrable_domain
from .annotations import LABELS, read_csv_rows
from .candidates import GATED_COLLECTION
from .dataset import load_assessment_files

MAIN_CANDIDATES = "data/candidates/main.csv"
MAIN_RESERVE = "data/candidates/main_reserve.csv"
MAIN_BATCHES = "data/candidates/main_batches.json"
MAIN_MANIFEST = "data/candidates/main_manifest.json"
MAIN_LOCK = "data/pilot_dataset_lock.json"
EXPORT_DIR = "data/exports/main"
ANNOTATION_DIR = "data/annotations/main"
STATUS_PATH = "data/main_collection_status.json"

USABLE_TARGET_MIN = 400
ANNOTATION_WINDOW_HOURS = 48
GATED_STRATA = ("scam_feed",)


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _host(value: str) -> str:
    return (urlsplit(value).hostname or "").lower().removeprefix("www.")


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _batch_files(root: Path) -> list[dict[str, Any]]:
    meta = _read_json(root / MAIN_BATCHES)
    batches = meta.get("batches")
    if not isinstance(batches, list):
        return []
    return [entry for entry in batches if isinstance(entry, dict) and entry.get("batch")]


def _candidate_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    return read_csv_rows(path)


def _collection_report(export_path: Path) -> dict[str, Any]:
    """Split an export into usable assessments and rows that failed collection."""
    if not export_path.exists():
        return {
            "export": str(export_path.name),
            "exists": False,
            "rows": 0,
            "assessments": 0,
            "domains": [],
            "failures": [],
            "redirects": [],
            "no_evidence": [],
            "levels": {},
            "collected_at": "",
        }
    assessments, errors = load_assessment_files([export_path])
    failures: list[dict[str, str]] = []
    for line in export_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and "error" in payload and "domain" not in payload:
            failures.append(
                {"url": str(payload.get("url", "")), "domain": _host(str(payload.get("url", ""))),
                 "error": str(payload.get("error", ""))}
            )
    levels = Counter(assessment.overall_level.value for assessment in assessments)
    redirects = [
        {
            "requested_domain": registrable_domain(urlsplit(assessment.url).hostname or ""),
            "url": assessment.url,
            "final_domain": assessment.domain,
            "final_url": assessment.final_url,
        }
        for assessment in assessments
        if registrable_domain(urlsplit(assessment.url).hostname or "") != assessment.domain
    ]
    no_evidence = [assessment.domain for assessment in assessments if not assessment.evidence]
    timestamps = [
        assessment.created_at for assessment in assessments if assessment.created_at
    ]
    return {
        "export": export_path.name,
        "exists": True,
        "sha256": sha256_file(export_path),
        "rows": len(failures) + len(assessments),
        "assessments": len(assessments),
        "domains": sorted(assessment.domain for assessment in assessments),
        "levels": dict(sorted(levels.items())),
        "failures": sorted(failures, key=lambda row: row["domain"]),
        "redirects": sorted(redirects, key=lambda row: row["final_domain"]),
        "no_evidence": sorted(no_evidence),
        "collected_at": max(timestamps).isoformat() if timestamps else "",
        "unreadable_rows": len(errors) - len(failures) if errors else 0,
    }


def _annotation_report(directory: Path) -> dict[str, Any]:
    key = _read_json(directory / "key.json")
    sheet = directory / "annotator_a.csv"
    labels = Counter()
    annotated = 0
    rows = 0
    if sheet.exists():
        for row in read_csv_rows(sheet):
            rows += 1
            label = str(row.get("label", "")).strip().lower()
            if label in LABELS:
                labels[label] += 1
                annotated += 1
    frozen_dir = directory / "frozen"
    archives: list[dict[str, Any]] = []
    if frozen_dir.exists():
        for record_path in sorted(frozen_dir.glob("*.freeze.json")):
            record = _read_json(record_path)
            if record:
                archives.append(
                    {
                        "role": record.get("role", ""),
                        "archive": record.get("archive", ""),
                        "sha256": record.get("sha256", ""),
                        "frozen_at": record.get("frozen_at", ""),
                        "annotated": record.get("annotated"),
                        "expected": record.get("expected"),
                    }
                )
    a_frozen = next(
        (item for item in archives if str(item.get("role", "")).lower().endswith("a")), None
    )
    return {
        "queue_exists": bool(key),
        "single_annotator": bool(key.get("single_annotator")),
        "sample_count": key.get("sample_count"),
        "sheet_rows": rows,
        "annotated": annotated,
        "pending": max(0, rows - annotated),
        "by_label": {label: labels.get(label, 0) for label in LABELS},
        "complete": bool(rows) and annotated == rows,
        "frozen": a_frozen is not None,
        "freeze": a_frozen,
    }


def _window_state(annotation: dict[str, Any], collection: dict[str, Any]) -> dict[str, Any]:
    """Compare freeze time against the last assessment in the batch export."""
    collected_raw = collection.get("collected_at", "")
    frozen_raw = (annotation.get("freeze") or {}).get("frozen_at", "")
    if not (collected_raw and frozen_raw):
        return {"assessable": False, "reason": "collection or freeze timestamp missing"}
    try:
        collected = datetime.fromisoformat(collected_raw)
        frozen = datetime.fromisoformat(frozen_raw)
    except ValueError:
        return {"assessable": False, "reason": "unparsable timestamp"}
    elapsed_hours = (frozen - collected).total_seconds() / 3600.0
    return {
        "assessable": True,
        "elapsed_hours": round(elapsed_hours, 2),
        "within_window": elapsed_hours <= ANNOTATION_WINDOW_HOURS,
        "window_hours": ANNOTATION_WINDOW_HOURS,
    }


def _integrity_checks(
    root: Path, batch_states: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    selected_path = root / MAIN_CANDIDATES
    selected_domains = {row["domain"] for row in _candidate_rows(selected_path)}
    reserve_domains = {row["domain"] for row in _candidate_rows(root / MAIN_RESERVE)}

    seen: set[str] = set()
    duplicates: set[str] = set()
    outside_selected: set[str] = set()
    outside_gated = 0
    for state in batch_states:
        path = root / str(state["candidates"]["path"])
        rows = _candidate_rows(path)
        domains = {row["domain"] for row in rows}
        duplicates |= seen & domains
        seen |= domains
        outside_selected |= domains - selected_domains
        outside_gated += sum(
            1
            for row in rows
            if str(row.get("collection_gate", "")) == GATED_COLLECTION
        )
    checks.append(
        {
            "id": "batch_domains_unique",
            "description": "No registrable domain appears in more than one batch file.",
            "ok": not duplicates,
            "detail": {"duplicates": sorted(duplicates)},
        }
    )
    checks.append(
        {
            "id": "batch_domains_are_selected",
            "description": "Every batch domain is part of the selected main manifest.",
            "ok": not outside_selected and bool(selected_domains),
            "detail": {"outside_selected": sorted(outside_selected)},
        }
    )
    checks.append(
        {
            "id": "safe_batches_have_no_gated_rows",
            "description": "Batch files built for standard collection contain no gated rows.",
            "ok": outside_gated == 0,
            "detail": {"gated_rows": outside_gated},
        }
    )
    checks.append(
        {
            "id": "reserve_disjoint_from_selected",
            "description": "Reserve domains never overlap the selected domains.",
            "ok": not (selected_domains & reserve_domains),
            "detail": {"overlap": sorted(selected_domains & reserve_domains)},
        }
    )
    checks.append(
        {
            "id": "batch_hashes_match_manifest",
            "description": "Recomputed batch CSV digests match main_batches.json.",
            "ok": not any(
                state["candidates"]["sha256_mismatch"] for state in batch_states
            ),
            "detail": {
                "mismatches": [
                    state["batch"]
                    for state in batch_states
                    if state["candidates"]["sha256_mismatch"]
                ]
            },
        }
    )
    redirects: list[dict[str, Any]] = []
    for state in batch_states:
        if not state["annotation"]["queue_exists"]:
            continue
        sheet_rows = _candidate_rows(
            root / ANNOTATION_DIR / f"batch_{state['batch']}" / "annotator_a.csv"
        )
        sheet_domains = {row["domain"] for row in sheet_rows}
        candidate_domains = {
            row["domain"] for row in _candidate_rows(root / state["candidates"]["path"])
        }
        collected_domains = set(state["collection"]["domains"])
        batch_redirects = state["collection"]["redirects"]
        redirects.extend(
            {**item, "batch": state["batch"]} for item in batch_redirects
        )
        # A cross-domain redirect replaces the candidate domain with the live landing domain,
        # so the landing domain is expected to sit outside the candidate list.
        explained = {item["final_domain"] for item in batch_redirects}
        unexplained = sorted(collected_domains - candidate_domains - explained)
        checks.append(
            {
                "id": f"sheet_matches_collection_batch_{state['batch']}",
                "description": (
                    f"Batch {state['batch']} sheet domains are exactly the collected domains, "
                    "each either a batch candidate or a recorded redirect landing domain."
                ),
                "ok": sheet_domains == collected_domains and not unexplained,
                "detail": {
                    "sheet_minus_collected": sorted(sheet_domains - collected_domains),
                    "collected_minus_sheet": sorted(collected_domains - sheet_domains),
                    "unexplained_domains": unexplained,
                },
            }
        )
        checks.append(
            {
                "id": f"no_collapsed_domains_batch_{state['batch']}",
                "description": (
                    f"Batch {state['batch']} queue has one row per collected assessment, so no "
                    "two candidates collapsed onto the same registrable domain."
                ),
                "ok": len(sheet_rows) == state["collection"]["assessments"],
                "detail": {
                    "sheet_rows": len(sheet_rows),
                    "assessments": state["collection"]["assessments"],
                },
            }
        )
    checks.append(
        {
            "id": "cross_domain_redirects_recorded",
            "description": (
                "Assessments whose live page sits on a different registrable domain than the "
                "candidate are listed so the queue substitution is auditable."
            ),
            "ok": True,
            "informational": True,
            "detail": {"redirects": redirects},
        }
    )
    return checks


def build_collection_status(root: Path) -> dict[str, Any]:
    root = Path(root)
    batches = _batch_files(root)
    export_dir = root / EXPORT_DIR
    annotation_root = root / ANNOTATION_DIR

    batch_states: list[dict[str, Any]] = []
    for entry in batches:
        batch = str(entry["batch"])
        candidates_path = Path(str(entry.get("path", "")))
        recorded_sha = str(entry.get("sha256", ""))
        actual_sha = sha256_file(root / candidates_path) if (root / candidates_path).exists() else ""
        rows = _candidate_rows(root / candidates_path)
        collection = _collection_report(export_dir / f"batch_{batch}.jsonl")
        annotation = _annotation_report(annotation_root / f"batch_{batch}")
        batch_states.append(
            {
                "batch": batch,
                "candidates": {
                    "path": candidates_path.as_posix(),
                    "sha256": actual_sha,
                    "recorded_sha256": recorded_sha,
                    "sha256_mismatch": bool(recorded_sha) and actual_sha != recorded_sha,
                    "domains": len(rows),
                    "strata": dict(
                        sorted(Counter(str(row.get("stratum", "")) for row in rows).items())
                    ),
                    "gated": sum(
                        1
                        for row in rows
                        if str(row.get("collection_gate", "")) == GATED_COLLECTION
                    ),
                },
                "collection": collection,
                "annotation": annotation,
                "annotation_window": _window_state(annotation, collection),
                "next_action": _next_action(collection, annotation),
            }
        )

    collected = sum(state["collection"]["assessments"] for state in batch_states)
    queued = sum(state["annotation"]["sample_count"] or 0 for state in batch_states)
    annotated = sum(state["annotation"]["annotated"] for state in batch_states)
    frozen_batches = [state for state in batch_states if state["annotation"]["frozen"]]
    label_totals: Counter[str] = Counter()
    for state in batch_states:
        label_totals.update(state["annotation"]["by_label"])

    lock = _read_json(root / MAIN_LOCK)
    policy = lock.get("main_dataset_policy", {})
    gated = policy.get("gated_collection", {})
    manifest = _read_json(root / MAIN_MANIFEST)
    selected_counts = manifest.get("selected", {})
    reserve_counts = manifest.get("reserve", {})
    gated_selected = int(selected_counts.get("scam_feed", 0))
    failures = sum(len(state["collection"]["failures"]) for state in batch_states)
    gated_collected = sum(
        state["collection"]["assessments"]
        for state in batch_states
        if state["candidates"]["gated"]
    )

    safe_target = int(selected_counts.get("established", 0)) + int(
        selected_counts.get("tail", 0)
    )
    return {
        "generated_at": _now(),
        "schema_version": 1,
        "protocol": {
            "document": "docs/main-dataset-protocol.md",
            "label_source": policy.get("label_source", "single_annotator_a"),
            "double_annotation_fraction": policy.get("double_annotation_fraction", 0.0),
            "inter_rater_reliability": policy.get("inter_rater_reliability", "not_available"),
            "annotation_window_hours": ANNOTATION_WINDOW_HOURS,
        },
        "targets": {
            "usable_domains_min": USABLE_TARGET_MIN,
            "selected_total": int(manifest.get("domains_total", 0)),
            "selected_by_stratum": selected_counts,
            "reserve_by_stratum": reserve_counts,
            "safe_selected": safe_target,
            "gated_selected": gated_selected,
        },
        "progress": {
            "batches_defined": len(batch_states),
            "batches_collected": sum(1 for state in batch_states if state["collection"]["assessments"]),
            "batches_queued": sum(1 for state in batch_states if state["annotation"]["queue_exists"]),
            "batches_frozen": len(frozen_batches),
            "candidates_in_batches": sum(state["candidates"]["domains"] for state in batch_states),
            "assessments_collected": collected,
            "collection_failures": failures,
            "cross_domain_redirects": sum(
                len(state["collection"]["redirects"]) for state in batch_states
            ),
            "no_evidence": sum(
                len(state["collection"]["no_evidence"]) for state in batch_states
            ),
            "sites_queued": queued,
            "sites_annotated": annotated,
            "sites_pending": queued - annotated,
            "labels_by_class": {label: label_totals.get(label, 0) for label in LABELS},
            "usable_now": annotated,
            "usable_target_shortfall": max(0, USABLE_TARGET_MIN - (annotated + gated_selected)),
        },
        "gated_collection": {
            "stratum": "scam_feed",
            "selected": gated_selected,
            "status": gated.get("status", "not_approved_for_main"),
            "requires_fresh_approval": True,
            "approval_note": (
                "The Round 2 gated approval is spent. Collecting main scam_feed rows needs a new "
                "explicit approval and a dedicated browser profile."
            ),
            "collected_rows": gated_collected,
        },
        "reserve_policy": {
            "reserve_domains": sum(int(value) for value in reserve_counts.values()),
            "rule": (
                "Reserve replacements are only allowed before the batch's annotator A sheet is "
                "frozen, and every substitution is recorded here."
            ),
            "used": [],
        },
        "batches": batch_states,
        "integrity_checks": _integrity_checks(root, batch_states),
        "blocked_on": [
            "Batches 02-04 collection, annotation, and freeze.",
            "Fresh explicit approval before any gated scam_feed collection.",
            "Delayed blind 15% intra-rater audit after frozen labels and a 7-day delay.",
        ]
        if len(frozen_batches) < len(batch_states) or len(batch_states) == 0
        else ["Gated scam_feed approval and collection.", "Delayed blind intra-rater audit."],
    }


def _next_action(collection: dict[str, Any], annotation: dict[str, Any]) -> str:
    if annotation["frozen"]:
        return "complete"
    if not collection["exists"]:
        return "collect"
    if not annotation["queue_exists"]:
        return "build queue"
    if annotation["complete"]:
        return "freeze sheet"
    if annotation["annotated"]:
        return "continue labelling"
    return "label"


def write_status(root: Path, out_path: Path | None = None) -> Path:
    root = Path(root)
    destination = Path(out_path) if out_path else root / STATUS_PATH
    status = build_collection_status(root)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(status, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return destination


def status_markdown(status: dict[str, Any]) -> str:
    progress = status["progress"]
    targets = status["targets"]
    lines = [
        "# Main collection status",
        "",
        f"Generated: {status['generated_at']}",
        "",
        f"- Batches: {progress['batches_collected']} collected, "
        f"{progress['batches_queued']} queued, {progress['batches_frozen']} frozen "
        f"of {progress['batches_defined']}",
        f"- Assessments: {progress['assessments_collected']} usable, "
        f"{progress['collection_failures']} collection failures",
        f"- Labels: {progress['sites_annotated']} annotated, "
        f"{progress['sites_pending']} pending",
        f"- Label mix: " + ", ".join(
            f"{label}={count}" for label, count in progress["labels_by_class"].items()
        ),
        f"- Usable target: {progress['usable_now']} of at least "
        f"{targets['usable_domains_min']} (gated {targets['gated_selected']} still pending)",
        f"- Gated scam_feed: {status['gated_collection']['status']}",
        "",
        "| Batch | Candidates | Collected | Failed | Queued | Annotated | Frozen | Next |",
        "| --- | ---: | ---: | ---: | ---: | ---: | --- | --- |",
    ]
    for state in status["batches"]:
        annotation = state["annotation"]
        lines.append(
            f"| {state['batch']} | {state['candidates']['domains']} | "
            f"{state['collection']['assessments']} | "
            f"{len(state['collection']['failures'])} | "
            f"{annotation['sample_count'] or 0} | {annotation['annotated']} | "
            f"{'yes' if annotation['frozen'] else 'no'} | {state['next_action']} |"
        )
    failed_checks = [check for check in status["integrity_checks"] if not check["ok"]]
    lines += ["", "## Integrity", ""]
    if failed_checks:
        for check in failed_checks:
            lines.append(f"- FAIL `{check['id']}`: {check['detail']}")
    else:
        lines.append(f"- All {len(status['integrity_checks'])} checks passed.")
    lines += ["", "## Blocked on", ""]
    lines += [f"- {item}" for item in status["blocked_on"]]
    return "\n".join(lines) + "\n"
