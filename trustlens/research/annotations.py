"""Blinded annotation queues, inter-annotator agreement, and consensus labels.

The queue deliberately omits automated scores and evidence so that annotators
cannot anchor on the system being evaluated. Rule outputs live in ``key.json``,
which the coordinator keeps aside until labels are frozen.
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import random
import stat
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

from ..schemas import Assessment

LABELS = ("benign", "suspicious", "malicious")
LABEL_TO_ORDINAL = {label: index for index, label in enumerate(LABELS)}
QUEUE_FIELDS = ("sample_id", "url", "domain", "action")
ANNOTATION_FIELDS = ("sample_id", "url", "domain", "label", "confidence", "notes")
CONSENSUS_FIELDS = (
    "sample_id",
    "domain",
    "url",
    "assessment_id",
    "label",
    "confidence",
    "source",
    "annotator_a",
    "annotator_b",
    "note",
)
DISAGREEMENT_FIELDS = (
    "sample_id",
    "domain",
    "url",
    "a_label",
    "b_label",
    "a_confidence",
    "b_confidence",
    "a_notes",
    "b_notes",
    "adjudicated_label",
    "resolved",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sample_id(domain: str, seed: int) -> str:
    digest = hashlib.sha256(f"{seed}:{domain}".encode("utf-8")).hexdigest()
    return f"s_{digest[:10]}"


def _normalise_label(value: Any) -> str | None:
    label = str(value or "").strip().lower()
    aliases = {
        "legit": "benign",
        "legitimate": "benign",
        "safe": "benign",
        "malware": "malicious",
        "phishing": "malicious",
        "sus": "suspicious",
        "unsure": "suspicious",
    }
    label = aliases.get(label, label)
    return label if label in LABELS else None


def _confidence(value: Any, default: float = 1.0) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    if not math.isfinite(parsed):
        return default
    return round(max(0.0, min(1.0, parsed)), 3)


def read_csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def write_csv(path: Path, fieldnames: Sequence[str], rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({name: row.get(name, "") for name in fieldnames})


def _pick_representative(assessments: Iterable[Assessment]) -> list[Assessment]:
    chosen: dict[str, Assessment] = {}
    for assessment in assessments:
        domain = (assessment.domain or "").strip().lower().rstrip(".")
        if not domain:
            continue
        current = chosen.get(domain)
        if current is None:
            chosen[domain] = assessment
            continue
        candidate_key = (assessment.action.value == "browse", assessment.created_at)
        current_key = (current.action.value == "browse", current.created_at)
        if candidate_key > current_key:
            chosen[domain] = assessment
    return sorted(chosen.values(), key=lambda item: item.domain)


def build_queue(
    assessments: Sequence[Assessment],
    out_dir: Path,
    *,
    overlap: float = 0.2,
    seed: int = 42,
    limit: int = 0,
    force: bool = False,
    single_annotator: bool = False,
) -> dict[str, Any]:
    """Create blinded sheets for one or two annotators and a coordinator-only key."""
    if not 0.0 <= overlap <= 1.0:
        raise ValueError("overlap must be between 0 and 1")
    representatives = _pick_representative(assessments)
    if not representatives:
        raise ValueError("no assessments with a domain were supplied")
    random.Random(seed).shuffle(representatives)
    if limit > 0:
        representatives = representatives[:limit]

    total = len(representatives)
    shared = (
        0
        if single_annotator
        else min(total, max(1, int(round(total * overlap)))) if overlap > 0 else 0
    )
    sample_rows: list[dict[str, Any]] = []
    annotator_a: list[dict[str, Any]] = []
    annotator_b: list[dict[str, Any]] = []
    key_samples: list[dict[str, Any]] = []
    assignments: Counter[str] = Counter()

    for index, assessment in enumerate(representatives):
        if single_annotator:
            assignment = "a_only"
        elif index < shared:
            assignment = "overlap"
        elif (index - shared) % 2 == 0:
            assignment = "a_only"
        else:
            assignment = "b_only"
        assignments[assignment] += 1
        sid = _sample_id(assessment.domain, seed)
        row = {
            "sample_id": sid,
            "url": assessment.final_url or assessment.url,
            "domain": assessment.domain,
            "action": assessment.action.value,
        }
        sample_rows.append(row)
        if assignment in {"overlap", "a_only"}:
            annotator_a.append({**row, "label": "", "confidence": "", "notes": ""})
        if assignment in {"overlap", "b_only"}:
            annotator_b.append({**row, "label": "", "confidence": "", "notes": ""})
        key_samples.append(
            {
                **row,
                "assessment_id": assessment.id,
                "created_at": assessment.created_at.isoformat(),
                "rule_risk": assessment.overall_risk,
                "rule_level": assessment.overall_level.value,
                "rule_confidence": assessment.confidence,
                "assignment": assignment,
            }
        )

    out_dir.mkdir(parents=True, exist_ok=True)
    targets = {
        "queue.csv": out_dir / "queue.csv",
        "annotator_a.csv": out_dir / "annotator_a.csv",
        "annotator_b.csv": out_dir / "annotator_b.csv",
        "key.json": out_dir / "key.json",
    }
    if not force:
        existing = [str(path) for path in targets.values() if path.exists()]
        if existing:
            raise FileExistsError(
                "annotation files already exist; choose another directory or pass --force: "
                + ", ".join(existing)
            )

    write_csv(targets["queue.csv"], QUEUE_FIELDS, sample_rows)
    write_csv(targets["annotator_a.csv"], ANNOTATION_FIELDS, annotator_a)
    write_csv(targets["annotator_b.csv"], ANNOTATION_FIELDS, annotator_b)
    key = {
        "schema_version": 1,
        "created_at": _now(),
        "seed": seed,
        "overlap": 0.0 if single_annotator else overlap,
        "single_annotator": single_annotator,
        "sample_count": total,
        "assignments": dict(sorted(assignments.items())),
        "annotator_a_count": len(annotator_a),
        "annotator_b_count": len(annotator_b),
        "blinding_note": (
            "The annotator must not see key.json while labelling. Labels describe the "
            "website as a typical visitor would encounter it. This is a single-annotator "
            "dataset; no second sheet exists and no inter-rater agreement can be claimed."
            if single_annotator
            else "Annotators must not see key.json before both annotation sheets are frozen. "
            "Labels describe the website as a typical visitor would encounter it."
        ),
        "samples": key_samples,
    }
    targets["key.json"].write_text(json.dumps(key, indent=2), encoding="utf-8")
    return key


def load_annotations(path: Path) -> dict[str, dict[str, Any]]:
    """Load a filled annotator sheet. Blank rows are ignored."""
    if not path.exists():
        raise FileNotFoundError(f"annotation file not found: {path}")
    annotations: dict[str, dict[str, Any]] = {}
    for line_number, row in enumerate(read_csv_rows(path), start=2):
        sample_id = str(row.get("sample_id") or "").strip()
        if not sample_id:
            continue
        raw_label = (
            row.get("label") or row.get("annotation") or row.get("adjudicated_label")
        )
        if not str(raw_label or "").strip():
            continue
        label = _normalise_label(raw_label)
        if label is None:
            raise ValueError(
                f"{path}:{line_number}: label must be one of {', '.join(LABELS)}"
            )
        annotations[sample_id] = {
            "sample_id": sample_id,
            "label": label,
            "confidence": _confidence(row.get("confidence")),
            "notes": str(row.get("notes") or row.get("note") or "").strip()[:1000],
        }
    return annotations


def _sheet_role(path: Path, role: str | None) -> str:
    if role:
        selected = role.strip().lower()
        if selected not in {"a", "b"}:
            raise ValueError("annotator role must be 'a' or 'b'")
        return selected
    stem = path.stem.lower().replace("-", "_")
    if "annotator_a" in stem or stem.endswith("_a"):
        return "a"
    if "annotator_b" in stem or stem.endswith("_b"):
        return "b"
    raise ValueError(
        f"cannot infer annotator role from {path.name}; pass the role explicitly"
    )


def validate_sheet(
    path: Path, key: dict[str, Any], *, role: str | None = None
) -> dict[str, Any]:
    """Check a completed sheet against its queue before it is frozen."""
    selected_role = _sheet_role(path, role)
    samples: dict[str, dict[str, Any]] = {}
    for item in key.get("samples", []):
        sample_id = str(item.get("sample_id") or "").strip()
        if not sample_id:
            continue
        if sample_id in samples:
            raise ValueError(f"key contains duplicate sample_id {sample_id}")
        samples[sample_id] = item
    if not samples:
        raise ValueError("key contains no samples")

    expected = {
        sample_id
        for sample_id, item in samples.items()
        if item.get("assignment") in {"overlap", f"{selected_role}_only"}
    }
    if not expected:
        raise ValueError(f"key has no sites assigned to annotator {selected_role.upper()}")

    rows = read_csv_rows(path)
    issues: list[str] = []
    seen: set[str] = set()
    completed: set[str] = set()
    labels: Counter[str] = Counter()
    for line_number, row in enumerate(rows, start=2):
        sample_id = str(row.get("sample_id") or "").strip()
        if not sample_id:
            issues.append(f"line {line_number}: missing sample_id")
            continue
        if sample_id in seen:
            issues.append(f"line {line_number}: duplicate sample_id {sample_id}")
            continue
        seen.add(sample_id)
        item = samples.get(sample_id)
        if item is None:
            issues.append(f"line {line_number}: sample_id {sample_id} is not in the key")
            continue
        if sample_id not in expected:
            issues.append(
                f"line {line_number}: {sample_id} is not assigned to annotator "
                f"{selected_role.upper()}"
            )
        sheet_url = str(row.get("url") or "").strip()
        if sheet_url and sheet_url != str(item.get("url") or "").strip():
            issues.append(f"line {line_number}: URL does not match the queue")

        raw_label = str(row.get("label") or "").strip().lower()
        label = None
        if not raw_label:
            issues.append(f"line {line_number}: missing label")
        elif raw_label not in LABEL_TO_ORDINAL:
            issues.append(
                f"line {line_number}: label must be one of {', '.join(LABELS)}"
            )
        else:
            label = raw_label
            labels[label] += 1
            completed.add(sample_id)

        raw_confidence = str(row.get("confidence") or "").strip()
        if not raw_confidence:
            issues.append(f"line {line_number}: missing confidence")
        else:
            try:
                confidence = float(raw_confidence)
            except ValueError:
                issues.append(f"line {line_number}: confidence must be a number")
            else:
                if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
                    issues.append(
                        f"line {line_number}: confidence must be between 0.0 and 1.0"
                    )

        notes = str(row.get("notes") or "").strip()
        if label in {"suspicious", "malicious"} and not notes:
            issues.append(
                f"line {line_number}: notes are required for a {label} label"
            )

    missing = sorted(expected - seen)
    if missing:
        preview = ", ".join(missing[:5])
        suffix = "" if len(missing) <= 5 else f" and {len(missing) - 5} more"
        issues.append(f"{len(missing)} assigned site(s) missing from the sheet: {preview}{suffix}")

    return {
        "ok": not issues,
        "role": selected_role,
        "sheet": str(path),
        "expected": len(expected),
        "rows": len(rows),
        "annotated": len(completed & expected),
        "labels": dict(sorted(labels.items())),
        "issues": issues,
    }


def freeze_sheet(
    sheet_path: Path,
    key_path: Path,
    *,
    role: str | None = None,
) -> tuple[Path, Path, dict[str, Any]]:
    """Archive a validated sheet read-only and record its hash."""
    key_raw = key_path.read_bytes()
    key = json.loads(key_raw.decode("utf-8"))
    if "samples" not in key:
        raise ValueError("annotation key is missing a samples list")
    report = validate_sheet(sheet_path, key, role=role)
    if report["issues"]:
        preview = "\n- ".join(report["issues"][:20])
        remainder = len(report["issues"]) - 20
        if remainder > 0:
            preview += f"\n- ... and {remainder} more issue(s)"
        raise ValueError(f"sheet failed freeze validation:\n- {preview}")

    frozen_at = datetime.now(timezone.utc)
    stamp = frozen_at.strftime("%Y%m%dT%H%M%SZ")
    archive_dir = sheet_path.parent / "frozen"
    archive_dir.mkdir(parents=True, exist_ok=True)
    archive_path = archive_dir / f"{sheet_path.stem}_{stamp}.csv"
    if archive_path.exists():
        raise FileExistsError(f"frozen archive already exists: {archive_path}")
    raw = sheet_path.read_bytes()
    archive_path.write_bytes(raw)
    os.chmod(archive_path, stat.S_IREAD)

    record = {
        "schema_version": 1,
        "frozen_at": frozen_at.isoformat(),
        "role": report["role"],
        "source_sheet": sheet_path.name,
        "archive": archive_path.name,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "expected": report["expected"],
        "annotated": report["annotated"],
        "labels": report["labels"],
        "key_file": key_path.name,
        "key_sha256": hashlib.sha256(key_raw).hexdigest(),
    }
    record_path = archive_dir / f"{sheet_path.stem}_{stamp}.freeze.json"
    record_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return archive_path, record_path, record


def _kappa_values(
    a_labels: Sequence[str], b_labels: Sequence[str], power: float | None
) -> tuple[float | None, float | None, float | None, list[list[int]]]:
    size = len(LABELS)
    matrix = [[0 for _ in range(size)] for _ in range(size)]
    for a_label, b_label in zip(a_labels, b_labels):
        matrix[LABEL_TO_ORDINAL[a_label]][LABEL_TO_ORDINAL[b_label]] += 1
    total = len(a_labels)
    if total == 0:
        return None, None, None, matrix
    row_totals = [sum(row) for row in matrix]
    column_totals = [sum(matrix[r][c] for r in range(size)) for c in range(size)]

    def weighted(observed: float, expected: float) -> float | None:
        denominator = 1.0 - expected
        if abs(denominator) < 1e-12:
            return None
        return round((observed - expected) / denominator, 4)

    if power is None:
        observed = sum(matrix[i][i] for i in range(size)) / total
        expected = sum(row_totals[i] * column_totals[i] for i in range(size)) / (total * total)
        return round(observed, 4), round(expected, 4), weighted(observed, expected), matrix

    observed = 0.0
    expected = 0.0
    for i in range(size):
        for j in range(size):
            distance = abs(i - j) / (size - 1)
            weight = 1.0 - distance**power
            observed += weight * matrix[i][j]
            expected += weight * row_totals[i] * column_totals[j] / total
    observed /= total
    expected /= total
    return round(observed, 4), round(expected, 4), weighted(observed, expected), matrix


def agreement_report(
    annotator_a: dict[str, dict[str, Any]],
    annotator_b: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    shared = sorted(set(annotator_a) & set(annotator_b))
    a_labels = [annotator_a[sid]["label"] for sid in shared]
    b_labels = [annotator_b[sid]["label"] for sid in shared]
    observed, expected, kappa, matrix = _kappa_values(a_labels, b_labels, None)
    _, _, linear, _ = _kappa_values(a_labels, b_labels, 1.0)
    _, _, quadratic, _ = _kappa_values(a_labels, b_labels, 2.0)
    disagreements = [
        {
            "sample_id": sid,
            "a_label": annotator_a[sid]["label"],
            "b_label": annotator_b[sid]["label"],
            "a_confidence": annotator_a[sid]["confidence"],
            "b_confidence": annotator_b[sid]["confidence"],
            "a_notes": annotator_a[sid]["notes"],
            "b_notes": annotator_b[sid]["notes"],
        }
        for sid in shared
        if annotator_a[sid]["label"] != annotator_b[sid]["label"]
    ]
    return {
        "n_overlap": len(shared),
        "n_a_only": len(set(annotator_a) - set(annotator_b)),
        "n_b_only": len(set(annotator_b) - set(annotator_a)),
        "observed_agreement": observed,
        "expected_agreement": expected,
        "cohen_kappa": kappa,
        "cohen_kappa_linear": linear,
        "cohen_kappa_quadratic": quadratic,
        "confusion_matrix": {
            "labels": list(LABELS),
            "rows_annotator_a": {
                label: dict(zip(LABELS, matrix[index])) for index, label in enumerate(LABELS)
            },
        },
        "disagreements": disagreements,
        "interpretation": _kappa_interpretation(kappa),
    }


def _kappa_interpretation(kappa: float | None) -> str:
    if kappa is None:
        return "not estimable"
    if kappa < 0.0:
        return "poor (below chance)"
    if kappa < 0.20:
        return "slight"
    if kappa < 0.40:
        return "fair"
    if kappa < 0.60:
        return "moderate"
    if kappa < 0.80:
        return "substantial"
    return "almost perfect"


def agreement_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Annotation agreement",
        "",
        f"- Double-annotated sites: {report['n_overlap']}",
        f"- Observed agreement: {_format(report['observed_agreement'], percent=True)}",
        f"- Cohen's kappa: {_format(report['cohen_kappa'])} ({report['interpretation']})",
        f"- Linear weighted kappa: {_format(report['cohen_kappa_linear'])}",
        f"- Quadratic weighted kappa: {_format(report['cohen_kappa_quadratic'])}",
        f"- Disagreements: {len(report['disagreements'])}",
        "",
        "## Confusion matrix (rows = annotator A)",
        "",
        "| A \\ B | benign | suspicious | malicious |",
        "| --- | ---: | ---: | ---: |",
    ]
    rows = report["confusion_matrix"]["rows_annotator_a"]
    for label in LABELS:
        values = rows[label]
        lines.append(
            f"| {label} | {values['benign']} | {values['suspicious']} | {values['malicious']} |"
        )
    if report["disagreements"]:
        lines.extend(["", "## Disagreements", "", "| Sample | A | B |", "| --- | --- | --- |"])
        for item in report["disagreements"]:
            lines.append(f"| {item['sample_id']} | {item['a_label']} | {item['b_label']} |")
    lines.append("")
    return "\n".join(lines)


AUDIT_MIN_DELAY_DAYS = 7


def build_audit_queue(
    sheet_path: Path,
    key_path: Path,
    out_dir: Path,
    *,
    fraction: float = 0.15,
    min_domains: int = 40,
    seed: int = 123,
    force: bool = False,
) -> dict[str, Any]:
    """Create a delayed, blinded intra-rater audit sheet and hidden reference."""
    if not 0.0 < fraction <= 1.0:
        raise ValueError("fraction must be greater than 0 and at most 1")
    if min_domains < 1:
        raise ValueError("min_domains must be at least 1")
    key = load_key(key_path)
    original = load_annotations(sheet_path)
    if not original:
        raise ValueError("the source sheet has no completed labels to audit")
    samples = {
        str(item.get("sample_id")): item
        for item in key.get("samples", [])
        if item.get("sample_id")
    }
    available = sorted(sample_id for sample_id in original if sample_id in samples)
    if not available:
        raise ValueError("no completed labels match the annotation key")
    target = min(len(available), max(min_domains, int(round(len(available) * fraction))))

    by_label: dict[str, list[str]] = {}
    for sample_id in available:
        by_label.setdefault(original[sample_id]["label"], []).append(sample_id)
    rng = random.Random(seed)
    for group in by_label.values():
        rng.shuffle(group)

    selected: list[str] = []
    for label in sorted(by_label):
        if len(selected) >= target:
            break
        selected.append(by_label[label][0])
    pool = [sample_id for sample_id in available if sample_id not in set(selected)]
    rng.shuffle(pool)
    selected.extend(pool[: max(0, target - len(selected))])
    selected = sorted(set(selected))
    selected_set = set(selected)

    rows = []
    reduced_samples = []
    for sample_id in selected:
        item = samples[sample_id]
        rows.append(
            {
                "sample_id": sample_id,
                "url": item.get("url", ""),
                "domain": item.get("domain", ""),
                "action": item.get("action", ""),
                "label": "",
                "confidence": "",
                "notes": "",
            }
        )
        reduced_samples.append({**item, "assignment": "a_only"})

    out_dir.mkdir(parents=True, exist_ok=True)
    sheet_target = out_dir / "annotator_a_audit.csv"
    key_target = out_dir / "audit_key.json"
    reference_target = out_dir / "audit_reference.json"
    targets = (sheet_target, key_target, reference_target)
    if not force:
        existing = [str(path) for path in targets if path.exists()]
        if existing:
            raise FileExistsError(
                "audit artifacts already exist; choose another directory or pass --force: "
                + ", ".join(existing)
            )

    audit_key = {
        "schema_version": 1,
        "created_at": _now(),
        "seed": seed,
        "purpose": "delayed_blind_intra_rater_audit",
        "source_sheet": sheet_path.name,
        "source_sheet_sha256": hashlib.sha256(sheet_path.read_bytes()).hexdigest(),
        "single_annotator": True,
        "sample_count": len(reduced_samples),
        "assignments": {"a_only": len(reduced_samples)},
        "annotator_a_count": len(reduced_samples),
        "annotator_b_count": 0,
        "blinding_note": (
            "Audit sheet only. The original labels are held in audit_reference.json and "
            "must not be shown to the annotator during the audit."
        ),
        "samples": reduced_samples,
    }
    write_csv(sheet_target, ANNOTATION_FIELDS, rows)
    key_target.write_text(json.dumps(audit_key, indent=2), encoding="utf-8")

    delay = timedelta(days=AUDIT_MIN_DELAY_DAYS)
    not_before = datetime.now(timezone.utc) + delay
    reference = {
        "schema_version": 1,
        "created_at": _now(),
        "mode": "delayed_blind_intra_rater_audit",
        "source_sheet": str(sheet_path),
        "source_sheet_sha256": audit_key["source_sheet_sha256"],
        "audit_sheet": str(sheet_target),
        "audit_sheet_sha256": hashlib.sha256(sheet_target.read_bytes()).hexdigest(),
        "audit_key": str(key_target),
        "audit_key_sha256": hashlib.sha256(key_target.read_bytes()).hexdigest(),
        "seed": seed,
        "fraction": fraction,
        "min_domains": min_domains,
        "available": len(available),
        "selected": len(selected),
        "by_label": {
            label: sum(1 for sid in selected if original[sid]["label"] == label)
            for label in sorted(by_label)
        },
        "not_before": not_before.isoformat(),
        "delay_days": AUDIT_MIN_DELAY_DAYS,
        "note": (
            "Re-label this sheet after not_before without viewing the original labels. "
            "The result is intra-rater consistency, not inter-rater reliability."
        ),
        "rows": [
            {
                "sample_id": sample_id,
                **original[sample_id],
            }
            for sample_id in selected
        ],
    }
    reference_target.write_text(json.dumps(reference, indent=2), encoding="utf-8")
    return reference


def audit_report(
    original: dict[str, dict[str, Any]],
    audit: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    report = agreement_report(original, audit)
    report["mode"] = "delayed_blind_intra_rater_audit"
    report["note"] = (
        "The same annotator re-labelled a seeded sample without access to the original "
        "labels after the recorded delay. This is intra-rater consistency, not "
        "inter-rater reliability, and it does not establish label correctness."
    )
    return report


def audit_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Delayed blind intra-rater audit",
        "",
        "**Intra-rater consistency, not inter-rater reliability.**",
        "",
        f"- Audited sites: {report['n_overlap']}",
        f"- Observed agreement: {_format(report['observed_agreement'], percent=True)}",
        f"- Cohen's kappa: {_format(report['cohen_kappa'])}",
        f"- Quadratic weighted kappa: {_format(report['cohen_kappa_quadratic'])}",
        f"- Disagreements: {len(report['disagreements'])}",
        "",
        "## Confusion matrix (rows = original labels)",
        "",
        "| Original \\ Audit | benign | suspicious | malicious |",
        "| --- | ---: | ---: | ---: |",
    ]
    rows = report["confusion_matrix"]["rows_annotator_a"]
    for label in LABELS:
        values = rows[label]
        lines.append(
            f"| {label} | {values['benign']} | {values['suspicious']} | {values['malicious']} |"
        )
    lines.extend(
        [
            "",
            "Review trigger: observed agreement below 0.80 or quadratic weighted kappa below 0.60.",
            "",
        ]
    )
    return "\n".join(lines)


def _format(value: Any, percent: bool = False) -> str:
    if value is None:
        return "n/a"
    if percent:
        return f"{float(value):.1%}"
    return f"{float(value):.3f}"


def load_key(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"annotation key not found: {path}")
    key = json.loads(path.read_text(encoding="utf-8"))
    if "samples" not in key:
        raise ValueError("annotation key is missing a samples list")
    return key


def merge_annotations(
    annotator_a: dict[str, dict[str, Any]],
    annotator_b: dict[str, dict[str, Any]],
    key: dict[str, Any],
    adjudications: dict[str, dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """Build consensus labels, excluding unresolved disagreements by default."""
    adjudications = adjudications or {}
    samples = {
        str(item.get("sample_id")): item
        for item in key.get("samples", [])
        if item.get("sample_id")
    }
    unknown = (set(annotator_a) | set(annotator_b)) - set(samples)
    if unknown:
        raise ValueError(f"{len(unknown)} annotation(s) are not present in the key")

    consensus: list[dict[str, Any]] = []
    disagreements: list[dict[str, Any]] = []
    sources: Counter[str] = Counter()
    for sample_id in sorted(set(annotator_a) | set(annotator_b)):
        item = samples[sample_id]
        a_row = annotator_a.get(sample_id)
        b_row = annotator_b.get(sample_id)
        a_label = a_row["label"] if a_row else ""
        b_label = b_row["label"] if b_row else ""
        adjudication = adjudications.get(sample_id)
        note = ""
        if a_row and b_row and a_label == b_label:
            label = a_label
            confidence = round((a_row["confidence"] + b_row["confidence"]) / 2, 3)
            source = "double_agreement"
            note = a_row["notes"] or b_row["notes"]
        elif a_row and b_row and a_label != b_label:
            disagreement = {
                "sample_id": sample_id,
                "domain": item.get("domain", ""),
                "url": item.get("url", ""),
                "a_label": a_label,
                "b_label": b_label,
                "a_confidence": a_row["confidence"],
                "b_confidence": b_row["confidence"],
                "a_notes": a_row["notes"],
                "b_notes": b_row["notes"],
                "adjudicated_label": "",
                "resolved": False,
            }
            if adjudication:
                label = adjudication["label"]
                confidence = adjudication["confidence"]
                source = "adjudicated"
                note = adjudication["notes"]
                disagreement["adjudicated_label"] = label
                disagreement["resolved"] = True
                disagreements.append(disagreement)
            else:
                disagreements.append(disagreement)
                sources["excluded_disagreement"] += 1
                continue
        elif a_row or b_row:
            row = a_row or b_row
            label = row["label"]
            confidence = row["confidence"]
            source = "single_annotator"
            note = row["notes"]
        else:
            continue
        sources[source] += 1
        consensus.append(
            {
                "sample_id": sample_id,
                "domain": item.get("domain", ""),
                "url": item.get("url", ""),
                "assessment_id": item.get("assessment_id", ""),
                "label": label,
                "confidence": confidence,
                "source": source,
                "annotator_a": a_label,
                "annotator_b": b_label,
                "note": note,
            }
        )
    summary = {
        "total_annotated": len(set(annotator_a) | set(annotator_b)),
        "consensus_count": len(consensus),
        "unresolved_count": sum(1 for item in disagreements if not item["resolved"]),
        "sources": dict(sorted(sources.items())),
        "labels": dict(Counter(row["label"] for row in consensus)),
        "adjudications_supplied": len(adjudications),
    }
    return consensus, disagreements, summary


def write_merge_outputs(
    consensus_path: Path,
    disagreement_path: Path,
    consensus: Sequence[dict[str, Any]],
    disagreements: Sequence[dict[str, Any]],
    summary: dict[str, Any],
) -> None:
    write_csv(consensus_path, CONSENSUS_FIELDS, consensus)
    write_csv(disagreement_path, DISAGREEMENT_FIELDS, disagreements)
    summary_path = consensus_path.with_name(consensus_path.stem + "_summary.json")
    summary_path.write_text(
        json.dumps({**summary, "created_at": _now()}, indent=2), encoding="utf-8"
    )
