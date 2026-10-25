"""Build leakage-checked, domain-grouped train/validation/test datasets.

Design rules enforced here:

* one label per registrable domain, never per URL;
* all pages from a domain stay in a single split;
* assessments that already saw a reputation label are excluded by default;
* labels are joined only by registrable domain, not by lexical similarity.
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
import random
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence
from urllib.parse import urlsplit

from .. import storage
from ..schemas import Assessment
from ..scoring.model import (
    FEATURE_GROUPS,
    FEATURE_SCHEMA_VERSION,
    feature_dict,
    leakage_reasons,
)
from . import DATASET_SCHEMA_VERSION

SPLITS = ("train", "val", "test")
DEFAULT_RATIOS = (0.7, 0.15, 0.15)
LABELS = ("benign", "suspicious", "malicious")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalise_domain(value: Any) -> str:
    from ..security import registrable_domain

    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    if raw.startswith("||"):
        raw = raw[2:].rstrip("^")
    if raw.startswith("*."):
        raw = raw[2:]
    if "://" not in raw:
        raw = "http://" + raw
    try:
        host = urlsplit(raw).hostname or ""
    except ValueError:
        return ""
    host = host.strip(".").lower()
    if not host:
        return ""
    return registrable_domain(host)


def load_labels(path: Path, *, default_label: str | None = None) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"label file not found: {path}")
    rows: list[dict[str, Any]] = []
    if path.suffix.lower() == ".json":
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict) and "labels" in payload:
            payload = payload["labels"]
        if isinstance(payload, dict):
            rows = [
                {"domain": domain, "label": label}
                for domain, label in payload.items()
                if isinstance(label, str)
            ]
        elif isinstance(payload, list):
            rows = [row for row in payload if isinstance(row, dict)]
        else:
            raise ValueError("label JSON must be a list, an object, or {'labels': [...]}")
    elif path.suffix.lower() == ".csv":
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            rows = [dict(row) for row in csv.DictReader(handle)]
    else:
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.split("#", 1)[0].strip()
            if not stripped:
                continue
            if "," in stripped:
                domain_value, label_value = stripped.split(",", 1)
                rows.append({"domain": domain_value, "label": label_value})
            else:
                tokens = stripped.split()
                if len(tokens) > 1 and tokens[0] in {"0.0.0.0", "127.0.0.1", "::", "::1"}:
                    stripped = tokens[-1]
                rows.append({"domain": stripped, "label": default_label or "malicious"})

    labels: dict[str, dict[str, Any]] = {}
    skipped = 0
    conflicts: list[dict[str, str]] = []
    for row in rows:
        domain = normalise_domain(row.get("domain") or row.get("url") or "")
        label = str(row.get("label") or row.get("expected") or default_label or "").strip().lower()
        if not domain or label not in LABELS:
            skipped += 1
            continue
        try:
            confidence = float(row.get("confidence") or 1.0)
        except (TypeError, ValueError):
            confidence = 1.0
        confidence = max(0.0, min(1.0, confidence))
        incoming = {
            "domain": domain,
            "label": label,
            "source": str(row.get("source") or path.stem)[:100],
            "confidence": confidence,
            "note": str(row.get("note") or row.get("notes") or "")[:1000],
        }
        existing = labels.get(domain)
        if existing and existing["label"] != label:
            conflicts.append({"domain": domain, "kept": existing["label"], "seen": label})
            if existing["confidence"] >= confidence:
                continue
        labels[domain] = incoming
    stats = {
        "path": str(path),
        "sha256": _sha256(path),
        "rows": len(rows),
        "imported_domains": len(labels),
        "skipped": skipped,
        "conflicts": conflicts[:20],
        "conflict_count": len(conflicts),
        "labels": dict(Counter(item["label"] for item in labels.values())),
    }
    return labels, stats


def load_labels_from_db() -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    labels: dict[str, dict[str, Any]] = {}
    for row in storage.iter_domain_labels():
        domain = normalise_domain(row.get("domain"))
        label = str(row.get("label") or "").strip().lower()
        if not domain or label not in LABELS:
            continue
        labels[domain] = {
            "domain": domain,
            "label": label,
            "source": str(row.get("source") or "database")[:100],
            "confidence": max(0.0, min(1.0, float(row.get("confidence") or 1.0))),
            "note": str(row.get("note") or "")[:1000],
        }
    stats = {
        "path": "sqlite:domain_labels",
        "sha256": None,
        "rows": len(labels),
        "imported_domains": len(labels),
        "skipped": 0,
        "conflicts": [],
        "conflict_count": 0,
        "labels": dict(Counter(item["label"] for item in labels.values())),
    }
    return labels, stats


def load_assessments_from_db() -> list[Assessment]:
    storage.init_db()
    return list(storage.iter_assessments())


def load_assessment_files(paths: Sequence[Path]) -> tuple[list[Assessment], list[dict[str, Any]]]:
    assessments: dict[str, Assessment] = {}
    errors: list[dict[str, Any]] = []
    for path in paths:
        if not path.exists():
            raise FileNotFoundError(f"assessment file not found: {path}")
        text = path.read_text(encoding="utf-8")
        stripped = text.lstrip()
        payloads: list[tuple[int, Any]] = []
        if stripped.startswith("["):
            try:
                payloads = list(enumerate(json.loads(text), start=1))
            except json.JSONDecodeError as exc:
                errors.append({"path": str(path), "line": 0, "error": str(exc)})
                continue
        else:
            for line_number, line in enumerate(text.splitlines(), start=1):
                if not line.strip():
                    continue
                try:
                    payloads.append((line_number, json.loads(line)))
                except json.JSONDecodeError as exc:
                    errors.append({"path": str(path), "line": line_number, "error": str(exc)})
        for line_number, payload in payloads:
            if not isinstance(payload, dict):
                errors.append({"path": str(path), "line": line_number, "error": "not an object"})
                continue
            payload.setdefault("normalized_url", payload.get("final_url") or payload.get("url"))
            try:
                assessment = Assessment.model_validate(payload)
            except Exception as exc:
                errors.append(
                    {
                        "path": str(path),
                        "line": line_number,
                        "error": f"{type(exc).__name__}: {str(exc)[:300]}",
                    }
                )
                continue
            assessments[assessment.id] = assessment
    ordered = sorted(assessments.values(), key=lambda item: (item.created_at, item.domain))
    return ordered, errors


def _allocate(total: int, ratios: Sequence[float]) -> list[int]:
    raw = [total * ratio for ratio in ratios]
    counts = [int(math.floor(value)) for value in raw]
    remainder = total - sum(counts)
    order = sorted(range(len(ratios)), key=lambda index: raw[index] - counts[index], reverse=True)
    for index in order[:remainder]:
        counts[index] += 1
    if total >= 3:
        for index in (1, 2):
            if counts[index] == 0:
                donors = [position for position, count in enumerate(counts) if count > 1]
                if donors:
                    donor = max(donors, key=lambda position: counts[position])
                    counts[donor] -= 1
                    counts[index] += 1
    return counts


def _assign_splits(domain_labels: dict[str, str], ratios: Sequence[float], seed: int) -> dict[str, str]:
    rng = random.Random(seed)
    by_label: dict[str, list[str]] = defaultdict(list)
    for domain, label in domain_labels.items():
        by_label[label].append(domain)
    assignment: dict[str, str] = {}
    for label in sorted(by_label):
        domains = sorted(by_label[label])
        rng.shuffle(domains)
        counts = _allocate(len(domains), ratios)
        cursor = 0
        for split, count in zip(SPLITS, counts):
            for domain in domains[cursor : cursor + count]:
                assignment[domain] = split
            cursor += count

    sample_counts = Counter(assignment.values())
    if len(domain_labels) >= 3:
        for split in ("val", "test"):
            if sample_counts[split] == 0:
                candidates = sorted(
                    domain for domain, assigned in assignment.items() if assigned == "train"
                )
                if candidates:
                    moved = candidates[-1]
                    assignment[moved] = split
                    sample_counts["train"] -= 1
                    sample_counts[split] += 1
    return assignment


def _split_warnings(samples: Sequence[dict[str, Any]]) -> list[str]:
    warnings: list[str] = []
    if len(samples) < 50:
        warnings.append("fewer than 50 samples: confidence intervals will be wide")
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for sample in samples:
        grouped[sample["split"]].append(sample)
    for split in SPLITS:
        rows = grouped.get(split, [])
        if len(rows) < 20:
            warnings.append(f"{split} split has fewer than 20 samples")
        targets = {int(row["target"]) for row in rows}
        if rows and len(targets) < 2:
            warnings.append(f"{split} split contains a single class")
    domains = defaultdict(set)
    for sample in samples:
        domains[sample["split"]].add(sample["domain"])
    if set(domains["train"]) & set(domains["val"]):
        warnings.append("domain overlap between train and val")
    if set(domains["train"]) & set(domains["test"]):
        warnings.append("domain overlap between train and test")
    if set(domains["val"]) & set(domains["test"]):
        warnings.append("domain overlap between val and test")
    return warnings


def build_dataset(
    assessments: Sequence[Assessment],
    labels: dict[str, dict[str, Any]],
    out_dir: Path,
    *,
    seed: int = 42,
    ratios: Sequence[float] = DEFAULT_RATIOS,
    include_suspicious: bool = False,
    allow_leakage: bool = False,
    per_domain_limit: int = 5,
    actions: Iterable[str] | None = None,
    force: bool = False,
    assessment_source: str = "sqlite:assessments",
    label_stats: dict[str, Any] | None = None,
    extra_warnings: Sequence[str] = (),
    uninspected_domains: Iterable[str] | None = None,
) -> dict[str, Any]:
    if len(ratios) != 3 or any(value < 0 for value in ratios) or sum(ratios) <= 0:
        raise ValueError("ratios must be three non-negative numbers")
    normalised_ratios = [float(value) / sum(ratios) for value in ratios]
    action_filter = set(actions) if actions else None
    uninspected = {
        normalise_domain(str(domain))
        for domain in (uninspected_domains or ())
        if str(domain).strip()
    }

    exclusions: Counter[str] = Counter()
    exclusion_examples: dict[str, list[str]] = defaultdict(list)
    records: list[dict[str, Any]] = []
    duplicates = 0
    for assessment in assessments:
        if action_filter and assessment.action.value not in action_filter:
            exclusions["action_filtered"] += 1
            continue
        domain = normalise_domain(assessment.domain or assessment.final_url or assessment.url)
        if not domain:
            exclusions["missing_domain"] += 1
            continue
        if domain in uninspected:
            exclusions["annotator_did_not_inspect"] += 1
            exclusion_examples["annotator_did_not_inspect"].append(domain)
            continue
        label_row = labels.get(domain)
        if label_row is None:
            exclusions["missing_label"] += 1
            exclusion_examples["missing_label"].append(domain)
            continue
        label = str(label_row["label"])
        if label == "suspicious" and not include_suspicious:
            exclusions["excluded_suspicious"] += 1
            exclusion_examples["excluded_suspicious"].append(domain)
            continue
        leaks = leakage_reasons(assessment)
        if leaks and not allow_leakage:
            exclusions["label_leakage"] += 1
            exclusion_examples["label_leakage"].append(f"{domain} ({', '.join(leaks)})")
            continue
        sample = {
            "assessment_id": assessment.id,
            "url": assessment.url,
            "normalized_url": assessment.normalized_url,
            "final_url": assessment.final_url,
            "domain": domain,
            "action": assessment.action.value,
            "assessed_at": assessment.created_at.isoformat(),
            "label": label,
            "target": 0 if label == "benign" else 1,
            "label_confidence": float(label_row.get("confidence") or 0.0),
            "label_source": str(label_row.get("source") or ""),
            "leakage": leaks,
            "features": feature_dict(assessment),
            "_created_at": assessment.created_at,
        }
        bad_features = [
            name for name, value in sample["features"].items() if not math.isfinite(float(value))
        ]
        if bad_features:
            exclusions["non_finite_features"] += 1
            exclusion_examples["non_finite_features"].append(
                f"{domain}: {', '.join(bad_features[:5])}"
            )
            continue
        records.append(sample)

    deduped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for record in records:
        key = (record["domain"], record["action"], record["normalized_url"])
        existing = deduped.get(key)
        if existing is not None:
            duplicates += 1
            if record["_created_at"] < existing["_created_at"]:
                continue
        deduped[key] = record

    grouped_by_domain: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in deduped.values():
        grouped_by_domain[record["domain"]].append(record)
    limited: list[dict[str, Any]] = []
    for domain, items in grouped_by_domain.items():
        items.sort(key=lambda item: item["_created_at"], reverse=True)
        if per_domain_limit > 0 and len(items) > per_domain_limit:
            exclusions["per_domain_limit"] += len(items) - per_domain_limit
            exclusion_examples["per_domain_limit"].append(
                f"{domain}: kept {per_domain_limit} of {len(items)}"
            )
        limited.extend(items[: per_domain_limit if per_domain_limit > 0 else None])

    if not limited:
        raise ValueError("no labeled, leakage-free samples were produced")
    domain_labels = {record["domain"]: record["label"] for record in limited}
    split_by_domain = _assign_splits(domain_labels, normalised_ratios, seed)
    for record in limited:
        record["split"] = split_by_domain[record["domain"]]
        record.pop("_created_at", None)
    order = {name: index for index, name in enumerate(SPLITS)}
    limited.sort(key=lambda item: (order[item["split"]], item["domain"], item["action"]))

    warnings = list(extra_warnings) + _split_warnings(limited)
    if exclusions["excluded_suspicious"]:
        warnings.append(
            "suspicious labels were excluded; rerun with --include-suspicious for a sensitivity check"
        )
    if exclusions["label_leakage"]:
        warnings.append(
            "assessments with known-label evidence were excluded to prevent label leakage"
        )
    if exclusions["annotator_did_not_inspect"]:
        warnings.append(
            "domains whose annotator note recorded a failed load were excluded as not "
            "inspectable, not as a trust judgement"
        )

    out_dir.mkdir(parents=True, exist_ok=True)
    dataset_path = out_dir / "dataset.jsonl"
    csv_path = out_dir / "dataset.csv"
    manifest_path = out_dir / "manifest.json"
    if not force:
        existing = [str(path) for path in (dataset_path, csv_path, manifest_path) if path.exists()]
        if existing:
            raise FileExistsError(
                "dataset files already exist; choose another directory or pass --force: "
                + ", ".join(existing)
            )

    with dataset_path.open("w", encoding="utf-8") as handle:
        for record in limited:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    metadata_fields = [
        "assessment_id",
        "url",
        "normalized_url",
        "final_url",
        "domain",
        "action",
        "assessed_at",
        "label",
        "target",
        "label_confidence",
        "label_source",
        "split",
        "leakage",
    ]
    feature_names = list(FEATURE_GROUPS["hybrid"])
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=[*metadata_fields, *feature_names], extrasaction="ignore"
        )
        writer.writeheader()
        for record in limited:
            row = {name: record.get(name, "") for name in metadata_fields}
            row["leakage"] = ";".join(record["leakage"])
            row.update(record["features"])
            writer.writerow(row)

    by_split: dict[str, Any] = {}
    for split in SPLITS:
        rows = [record for record in limited if record["split"] == split]
        by_split[split] = {
            "samples": len(rows),
            "domains": len({record["domain"] for record in rows}),
            "labels": dict(Counter(record["label"] for record in rows)),
            "targets": dict(Counter(str(record["target"]) for record in rows)),
        }
    manifest = {
        "schema_version": DATASET_SCHEMA_VERSION,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "created_at": _now(),
        "seed": seed,
        "ratios": dict(zip(SPLITS, [round(value, 4) for value in normalised_ratios])),
        "include_suspicious": include_suspicious,
        "allow_leakage": allow_leakage,
        "per_domain_limit": per_domain_limit,
        "actions": sorted(action_filter) if action_filter else "all",
        "samples": len(limited),
        "domains": len({record["domain"] for record in limited}),
        "labels": dict(Counter(record["label"] for record in limited)),
        "targets": dict(Counter(str(record["target"]) for record in limited)),
        "splits": by_split,
        "exclusions": dict(sorted(exclusions.items())),
        "exclusion_examples": {
            name: values[:20] for name, values in sorted(exclusion_examples.items())
        },
        "duplicates_removed": duplicates,
        "warnings": warnings,
        "assessment_source": assessment_source,
        "label_source": label_stats or {},
        "feature_names": feature_names,
        "feature_groups": {name: len(names) for name, names in FEATURE_GROUPS.items()},
        "files": {
            "dataset_jsonl": {
                "path": dataset_path.name,
                "sha256": _sha256(dataset_path),
                "bytes": dataset_path.stat().st_size,
            },
            "dataset_csv": {
                "path": csv_path.name,
                "sha256": _sha256(csv_path),
                "bytes": csv_path.stat().st_size,
            },
        },
    }
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def load_dataset(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"dataset not found: {path}")
    samples: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        sample = json.loads(line)
        if not isinstance(sample, dict):
            raise ValueError(f"{path}:{line_number}: sample is not an object")
        for field in ("assessment_id", "domain", "label", "target", "split", "features"):
            if field not in sample:
                raise ValueError(f"{path}:{line_number}: missing field '{field}'")
        if sample["split"] not in SPLITS:
            raise ValueError(f"{path}:{line_number}: invalid split '{sample['split']}'")
        samples.append(sample)
    manifest_path = path.with_name("manifest.json")
    manifest: dict[str, Any] = {}
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        version = manifest.get("feature_schema_version")
        if version is not None and int(version) != FEATURE_SCHEMA_VERSION:
            raise ValueError(
                f"dataset feature schema {version} does not match code "
                f"{FEATURE_SCHEMA_VERSION}; rebuild the dataset"
            )
    return samples, manifest


def subset(samples: Sequence[dict[str, Any]], split: str) -> list[dict[str, Any]]:
    return [sample for sample in samples if sample["split"] == split]
