"""Command-line interface for scanning, labeling, and serving TrustLens."""

from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import importlib
import json
import shutil
import socket
import sqlite3
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import ENGINE_VERSION, storage
from .config import PACKAGE_ROOT, PROJECT_ROOT, settings
from .pipeline import Assessor
from .research.candidates import GATED_COLLECTION
from .schemas import Action, Assessment
from .security import UnsafeURLError, registrable_domain


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trustlens",
        description="Evidence-grounded website trust assessment (local research prototype)",
    )
    parser.add_argument("--version", action="version", version=f"TrustLens {ENGINE_VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="assess one URL")
    scan.add_argument("url")
    scan.add_argument("--action", choices=[action.value for action in Action], default="browse")
    scan.add_argument("--json", action="store_true", help="print the full assessment as JSON")
    scan.add_argument("--force", action="store_true", help="ignore the assessment cache")
    scan.add_argument("--quiet", action="store_true", help="print only the score and headline")

    guard = sub.add_parser("guard", help="one-line allow/warn/block decision")
    guard.add_argument("url")
    guard.add_argument("--action", choices=[action.value for action in Action], default="browse")

    batch = sub.add_parser("batch", help="assess URLs from a text file or CSV")
    batch.add_argument("file")
    batch.add_argument("--action", choices=[action.value for action in Action], default="browse")
    batch.add_argument("--out", default="", help="write JSONL results to this path")
    batch.add_argument("--full", action="store_true", help="write full assessment objects")
    batch.add_argument(
        "--resume", action="store_true", help="skip URLs already completed in --out"
    )
    batch.add_argument("--force", action="store_true")
    batch.add_argument("--limit", type=int, default=0)
    batch.add_argument(
        "--allow-gated",
        action="store_true",
        help="visit CSV rows marked as requiring explicit confirmation",
    )

    label = sub.add_parser("label", help="add or update a local domain label")
    label.add_argument("domain")
    label.add_argument("--label", required=True, choices=["benign", "suspicious", "malicious"])
    label.add_argument("--source", default="manual")
    label.add_argument("--confidence", type=float, default=1.0)
    label.add_argument("--note", default="")

    import_labels = sub.add_parser(
        "import-labels", help="import labels from CSV, JSON, or a plaintext blocklist"
    )
    import_labels.add_argument("file")
    import_labels.add_argument("--source", default="import")
    import_labels.add_argument(
        "--label",
        default="malicious",
        choices=["benign", "suspicious", "malicious"],
        help="label applied to plaintext blocklist entries",
    )

    sub.add_parser("stats", help="show database statistics")
    sub.add_parser("list", help="list recent assessments")
    sub.add_parser("init", help="initialise the local database")
    doctor = sub.add_parser("doctor", help="check that this installation is ready to run")
    doctor.add_argument("--json", action="store_true", help="print machine-readable results")

    serve = sub.add_parser("serve", help="start the local API and dashboard")
    serve.add_argument("--host", default=settings().host)
    serve.add_argument("--port", type=int, default=settings().port)
    serve.add_argument("--reload", action="store_true")

    research = sub.add_parser("research", help="annotation, dataset, training, and evaluation")
    research_sub = research.add_subparsers(dest="research_command", required=True)

    candidates = research_sub.add_parser(
        "candidates", help="build the gated Round 2 candidate manifest"
    )
    candidates.add_argument("--out-dir", default="data/candidates")
    candidates.add_argument("--curated", default="data/candidates/round2_curated.csv")
    candidates.add_argument("--pilot", default="data/candidates/pilot.csv")
    candidates.add_argument("--feed-url", default="https://openphish.com/feed.txt")
    candidates.add_argument(
        "--feed-file", default="", help="read a local feed snapshot instead of the network"
    )
    candidates.add_argument("--feed-source", default="OpenPhish public feed")
    candidates.add_argument("--seed", type=int, default=11)
    candidates.add_argument("--scam", type=int, default=20)
    candidates.add_argument("--ambiguous", type=int, default=8)
    candidates.add_argument("--benign", type=int, default=8)
    candidates.add_argument("--force", action="store_true")

    main_candidates = research_sub.add_parser(
        "main-candidates", help="build the Tranco + public-feed main candidate manifest"
    )
    main_candidates.add_argument("--out-dir", default="data/candidates")
    main_candidates.add_argument(
        "--tranco-file", default="", help="local Tranco CSV or zip snapshot"
    )
    main_candidates.add_argument(
        "--tranco-url", default="https://tranco-list.eu/top-1m.csv.zip"
    )
    main_candidates.add_argument("--openphish-file", default="")
    main_candidates.add_argument(
        "--openphish-url", default="https://openphish.com/feed.txt"
    )
    main_candidates.add_argument("--urlhaus-file", default="")
    main_candidates.add_argument(
        "--urlhaus-url", default="https://urlhaus.abuse.ch/downloads/csv_online/"
    )
    main_candidates.add_argument("--seed", type=int, default=42)
    main_candidates.add_argument("--established", type=int, default=260)
    main_candidates.add_argument("--tail", type=int, default=100)
    main_candidates.add_argument("--scam", type=int, default=140)
    main_candidates.add_argument("--reserve-established", type=int, default=80)
    main_candidates.add_argument("--reserve-tail", type=int, default=30)
    main_candidates.add_argument("--reserve-scam", type=int, default=50)
    main_candidates.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="additional candidate CSV whose domains must be excluded; may be repeated",
    )
    main_candidates.add_argument("--force", action="store_true")

    queue = research_sub.add_parser("queue", help="build blinded annotation sheets")
    queue.add_argument("--out", default="data/annotations/round1")
    queue.add_argument("--assessments", nargs="*", default=[])
    queue.add_argument("--overlap", type=float, default=0.2)
    queue.add_argument(
        "--single-annotator",
        action="store_true",
        help="assign every site to annotator A and leave the B sheet empty",
    )
    queue.add_argument("--seed", type=int, default=42)
    queue.add_argument("--limit", type=int, default=0)
    queue.add_argument("--force", action="store_true")

    freeze = research_sub.add_parser(
        "freeze", help="validate and freeze a completed annotator sheet"
    )
    freeze.add_argument("--sheet", required=True, help="completed annotator CSV")
    freeze.add_argument("--key", required=True, help="coordinator-only queue key")
    freeze.add_argument("--role", choices=["a", "b"], default="")

    main_status = research_sub.add_parser(
        "main-status",
        help="summarise main-dataset collection, annotation, and gate state",
    )
    main_status.add_argument(
        "--out",
        default="",
        help="write the JSON status here (default: data/main_collection_status.json)",
    )
    main_status.add_argument("--markdown", default="", help="also write a Markdown summary")

    feed_labels = research_sub.add_parser(
        "feed-labels",
        help="build a malicious label set from public abuse feeds for the primary evaluation",
    )
    feed_labels.add_argument(
        "--out", default="data/labels/feed/labels.csv", help="label CSV to write"
    )
    feed_labels.add_argument(
        "--manifest", default="", help="provenance JSON (default: <out>.json)"
    )
    feed_labels.add_argument("--openphish-url", default="https://openphish.com/feed.txt")
    feed_labels.add_argument("--openphish-file", default="", help="use a saved feed snapshot")
    feed_labels.add_argument(
        "--urlhaus-url", default="https://urlhaus.abuse.ch/downloads/csv_online/"
    )
    feed_labels.add_argument("--urlhaus-file", default="", help="use a saved feed snapshot")
    feed_labels.add_argument("--no-urlhaus", action="store_true", help="label from OpenPhish only")
    feed_labels.add_argument(
        "--snapshot-dir",
        default="",
        help="also save the raw feed text here so the label set can be rebuilt offline",
    )
    feed_labels.add_argument(
        "--exclude-domains",
        action="append",
        default=[],
        metavar="CSV",
        help="candidate CSV whose domains must not be labelled (repeatable)",
    )
    feed_labels.add_argument(
        "--max-age-days",
        type=int,
        default=7,
        help="treat a feed older than this as stale and refuse to label from it",
    )

    feed_cand = research_sub.add_parser(
        "feed-candidates",
        help="split the feed label CSV into gated crawl batches (reads label metadata only)",
    )
    feed_cand.add_argument("--labels", default="data/labels/feed/labels.csv")
    feed_cand.add_argument("--out-dir", default="data/candidates")
    feed_cand.add_argument("--seed", type=int, default=42)
    feed_cand.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="domains per batch; the collection contract caps a batch at 100",
    )

    feed_check = research_sub.add_parser(
        "feed-check",
        help="assert that feed verdicts never leaked into the assessments being scored",
    )
    feed_check.add_argument("--labels", required=True, help="the feed label CSV")
    feed_check.add_argument(
        "--assessments", nargs="*", default=[], help="assessment JSONL files to inspect"
    )
    feed_check.add_argument("--out", default="", help="write the check result as JSON")

    feed_agreement = research_sub.add_parser(
        "feed-agreement",
        help="compare the frozen human labels with feed membership on their overlap",
    )
    feed_agreement.add_argument("--labels", required=True, help="the feed label CSV")
    feed_agreement.add_argument(
        "--human-labels",
        nargs="+",
        required=True,
        metavar="CSV",
        help="merged human label CSVs (one per batch)",
    )
    feed_agreement.add_argument("--out", default="", help="write the comparison as JSON")

    feed_eval = research_sub.add_parser(
        "feed-eval-labels",
        help="join collected assessments with feed membership into the primary label file",
    )
    feed_eval.add_argument("--labels", required=True, help="the feed label CSV")
    feed_eval.add_argument(
        "--assessments", nargs="+", required=True, help="assessment JSONL files actually collected"
    )
    feed_eval.add_argument(
        "--human-labels",
        nargs="*",
        default=[],
        metavar="CSV",
        help="frozen human label CSVs; those domains get no derived label",
    )
    feed_eval.add_argument("--out", default="data/labels/feed/eval_labels.csv")
    feed_eval.add_argument("--manifest", default="", help="provenance JSON (default: <out>.json)")

    injection_build = research_sub.add_parser(
        "injection-build",
        help="write the controlled H4 prompt-injection fixtures and their ground truth",
    )
    injection_build.add_argument("--out", default="data/injection_fixtures")

    injection_eval = research_sub.add_parser(
        "injection-eval",
        help="measure injection detection and score isolation on the controlled corpus",
    )
    injection_eval.add_argument("--corpus", default="data/injection_fixtures")
    injection_eval.add_argument("--action", default="browse")
    injection_eval.add_argument("--out", default="data/research/injection_h4.json")

    label_ui = research_sub.add_parser(
        "label-ui", help="serve a local blind labeling form for one annotator sheet"
    )
    label_ui.add_argument("--sheet", required=True, help="that annotator's CSV only")
    label_ui.add_argument("--port", type=int, default=8765)
    label_ui.add_argument(
        "--snapshots",
        action="append",
        default=[],
        metavar="JSONL",
        help="assessment export to read captured page screenshots from (repeatable)",
    )
    label_ui.add_argument(
        "--screenshots-dir",
        default="",
        help="directory holding the captured screenshots (default: the configured screenshots dir)",
    )
    label_ui.add_argument(
        "--no-open", action="store_true", help="do not open the browser automatically"
    )

    agreement = research_sub.add_parser("agreement", help="compute inter-annotator agreement")
    agreement.add_argument("--a", required=True, help="annotator A CSV")
    agreement.add_argument("--b", required=True, help="annotator B CSV")
    agreement.add_argument("--key", default="", help="optional queue key for domains and URLs")
    agreement.add_argument("--out", default="", help="write the full report as JSON")
    agreement.add_argument("--markdown", default="", help="write a Markdown summary")

    audit_queue = research_sub.add_parser(
        "audit-queue", help="build a delayed blinded intra-rater audit sheet"
    )
    audit_queue.add_argument("--sheet", required=True, help="completed annotator A sheet")
    audit_queue.add_argument("--key", required=True, help="that batch's coordinator key")
    audit_queue.add_argument("--out", default="data/annotations/main/audit")
    audit_queue.add_argument("--fraction", type=float, default=0.15)
    audit_queue.add_argument("--min-domains", type=int, default=40)
    audit_queue.add_argument("--seed", type=int, default=123)
    audit_queue.add_argument("--force", action="store_true")

    audit_report_parser = research_sub.add_parser(
        "audit-report", help="compare original labels with the delayed blind audit"
    )
    audit_report_parser.add_argument("--reference", required=True, help="audit_reference.json")
    audit_report_parser.add_argument("--audit", required=True, help="completed audit sheet")
    audit_report_parser.add_argument("--out", default="data/annotations/main/audit/audit_report.json")
    audit_report_parser.add_argument("--markdown", default="data/annotations/main/audit/audit_report.md")

    merge = research_sub.add_parser("merge", help="build consensus labels and adjudication list")
    merge.add_argument("--a", required=True)
    merge.add_argument("--b", default="", help="annotator B CSV; omit for single-annotator labels")
    merge.add_argument("--key", required=True)
    merge.add_argument("--adjudication", default="", help="CSV of resolved disagreements")
    merge.add_argument("--out", default="data/annotations/consensus.csv")
    merge.add_argument(
        "--apply-to-db",
        action="store_true",
        help="also write consensus labels into the runtime domain_labels table",
    )

    dataset = research_sub.add_parser("dataset", help="build a leakage-checked dataset")
    dataset.add_argument("--out", default="data/datasets/trustlens")
    dataset.add_argument("--assessments", nargs="*", default=[], help="full-assessment JSONL")
    dataset.add_argument("--labels", default="", help="CSV or JSON labels; default: database")
    dataset.add_argument("--ratios", default="0.7,0.15,0.15")
    dataset.add_argument("--seed", type=int, default=42)
    dataset.add_argument("--per-domain-limit", type=int, default=5)
    dataset.add_argument("--actions", default="", help="comma-separated action filter")
    dataset.add_argument("--include-suspicious", action="store_true")
    dataset.add_argument(
        "--exclude-uninspected",
        action="append",
        default=[],
        metavar="RECORD",
        help="non-inspection record (CSV with a domain column or JSON with excluded_domains); "
        "may be repeated",
    )
    dataset.add_argument("--allow-leakage", action="store_true")
    dataset.add_argument("--force", action="store_true")

    train = research_sub.add_parser("train", help="train, calibrate, and evaluate models")
    train.add_argument("--dataset", default="data/datasets/trustlens/dataset.jsonl")
    train.add_argument("--out-dir", default="data/research/runs")
    train.add_argument("--models-dir", default="models/research")
    train.add_argument("--groups", default="all", help="comma-separated or all")
    train.add_argument("--seed", type=int, default=42)
    train.add_argument("--bootstrap", type=int, default=1000)
    train.add_argument("--cv-folds", type=int, default=5)
    train.add_argument("--run-name", default="")

    evaluate = research_sub.add_parser("evaluate", help="evaluate a saved logistic artifact")
    evaluate.add_argument("--model", required=True)
    evaluate.add_argument("--dataset", default="data/datasets/trustlens/dataset.jsonl")
    evaluate.add_argument("--split", choices=["train", "val", "test"], default="test")
    evaluate.add_argument("--bootstrap", type=int, default=1000)
    evaluate.add_argument("--seed", type=int, default=42)
    evaluate.add_argument("--out", default="")
    return parser


def _print_assessment(assessment: Assessment, quiet: bool = False) -> None:
    if quiet:
        print(f"{assessment.overall_level.value.upper()} {assessment.overall_risk:.0f}/100 "
              f"(confidence {assessment.confidence:.0%}) - {assessment.headline}")
        return
    print(f"URL:         {assessment.final_url}")
    print(f"Domain:      {assessment.domain}")
    print(f"Action:      {assessment.action.value}")
    print(f"Verdict:     {assessment.overall_level.value.upper()} "
          f"({assessment.overall_risk:.1f}/100, confidence {assessment.confidence:.0%})")
    if assessment.calibrated_probability is not None:
        print(f"Calibrated:  {assessment.calibrated_probability:.1%} probability of a negative label")
    print(f"Headline:    {assessment.headline}")
    print(f"Advice:      {assessment.recommendation}")
    print()
    for dimension in assessment.dimensions.values():
        state = "insufficient evidence" if dimension.abstained else dimension.risk_level.value
        print(f"  {dimension.label:<24} {dimension.risk_score:5.1f}/100  "
              f"{state:<22} confidence {dimension.confidence:.0%}")
    if assessment.evidence:
        print("\nEvidence:")
        for item in sorted(
            assessment.evidence,
            key=lambda ev: ev.risk_points * ev.confidence,
            reverse=True,
        )[:10]:
            sign = "+" if item.risk_points else "-"
            points = item.risk_points or item.trust_points
            print(f"  [{item.severity.value:<8}] {sign}{points:.0f} {item.title} ({item.source})")
    floors = assessment.meta.get("floors") or []
    if floors:
        print(f"\nFloors applied: {', '.join(str(floor) for floor in floors)}")
    if assessment.missing_evidence:
        print("\nMissing evidence:")
        for message in assessment.missing_evidence[:5]:
            print(f"  - {message}")
    print("\nAutomated risk signals are advisory and can be wrong.")


async def _scan(args: argparse.Namespace) -> int:
    assessor = Assessor()
    try:
        assessment = await assessor.assess(
            args.url, Action(args.action), force_refresh=args.force
        )
    except UnsafeURLError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(assessment.model_dump_json(indent=2))
    else:
        _print_assessment(assessment, quiet=args.quiet)
    return 0


async def _guard(args: argparse.Namespace) -> int:
    from .pipeline import guard_decision

    assessor = Assessor()
    try:
        assessment = await assessor.assess(args.url, Action(args.action))
    except UnsafeURLError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    verdict, reasons = guard_decision(assessment)
    print(f"{verdict.upper()} {assessment.overall_level.value} "
          f"{assessment.overall_risk:.0f}/100 confidence {assessment.confidence:.0%}")
    for reason in reasons:
        print(f"  - {reason}")
    return 0


def _read_batch_items(path: Path) -> list[dict[str, str]]:
    if path.suffix.lower() == ".csv":
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            fields = reader.fieldnames or []
            field = next((name for name in fields if name.lower() in {"url", "uri"}), None)
            if field is None:
                raise SystemExit("CSV must contain a url column")
            gate_field = next(
                (name for name in fields if name.lower() == "collection_gate"), None
            )
            return [
                {
                    "url": row[field].strip(),
                    "collection_gate": (row.get(gate_field) or "").strip() if gate_field else "",
                }
                for row in reader
                if row.get(field, "").strip()
            ]
    return [
        {"url": line.strip(), "collection_gate": ""}
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def _split_gated_batch_items(
    items: list[dict[str, str]], *, allow_gated: bool
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    if allow_gated:
        return items, []
    allowed = [item for item in items if item.get("collection_gate") != GATED_COLLECTION]
    gated = [item for item in items if item.get("collection_gate") == GATED_COLLECTION]
    return allowed, gated


def _completed_urls(path: Path) -> set[str]:
    completed: set[str] = set()
    if not path.exists():
        return completed
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        for key in ("url", "normalized_url"):
            url = row.get(key)
            if url and not row.get("error"):
                completed.add(str(url))
    return completed


async def _batch(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.exists():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 1
    items = _read_batch_items(path)
    items, gated = _split_gated_batch_items(items, allow_gated=args.allow_gated)
    if gated:
        print(
            f"Safety gate: skipped {len(gated)} candidate(s) marked {GATED_COLLECTION!r}. "
            "No gated page was opened; pass --allow-gated only after explicit team confirmation."
        )
    if args.limit:
        items = items[: args.limit]
    urls = [item["url"] for item in items]
    if not urls:
        print("error: no URLs found", file=sys.stderr)
        return 1
    output = Path(args.out) if args.out else None
    if (args.full or args.resume) and output is None:
        print("error: --full and --resume require --out", file=sys.stderr)
        return 1
    if output is not None and args.resume:
        completed = _completed_urls(output)
        before = len(urls)
        urls = [url for url in urls if url not in completed]
        if completed:
            print(f"Resume: {before - len(urls)} URL(s) already completed")
        if not urls:
            print(f"Nothing to do; all URLs are present in {output}")
            return 0

    assessor = Assessor()
    counts: dict[str, int] = {}
    failures = 0
    written = 0
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
    handle = output.open("a" if args.resume else "w", encoding="utf-8") if output else None
    try:
        for index, url in enumerate(urls, 1):
            row: dict = {"url": url}
            try:
                assessment = await assessor.assess(
                    url, Action(args.action), force_refresh=args.force
                )
            except UnsafeURLError as exc:
                failures += 1
                row["error"] = str(exc)
                print(f"[{index}/{len(urls)}] SKIP {url} ({exc})")
            except Exception as exc:
                failures += 1
                row["error"] = f"{type(exc).__name__}: {str(exc)[:300]}"
                print(f"[{index}/{len(urls)}] ERROR {url} ({row['error']})")
            else:
                counts[assessment.overall_level.value] = (
                    counts.get(assessment.overall_level.value, 0) + 1
                )
                print(f"[{index}/{len(urls)}] {assessment.overall_level.value:<8} "
                      f"{assessment.overall_risk:5.1f} {assessment.domain}")
                if args.full:
                    row = assessment.model_dump(mode="json")
                else:
                    row = {
                        "url": assessment.url,
                        "final_url": assessment.final_url,
                        "domain": assessment.domain,
                        "action": assessment.action.value,
                        "overall_risk": assessment.overall_risk,
                        "overall_level": assessment.overall_level.value,
                        "confidence": assessment.confidence,
                        "headline": assessment.headline,
                        "assessment_id": assessment.id,
                        "created_at": assessment.created_at.isoformat(),
                    }
            if handle is not None:
                handle.write(json.dumps(row) + "\n")
                handle.flush()
                written += 1
    finally:
        if handle is not None:
            handle.close()
    if output:
        print(f"\nWrote {written} row(s) to {output}")
    print("Summary: " + ", ".join(f"{name}={count}" for name, count in sorted(counts.items())))
    if failures:
        print(f"Skipped or failed {failures} URL(s)")
    return 0


def _domain_from_value(value: object) -> str:
    raw = str(value or "").strip()
    if not raw or raw.startswith("#"):
        return ""
    if raw.startswith("||"):
        raw = raw[2:].rstrip("^")
    if raw.startswith("*."):
        raw = raw[2:]
    if "://" not in raw:
        raw = "http://" + raw
    try:
        host = urlsplit(raw).hostname or ""
        return registrable_domain(host) if host else ""
    except ValueError:
        return ""


def _import_labels(path: Path, source: str, default_label: str = "malicious") -> int:
    if not path.exists():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 1
    storage.init_db()
    rows: list[dict] = []
    plaintext = path.suffix.lower() not in {".csv", ".json"}
    if path.suffix.lower() == ".json":
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict) and "labels" not in payload:
            rows = [{"domain": key, "label": value} for key, value in payload.items()]
        else:
            rows = payload if isinstance(payload, list) else payload.get("labels", [])
    elif path.suffix.lower() == ".csv":
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))
    else:
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.split("#", 1)[0].strip()
            if not stripped:
                continue
            tokens = stripped.split()
            if len(tokens) > 1 and tokens[0] in {"0.0.0.0", "127.0.0.1", "::", "::1"}:
                stripped = tokens[-1]
            elif len(tokens) > 1:
                stripped = tokens[0]
            rows.append({"domain": stripped, "label": default_label})
    imported = 0
    skipped = 0
    for row in rows:
        if not isinstance(row, dict):
            skipped += 1
            continue
        domain = _domain_from_value(row.get("domain") or row.get("url") or "")
        label = str(
            row.get("label") or row.get("expected") or (default_label if plaintext else "")
        ).strip().lower()
        if not domain or label not in {"benign", "suspicious", "malicious"}:
            skipped += 1
            continue
        try:
            confidence = float(row.get("confidence") or 1.0)
        except (TypeError, ValueError):
            confidence = 1.0
        try:
            storage.upsert_domain_label(
                domain,
                label,
                str(row.get("source") or source)[:100],
                max(0.0, min(1.0, confidence)),
                str(row.get("note") or "")[:1000],
            )
        except ValueError:
            skipped += 1
            continue
        imported += 1
    print(f"Imported {imported} label(s) from {path}")
    if skipped:
        print(f"Skipped {skipped} invalid or incomplete row(s)")
    return 0


def _fmt_metric(value: object) -> str:
    return "n/a" if value is None else f"{float(value):.3f}"


def _load_uninspected_domains(paths: list[str]) -> tuple[set[str], dict[str, int]]:
    """Read domains that an annotator recorded as not inspected from CSV or JSON records."""
    from .research.annotations import read_csv_rows

    domains: set[str] = set()
    counts: dict[str, int] = {}
    for value in paths:
        path = Path(value)
        if not path.exists():
            raise FileNotFoundError(f"uninspected record not found: {path}")
        found: set[str] = set()
        if path.suffix.lower() == ".json":
            payload = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                found |= {
                    str(item).strip().lower()
                    for item in payload.get("excluded_domains", [])
                    if str(item).strip()
                }
                for row in payload.get("rows", []):
                    if isinstance(row, dict) and str(row.get("domain", "")).strip():
                        found.add(str(row["domain"]).strip().lower())
        else:
            for row in read_csv_rows(path):
                if str(row.get("domain", "")).strip():
                    found.add(str(row["domain"]).strip().lower())
        if not found:
            raise ValueError(f"{path} contains no domain column or excluded_domains list")
        counts[path.name] = len(found)
        domains |= found
    return domains, counts


def _load_research_assessments(values: list[str]) -> tuple[list, list[dict], str]:
    from .research import dataset as research_dataset

    if values:
        assessments, errors = research_dataset.load_assessment_files(
            [Path(value) for value in values]
        )
        return assessments, errors, "jsonl:" + ",".join(values)
    return research_dataset.load_assessments_from_db(), [], "sqlite:assessments"


def _research(args: argparse.Namespace) -> int:
    from .research import annotations, candidates as research_candidates, training
    from .research import dataset as research_dataset

    command = args.research_command
    if command == "main-candidates":
        import io
        import zipfile

        import httpx

        def _fetch_public(url: str, label: str) -> tuple[bytes, dict[str, Any]]:
            response = httpx.get(
                url,
                follow_redirects=True,
                timeout=60.0,
                headers={"User-Agent": "TrustLens/0.1 candidate metadata"},
            )
            response.raise_for_status()
            retrieved_at = datetime.now(timezone.utc)
            return response.content, {
                "source": label,
                "url": url,
                "final_url": str(response.url),
                "retrieved_at": retrieved_at.isoformat(),
                "source_date": retrieved_at.date().isoformat(),
                "http_date": response.headers.get("date", ""),
                "sha256": hashlib.sha256(response.content).hexdigest(),
                "bytes": len(response.content),
                "fetch_mode": "network",
            }

        def _read_public(path_value: str, url: str, label: str) -> tuple[bytes, dict[str, Any]]:
            path = Path(path_value)
            if not path.exists():
                raise FileNotFoundError(f"snapshot not found: {path}")
            raw = path.read_bytes()
            return raw, {
                "source": label,
                "url": url,
                "final_url": url,
                "snapshot_file": str(path),
                "retrieved_at": "",
                "source_date": datetime.now(timezone.utc).date().isoformat(),
                "http_date": "",
                "sha256": hashlib.sha256(raw).hexdigest(),
                "bytes": len(raw),
                "fetch_mode": "local_file",
            }

        def _tranco_text(raw: bytes, meta: dict[str, Any]) -> str:
            if raw[:2] == b"PK":
                with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                    names = [
                        name for name in archive.namelist() if name.lower().endswith(".csv")
                    ]
                    if not names:
                        raise ValueError("Tranco zip contains no CSV file")
                    member = next(
                        (name for name in names if "top-1m" in name.lower()), names[0]
                    )
                    data = archive.read(member)
                    meta["archive_member"] = member
                    meta["csv_sha256"] = hashlib.sha256(data).hexdigest()
                    meta["csv_bytes"] = len(data)
                    return data.decode("utf-8-sig", errors="replace")
            return raw.decode("utf-8-sig", errors="replace")

        def _urlhaus_text(text: str) -> str:
            fields = [
                "id", "dateadded", "url", "url_status", "last_online", "threat",
                "tags", "urlhaus_link", "reporter",
            ]
            rows = [
                line
                for line in text.splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
            urls = []
            for row in csv.DictReader(io.StringIO("\n".join(rows)), fieldnames=fields):
                value = str(row.get("url") or "").strip()
                if value:
                    urls.append(value)
            return "\n".join(urls)

        try:
            counts = {
                "established": args.established,
                "tail": args.tail,
                "scam_feed": args.scam,
            }
            reserve_counts = {
                "established": args.reserve_established,
                "tail": args.reserve_tail,
                "scam_feed": args.reserve_scam,
            }
            if any(value < 0 for value in (*counts.values(), *reserve_counts.values())):
                raise ValueError("candidate counts must be non-negative")
            if args.tranco_file:
                tranco_raw, tranco_meta = _read_public(
                    args.tranco_file, args.tranco_url, "Tranco top-1M"
                )
            else:
                tranco_raw, tranco_meta = _fetch_public(
                    args.tranco_url, "Tranco top-1M"
                )
            tranco_text = _tranco_text(tranco_raw, tranco_meta)

            if args.openphish_file:
                openphish_raw, openphish_meta = _read_public(
                    args.openphish_file, args.openphish_url, "OpenPhish public feed"
                )
            else:
                openphish_raw, openphish_meta = _fetch_public(
                    args.openphish_url, "OpenPhish public feed"
                )
            openphish_text = openphish_raw.decode("utf-8", errors="replace")

            if args.urlhaus_file:
                urlhaus_raw, urlhaus_meta = _read_public(
                    args.urlhaus_file, args.urlhaus_url, "URLhaus online CSV"
                )
            else:
                urlhaus_raw, urlhaus_meta = _fetch_public(
                    args.urlhaus_url, "URLhaus online CSV"
                )
            urlhaus_meta["format"] = "csv_no_header"
            urlhaus_text = _urlhaus_text(urlhaus_raw.decode("utf-8", errors="replace"))

            exclusions = [
                Path("data/candidates/pilot.csv"),
                Path("data/candidates/round2.csv"),
                Path("data/candidates/round2_reserve.csv"),
            ] + [Path(value) for value in args.exclude]
            manifest = research_candidates.build_main_manifest(
                tranco_text=tranco_text,
                tranco_meta=tranco_meta,
                feeds=[
                    {
                        "text": openphish_text,
                        "meta": openphish_meta,
                        "source": "openphish_public_feed",
                        "candidate_family": "unclassified_feed",
                        "html_only": True,
                    },
                    {
                        "text": urlhaus_text,
                        "meta": urlhaus_meta,
                        "source": "urlhaus_public_feed",
                        "candidate_family": "malware_download",
                        "html_only": True,
                    },
                ],
                exclusion_paths=exclusions,
                out_dir=Path(args.out_dir),
                seed=args.seed,
                counts=counts,
                reserve_counts=reserve_counts,
                force=args.force,
            )
        except (
            FileNotFoundError,
            FileExistsError,
            ValueError,
            OSError,
            httpx.HTTPError,
            zipfile.BadZipFile,
        ) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(
            f"Main candidate manifest: {manifest['domains_total']} domains "
            f"-> {Path(args.out_dir) / 'main.csv'}"
        )
        print(
            "Strata: "
            + ", ".join(
                f"{name}={count}" for name, count in manifest["selected"].items()
            )
        )
        print(
            "Reserve: "
            + str(sum(manifest["reserve"].values()))
            + f" domains -> {Path(args.out_dir) / 'main_reserve.csv'}"
        )
        print(
            f"Tranco: {manifest['tranco']['unique_domains']} usable rows; "
            f"{manifest['tranco']['excluded_overlap_domains']} excluded pilot/overlap domain(s)"
        )
        for feed in manifest["feeds"]:
            print(
                f"Feed {feed['source']}: {feed['unique_usable_domains']} usable domain(s) "
                f"after filters"
            )
        print(
            f"Safety: {manifest['safety']['gated_selected']} gated candidate(s); "
            "no candidate page was opened."
        )
        print(
            "The batch command skips gated rows by default. Use --allow-gated only after "
            "fresh explicit approval for the main collection."
        )
        return 0

    if command == "candidates":
        import httpx

        counts = {
            "scam_feed": args.scam,
            "ambiguous": args.ambiguous,
            "benign_control": args.benign,
        }
        try:
            if any(value < 0 for value in counts.values()):
                raise ValueError("candidate counts must be non-negative")
            if args.feed_file:
                feed_path = Path(args.feed_file)
                if not feed_path.exists():
                    raise FileNotFoundError(f"feed snapshot not found: {feed_path}")
                raw = feed_path.read_bytes()
                feed_url = args.feed_url
                final_url = args.feed_url
                snapshot_file = str(feed_path)
                http_date = ""
                fetch_mode = "local_file"
            else:
                response = httpx.get(
                    args.feed_url,
                    follow_redirects=True,
                    timeout=30.0,
                    headers={"User-Agent": "TrustLens/0.1 candidate metadata"},
                )
                response.raise_for_status()
                raw = response.content
                feed_url = args.feed_url
                final_url = str(response.url)
                snapshot_file = ""
                http_date = response.headers.get("date", "")
                fetch_mode = "network"
            retrieved_at = datetime.now(timezone.utc)
            feed_meta = {
                "source": args.feed_source,
                "url": feed_url,
                "final_url": final_url,
                "snapshot_file": snapshot_file,
                "retrieved_at": retrieved_at.isoformat(),
                "source_date": retrieved_at.date().isoformat(),
                "http_date": http_date,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "bytes": len(raw),
                "fetch_mode": fetch_mode,
            }
            manifest = research_candidates.build_round2_manifest(
                feed_text=raw.decode("utf-8", errors="replace"),
                feed_meta=feed_meta,
                curated_path=Path(args.curated),
                pilot_path=Path(args.pilot),
                out_dir=Path(args.out_dir),
                seed=args.seed,
                counts=counts,
                force=args.force,
            )
        except (FileNotFoundError, FileExistsError, ValueError, OSError, httpx.HTTPError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(
            f"Round 2 candidate manifest: {manifest['domains_total']} domains "
            f"-> {Path(args.out_dir) / 'round2.csv'}"
        )
        print(
            "Strata: "
            + ", ".join(
                f"{name}={count}" for name, count in manifest["selected"].items()
            )
        )
        print(
            "Reserve: "
            + str(sum(manifest["reserve"].values()))
            + f" domains -> {Path(args.out_dir) / 'round2_reserve.csv'}"
        )
        print(
            f"Feed: {manifest['feed']['lines']} row(s), "
            f"{manifest['feed']['unique_usable_domains']} usable domain(s)"
        )
        print(
            f"Safety: {manifest['safety']['gated_selected']} gated candidate(s); "
            "no candidate page was opened."
        )
        print(
            "The batch command skips gated rows by default. Use --allow-gated only after "
            "explicit team confirmation."
        )
        return 0

    if command == "main-status":
        from .research import collection as research_collection

        out_path = Path(args.out) if args.out else None
        try:
            status_path = research_collection.write_status(Path.cwd(), out_path)
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        status = json.loads(status_path.read_text(encoding="utf-8"))
        progress = status["progress"]
        targets = status["targets"]
        print(f"Status written to {status_path}")
        print(
            f"Batches: {progress['batches_collected']}/{progress['batches_defined']} collected, "
            f"{progress['batches_queued']} queued, {progress['batches_frozen']} frozen"
        )
        print(
            f"Assessments: {progress['assessments_collected']} usable, "
            f"{progress['collection_failures']} unreachable, "
            f"{progress['cross_domain_redirects']} cross-domain redirect(s), "
            f"{progress['no_evidence']} without evidence"
        )
        print(
            f"Labels: {progress['sites_annotated']} annotated, "
            f"{progress['sites_pending']} pending, "
            f"mix: "
            + ", ".join(f"{k}={v}" for k, v in progress["labels_by_class"].items())
        )
        print(
            f"Usable now {progress['usable_now']} against a minimum of "
            f"{targets['usable_domains_min']}; gated scam_feed "
            f"{targets['gated_selected']} site(s) are still "
            f"{status['gated_collection']['status']}"
        )
        for state in status["batches"]:
            annotation = state["annotation"]
            print(
                f"  batch {state['batch']}: {state['candidates']['domains']} candidate(s), "
                f"{state['collection']['assessments']} collected, "
                f"{annotation['annotated']} labelled, "
                f"{'frozen' if annotation['frozen'] else 'not frozen'} -> {state['next_action']}"
            )
        failed = [
            check
            for check in status["integrity_checks"]
            if not check["ok"] and not check.get("informational")
        ]
        if failed:
            print(f"Integrity: {len(failed)} check(s) FAILED", file=sys.stderr)
            for check in failed:
                print(f"  - {check['id']}: {check['detail']}", file=sys.stderr)
            return 1
        print(f"Integrity: {len(status['integrity_checks'])} check(s) passed")
        if args.markdown:
            markdown_path = Path(args.markdown)
            markdown_path.parent.mkdir(parents=True, exist_ok=True)
            markdown_path.write_text(
                research_collection.status_markdown(status), encoding="utf-8"
            )
            print(f"Markdown summary: {markdown_path}")
        return 0

    if command == "queue":
        if args.limit < 0:
            print("error: --limit must not be negative", file=sys.stderr)
            return 1
        try:
            assessments, errors, source = _load_research_assessments(args.assessments)
            if errors:
                print(f"warning: skipped {len(errors)} unreadable assessment row(s)")
            key = annotations.build_queue(
                assessments,
                Path(args.out),
                overlap=args.overlap,
                seed=args.seed,
                limit=args.limit,
                force=args.force,
                single_annotator=args.single_annotator,
            )
        except (FileNotFoundError, FileExistsError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(f"Annotation queue: {key['sample_count']} site(s) from {source}")
        print(
            "Assignments: "
            + ", ".join(f"{name}={count}" for name, count in key["assignments"].items())
        )
        print(f"Annotator A sheet: {Path(args.out) / 'annotator_a.csv'} "
              f"({key['annotator_a_count']} sites)")
        print(f"Annotator B sheet: {Path(args.out) / 'annotator_b.csv'} "
              f"({key['annotator_b_count']} sites)")
        print(f"Coordinator key:   {Path(args.out) / 'key.json'} (do not share before labelling)")
        if key.get("single_annotator"):
            print(
                "Mode: single annotator. No second sheet or inter-rater agreement is available; "
                "a delayed blind intra-rater audit is required."
            )
        return 0

    if command == "feed-labels":
        from .research import feed_labels as fl

        sources: list[fl.FeedSource] = []
        warnings: list[str] = []
        try:
            if args.openphish_file:
                text, meta = fl.read_feed(
                    Path(args.openphish_file),
                    name="openphish_public_feed",
                    url=args.openphish_url,
                )
            else:
                text, meta = fl.fetch_feed(args.openphish_url, name="openphish_public_feed")
            sources.append(
                fl.FeedSource(
                    name=meta["source"],
                    text=text,
                    retrieved_at=meta["retrieved_at"],
                    source_date=meta["source_date"],
                    sha256=meta["sha256"],
                    url=meta["url"],
                    max_age_days=args.max_age_days,
                    snapshot_file=meta.get("snapshot_file", ""),
                )
            )
            if args.snapshot_dir:
                snapshot = Path(args.snapshot_dir) / f"openphish_{meta['sha256'][:12]}.txt"
                snapshot.parent.mkdir(parents=True, exist_ok=True)
                # newline="" keeps the snapshot byte-identical to the fetched body, so its SHA-256
                # still matches the digest recorded in the provenance manifest.
                with snapshot.open("w", encoding="utf-8", newline="") as handle:
                    handle.write(text)
                sources[-1] = fl.with_snapshot(sources[-1], snapshot)
            if not args.no_urlhaus:
                if args.urlhaus_file:
                    raw, meta = fl.read_feed(
                        Path(args.urlhaus_file),
                        name="urlhaus_public_feed",
                        url=args.urlhaus_url,
                    )
                else:
                    raw, meta = fl.fetch_feed(args.urlhaus_url, name="urlhaus_public_feed")
                text = "\n".join(fl.urlhaus_urls(raw))
                sources.append(
                    fl.FeedSource(
                        name=meta["source"],
                        text=text,
                        retrieved_at=meta["retrieved_at"],
                        source_date=meta["source_date"],
                        sha256=meta["sha256"],
                        url=meta["url"],
                        max_age_days=args.max_age_days,
                        snapshot_file=meta.get("snapshot_file", ""),
                    )
                )
                if args.snapshot_dir:
                    snapshot = Path(args.snapshot_dir) / f"urlhaus_{meta['sha256'][:12]}.csv"
                    snapshot.parent.mkdir(parents=True, exist_ok=True)
                    with snapshot.open("w", encoding="utf-8", newline="") as handle:
                        handle.write(raw)
                    sources[-1] = fl.with_snapshot(sources[-1], snapshot)
        except (OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

        excluded: set[str] = set()
        try:
            for path in args.exclude_domains:
                excluded |= research_candidates.load_candidate_domains(Path(path))
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

        try:
            rows, stats = fl.build_feed_labels(sources, excluded_domains=excluded)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        if stats["stale_sources"]:
            print(
                "error: refusing to label from stale feed snapshots: "
                + ", ".join(stats["stale_sources"])
                + f" (older than {args.max_age_days} days)",
                file=sys.stderr,
            )
            return 1
        warnings += [
            f"{name}: feed age is unknown for a local snapshot, so the crawl window is unverifiable"
            for name, meta in stats["sources"].items()
            if meta["age_state"] == "unknown_age"
        ]
        out_path = Path(args.out)
        fl.write_labels(rows, out_path)
        manifest_path = Path(args.manifest) if args.manifest else out_path.with_suffix(".json")
        stats["outputs"] = {"labels": str(out_path)}
        stats["excluded_domains_requested"] = len(excluded)
        stats["warnings"] = warnings
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(stats, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        print(f"Feed labels: {len(rows)} domains -> {out_path}")
        for name, meta in sorted(stats["sources"].items()):
            print(
                f"  {name}: {meta['lines']} entries, {meta['accepted_entries']} accepted, "
                f"{meta['age_state']}, sha256 {meta['sha256'][:12]}"
            )
        print(f"  multi-feed domains: {stats['multi_feed_domains']}")
        print(f"  rejected entries: {stats['rejection_total']}")
        print(f"Provenance: {manifest_path}")
        for warning in warnings:
            print(f"warning: {warning}")
        print(
            "Note: this label is feed membership, not a human trust judgement. Never import this "
            "file with `import-labels`; that would leak the verdict into the scored features."
        )
        return 0

    if command == "feed-candidates":
        try:
            manifest = research_candidates.build_feed_candidates(
                labels_path=Path(args.labels),
                out_dir=Path(args.out_dir),
                seed=args.seed,
                batch_size=args.batch_size,
            )
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(
            f"Feed crawl plan: {manifest['candidates']} candidate(s), "
            f"{manifest['domains']} domain(s), {len(manifest['batches'])} batch(es) "
            f"of at most {manifest['batch_size']}"
        )
        for batch in manifest["batches"]:
            print(
                f"  batch {batch['batch']:02d}: {batch['domains']} domain(s) -> {batch['file']}"
            )
        if manifest["payload_urls_replaced_by_domain_root"]:
            print(
                f"  {manifest['payload_urls_replaced_by_domain_root']} feed URL(s) pointed at a "
                "download; the crawl target was set to the domain root instead"
            )
        print(f"Manifest: {Path(args.out_dir) / 'feed_manifest.json'}")
        print(
            "Safety: every row is gated. No page was opened by this command and none will be opened "
            "by `batch` without --allow-gated, which requires fresh explicit confirmation."
        )
        return 0

    if command == "feed-check":
        from .research import feed_labels as fl

        try:
            result = fl.assert_no_label_leakage(
                [Path(path) for path in args.assessments],
                fl.load_feed_label_domains(Path(args.labels)),
            )
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(f"Assessments checked: {result['assessments']}")
        print(f"Runtime domain_labels rows: {result['runtime_label_store_rows']}")
        print(f"Leaked assessments: {result['leaked_assessments']}")
        for item in result["leaked_examples"]:
            print(f"  {item['domain']}: {', '.join(item['reasons'])}")
        if result["feed_domains_in_runtime_store"]:
            print(
                "error: feed domains are present in the runtime label store: "
                + ", ".join(result["feed_domains_in_runtime_store"][:10]),
                file=sys.stderr,
            )
        if args.out:
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(
                json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        print("Leakage check passed." if result["passed"] else "Leakage check FAILED.")
        return 0 if result["passed"] else 1

    if command == "feed-agreement":
        from .research import feed_labels as fl

        try:
            result = fl.cross_check_human_labels(
                [Path(path) for path in args.human_labels], Path(args.labels)
            )
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(f"Human-labelled domains: {result['human_domains']}")
        print(f"Feed-labelled domains: {result['feed_domains']}")
        print(f"Domains in both: {result['overlap']}")
        for label, counts in result["human_label_by_feed_membership"].items():
            print(
                f"  human {label:<10} in feed {counts['in_feed']:>4}   not in feed "
                f"{counts['not_in_feed']:>4}"
            )
        print(
            f"Observed agreement on the overlap: {result['observed_agreement_on_overlap']}"
            f"  Cohen kappa: {result['cohens_kappa_on_overlap']}"
            + ("" if result["cohens_kappa_interpretable"] else " (not interpretable: the feed "
               "marginal is constant, so kappa cannot exceed zero here)")
        )
        coverage = result["human_malicious_still_in_feed"]
        print(
            f"Human-malicious domains still in the feed: "
            f"{coverage['still_listed']} of {coverage['human_malicious_domains']}"
            + (f" ({coverage['share']:.0%})" if coverage["share"] is not None else "")
        )
        for item in result["human_not_malicious_but_feed_malicious"]:
            print(
                f"  disagreement {item['domain']}: human {item['human_labels']} "
                f"({item['batches']}), feed {item['feed']}"
            )
        print("No label is moved by this comparison; disagreements are reported, not reconciled.")
        if args.out:
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(
                json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            print(f"Report: {args.out}")
        return 0

    if command == "feed-eval-labels":
        from .research import feed_labels as fl

        try:
            human_rows = fl.load_human_label_rows([Path(path) for path in args.human_labels])
            rows, stats = fl.derive_evaluation_labels(
                [Path(path) for path in args.assessments],
                Path(args.labels),
                exclude_domains=set(human_rows),
            )
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        out_path = Path(args.out)
        fl.write_labels(rows, out_path)
        manifest_path = Path(args.manifest) if args.manifest else out_path.with_suffix(".json")
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(
            json.dumps(stats, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"Primary labels: {stats['derived_rows']} rows -> {out_path}")
        for label, count in sorted(stats["labels"].items()):
            print(f"  {label}: {count}")
        print(f"  feed domains with no assessment (dropped, never benign): "
              f"{stats['feed_domains_without_an_assessment']}")
        print(f"  human-labelled domains given no derived label: "
              f"{stats['excluded_human_labelled_domains']}")
        print(f"Provenance: {manifest_path}")
        print(
            "Note: `benign` here means absent from both feeds at retrieval time, not verified "
            "trustworthy."
        )
        return 0

    if command == "injection-build":
        from .research import injection as injection_corpus

        manifest = injection_corpus.build_corpus(Path(args.out))
        print(
            f"Wrote {manifest['case_count']} fixtures to {args.out}: "
            f"{manifest['injection_cases']} injection cases, "
            f"{manifest['negative_cases']} benign negatives "
            f"({manifest['adversarial_negative_cases']} adversarial)."
        )
        return 0

    if command == "injection-eval":
        from .research import injection as injection_corpus

        corpus = Path(args.corpus)
        if not (corpus / "manifest.json").exists():
            injection_corpus.build_corpus(corpus)
        result = injection_corpus.evaluate(corpus, action=Action(args.action))
        detection = result["detection"]["all"]
        invariance = result["score_invariance"]
        confusion = detection["confusion"]
        print(
            f"Cases: {result['corpus']['cases']} "
            f"({result['corpus']['injection_cases']} injection, "
            f"{result['corpus']['negative_cases']} negative)"
        )
        print(
            f"Detection: precision {detection['precision']:.4f}, "
            f"recall {detection['recall']:.4f}, F1 {detection['f1']:.4f} "
            f"(tp {confusion['tp']} / fp {confusion['fp']} / "
            f"fn {confusion['fn']} / tn {confusion['tn']})"
        )
        print(
            f"Invariance: {invariance['exact_score_match_after_removal']}/"
            f"{invariance['comparable_pairs']} hidden-channel pairs reproduce the baseline "
            f"exactly once the injection evidence is removed "
            f"(max residual delta {invariance['max_abs_risk_delta_after_removal']})"
        )
        print(
            f"Obedience check: trust gain "
            f"{result['obedience_check']['max_trust_point_gain_from_any_fixture']}, "
            f"risk reductions {result['obedience_check']['cases_reduced_in_overall_risk']}, "
            f"verdicts relaxed to allow "
            f"{result['injection_contribution']['cases_verdict_relaxed_to_allow']}"
        )
        for name, ok in result["gate"].items():
            print(f"  {'PASS' if ok else 'FAIL'} {name}")
        if args.out:
            injection_corpus.write_report(result, Path(args.out))
            print(f"Report: {args.out}")
        print("Isolation gate passed." if result["passed"] else "Isolation gate FAILED.")
        return 0 if result["passed"] else 1

    if command == "label-ui":
        import secrets
        import threading
        import webbrowser

        import uvicorn

        from .research.labeling import create_app
        from .research.snapshots import build_snapshot_index

        sheet_path = Path(args.sheet)
        if not 1 <= args.port <= 65535:
            print("error: --port must be between 1 and 65535", file=sys.stderr)
            return 1
        screenshots_dir = (
            Path(args.screenshots_dir) if args.screenshots_dir else settings().screenshots_dir
        )
        snapshots: dict = {}
        if args.snapshots:
            try:
                snapshots = build_snapshot_index([Path(p) for p in args.snapshots], screenshots_dir)
            except (FileNotFoundError, OSError) as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
        try:
            token = secrets.token_urlsafe(24)
            app = create_app(sheet_path, token, snapshots)
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        url = f"http://127.0.0.1:{args.port}/?token={token}"
        print(f"Blind labeling sheet: {sheet_path}")
        print("This form reads only that sheet; it never opens key.json.")
        if snapshots:
            print(
                f"Captured pages from {len(args.snapshots)} export file(s): "
                f"{sum(1 for ref in snapshots.values() if ref.state in ('ok', 'duplicate'))} usable, "
                f"{sum(1 for ref in snapshots.values() if ref.state == 'likely_blank')} suspect."
            )
        else:
            print("No --snapshots given, so sites must be reviewed live in the browser.")
        print("Close the CSV in Excel or any editor before labeling.")
        print(f"Open: {url}")
        print("Press Ctrl+C to stop.")
        if not args.no_open:
            threading.Timer(1.0, lambda: webbrowser.open(url)).start()
        try:
            uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
        except (OSError, SystemExit) as exc:
            print(f"error: could not start the labeling server: {exc}", file=sys.stderr)
            return 1
        return 0

    if command == "freeze":
        try:
            archive, record_path, record = annotations.freeze_sheet(
                Path(args.sheet), Path(args.key), role=args.role or None
            )
        except (FileNotFoundError, FileExistsError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(
            f"Frozen annotator {record['role'].upper()} sheet: "
            f"{record['annotated']}/{record['expected']} assigned site(s)"
        )
        print(f"Labels: {record['labels']}")
        print(f"Archive: {archive} (sha256 {record['sha256']})")
        print(f"Record:  {record_path}")
        print(
            "The archive is read-only. Any correction must be recorded as a protocol "
            "amendment, not a silent edit."
        )
        return 0

    if command == "agreement":
        try:
            a_rows = annotations.load_annotations(Path(args.a))
            b_rows = annotations.load_annotations(Path(args.b))
            if not set(a_rows) & set(b_rows):
                print("error: the two sheets have no sample_id values in common", file=sys.stderr)
                return 1
            report = annotations.agreement_report(a_rows, b_rows)
            if args.key:
                key = annotations.load_key(Path(args.key))
                lookup = {
                    str(item.get("sample_id")): item for item in key.get("samples", [])
                }
                for item in report["disagreements"]:
                    source = lookup.get(item["sample_id"], {})
                    item["domain"] = source.get("domain", "")
                    item["url"] = source.get("url", "")
            if args.out:
                out_path = Path(args.out)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
                print(f"Full report written to {out_path}")
            if args.markdown:
                markdown_path = Path(args.markdown)
                markdown_path.parent.mkdir(parents=True, exist_ok=True)
                markdown_path.write_text(
                    annotations.agreement_markdown(report), encoding="utf-8"
                )
                print(f"Markdown summary written to {markdown_path}")
        except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(f"Double-annotated sites: {report['n_overlap']}")
        print(f"Observed agreement: {report['observed_agreement']}")
        print(
            f"Cohen's kappa: {report['cohen_kappa']} "
            f"({report['interpretation']}); "
            f"weighted kappa (quadratic): {report['cohen_kappa_quadratic']}"
        )
        print(f"Disagreements: {len(report['disagreements'])}")
        return 0

    if command == "audit-queue":
        try:
            reference = annotations.build_audit_queue(
                Path(args.sheet),
                Path(args.key),
                Path(args.out),
                fraction=args.fraction,
                min_domains=args.min_domains,
                seed=args.seed,
                force=args.force,
            )
        except (FileNotFoundError, FileExistsError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(f"Audit sites: {reference['selected']} of {reference['available']}")
        print(f"Audit labels: {reference['by_label']}")
        print(f"Audit sheet: {reference['audit_sheet']}")
        print(f"Audit key: {reference['audit_key']} (coordinator only)")
        print(f"Hidden reference: {Path(args.out) / 'audit_reference.json'}")
        print(f"Do not re-label before {reference['not_before']}.")
        print(
            "Serve only the audit sheet with label-ui. Do not open audit_reference.json "
            "until the audit sheet is frozen."
        )
        return 0

    if command == "audit-report":
        try:
            reference_payload = json.loads(
                Path(args.reference).read_text(encoding="utf-8")
            )
            original = {
                str(row["sample_id"]): {
                    "sample_id": str(row["sample_id"]),
                    "label": str(row["label"]),
                    "confidence": float(row.get("confidence") or 0.0),
                    "notes": str(row.get("notes") or ""),
                }
                for row in reference_payload.get("rows", [])
                if row.get("sample_id")
            }
            if not original:
                raise ValueError("audit reference contains no rows")
            audit = annotations.load_annotations(Path(args.audit))
            if not audit:
                raise ValueError("audit sheet has no completed labels")
            report = annotations.audit_report(original, audit)
            out_path = Path(args.out)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
            markdown_path = Path(args.markdown)
            markdown_path.parent.mkdir(parents=True, exist_ok=True)
            markdown_path.write_text(
                annotations.audit_markdown(report), encoding="utf-8"
            )
        except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(f"Audited sites: {report['n_overlap']} of {len(original)}")
        print(f"Observed agreement: {report['observed_agreement']}")
        print(
            f"Quadratic weighted kappa: {report['cohen_kappa_quadratic']} "
            "(intra-rater, not inter-rater)"
        )
        print(f"Disagreements: {len(report['disagreements'])}")
        print(f"Report: {out_path} and {markdown_path}")
        return 0

    if command == "merge":
        try:
            a_rows = annotations.load_annotations(Path(args.a))
            b_rows = annotations.load_annotations(Path(args.b)) if args.b else {}
            key = annotations.load_key(Path(args.key))
            adjudications = (
                annotations.load_annotations(Path(args.adjudication))
                if args.adjudication
                else {}
            )
            consensus, disagreements, summary = annotations.merge_annotations(
                a_rows, b_rows, key, adjudications
            )
            out_path = Path(args.out)
            disagreement_path = out_path.with_name(out_path.stem + "_disagreements.csv")
            annotations.write_merge_outputs(
                out_path, disagreement_path, consensus, disagreements, summary
            )
        except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(f"Consensus labels: {summary['consensus_count']} -> {out_path}")
        print(f"Disagreements: {summary['unresolved_count']} unresolved -> {disagreement_path}")
        print(f"Sources: {summary['sources']}")
        if summary["unresolved_count"]:
            print(
                "Fill the adjudicated_label column in the disagreements file and rerun merge "
                "with --adjudication pointing at that file."
            )
        if args.apply_to_db:
            storage.init_db()
            applied = 0
            for row in consensus:
                storage.upsert_domain_label(
                    row["domain"],
                    row["label"],
                    "annotation",
                    float(row["confidence"]),
                    f"consensus:{row['source']} {row['note']}"[:1000],
                )
                applied += 1
            print(f"Applied {applied} consensus label(s) to the runtime database.")
            print("Warning: runtime labels can affect future assessments through label floors.")
        return 0

    if command == "dataset":
        try:
            ratios = [float(value) for value in args.ratios.split(",")]
            if len(ratios) != 3:
                raise ValueError("--ratios needs three comma-separated numbers")
            actions = (
                {value.strip() for value in args.actions.split(",") if value.strip()}
                if args.actions
                else None
            )
            assessments, errors, source = _load_research_assessments(args.assessments)
            if not assessments:
                raise ValueError("no assessments found")
            if args.labels:
                labels, label_stats = research_dataset.load_labels(Path(args.labels))
            else:
                labels, label_stats = research_dataset.load_labels_from_db()
            if not labels:
                raise ValueError("no labels found; import labels or pass --labels")
            extra_warnings = []
            if errors:
                extra_warnings.append(
                    f"{len(errors)} assessment row(s) could not be parsed and were skipped"
                )
            uninspected, uninspected_counts = _load_uninspected_domains(
                args.exclude_uninspected
            )
            if uninspected:
                extra_warnings.append(
                    f"{len(uninspected)} domain(s) are excluded because the annotator recorded "
                    "a failed load rather than an observation: "
                    + ", ".join(
                        f"{name}={count}" for name, count in sorted(uninspected_counts.items())
                    )
                )
            manifest = research_dataset.build_dataset(
                assessments,
                labels,
                Path(args.out),
                seed=args.seed,
                ratios=ratios,
                include_suspicious=args.include_suspicious,
                allow_leakage=args.allow_leakage,
                per_domain_limit=args.per_domain_limit,
                actions=actions,
                force=args.force,
                assessment_source=source,
                label_stats=label_stats,
                extra_warnings=extra_warnings,
                uninspected_domains=uninspected,
            )
        except (FileNotFoundError, FileExistsError, ValueError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        if errors:
            print(f"warning: {len(errors)} unreadable assessment row(s); first few:")
            for error in errors[:3]:
                print(f"  {error['path']}:{error['line']} {error['error']}")
        print(f"Dataset written to {Path(args.out)}")
        print(f"Samples: {manifest['samples']} across {manifest['domains']} domains")
        for split, info in manifest["splits"].items():
            print(
                f"  {split:<5} samples={info['samples']:<4} domains={info['domains']:<4} "
                f"labels={info['labels']}"
            )
        print(f"Exclusions: {manifest['exclusions']}")
        print(f"Labels: {manifest['labels']}")
        for warning in manifest["warnings"]:
            print(f"warning: {warning}")
        return 0

    if command == "train":
        groups = [value.strip() for value in args.groups.split(",") if value.strip()]
        try:
            results = training.train_run(
                Path(args.dataset),
                Path(args.out_dir),
                groups=groups or ["all"],
                seed=args.seed,
                bootstrap=args.bootstrap,
                cv_folds=args.cv_folds,
                model_dir=Path(args.models_dir),
                run_name=args.run_name or None,
            )
        except (FileNotFoundError, ValueError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(f"Run directory: {results['run_dir']}")
        for group, group_result in results["groups"].items():
            rule = group_result["models"]["rule_engine"]["test"]
            logistic = group_result["models"]["logistic_regression"]["test"]
            hgb = group_result["models"]["hist_gradient_boosting"]["test"]
            print(
                f"  {group:<8} test AUROC: rule={_fmt_metric(rule.get('roc_auc'))} "
                f"logistic={_fmt_metric(logistic.get('roc_auc'))} "
                f"hgb={_fmt_metric(hgb.get('roc_auc'))} | "
                f"AUPRC logistic={_fmt_metric(logistic.get('average_precision'))}"
            )
            print(f"    logistic artifact: {group_result['artifact']}")
        print(f"Report: {Path(results['run_dir']) / 'report.md'}")
        return 0

    if command == "evaluate":
        try:
            result = training.evaluate_artifact(
                Path(args.model),
                Path(args.dataset),
                split=args.split,
                bootstrap=args.bootstrap,
                seed=args.seed,
            )
        except (FileNotFoundError, ValueError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        payload = json.dumps(result, indent=2)
        if args.out:
            out_path = Path(args.out)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(payload, encoding="utf-8")
            summary = result["metrics"]
            print(f"Evaluation written to {out_path}")
            print(
                f"{result['split']}: n={result['samples']} "
                f"AUROC={_fmt_metric(summary.get('roc_auc'))} "
                f"AUPRC={_fmt_metric(summary.get('average_precision'))} "
                f"F1={_fmt_metric(summary.get('f1'))}"
            )
        else:
            print(payload)
        return 0
    return 1


_REQUIRED_MODULES = (
    ("fastapi", "fastapi"),
    ("uvicorn", "uvicorn"),
    ("pydantic", "pydantic"),
    ("httpx", "httpx"),
    ("bs4", "beautifulsoup4"),
    ("lxml", "lxml"),
    ("tldextract", "tldextract"),
    ("dns", "dnspython"),
    ("cryptography", "cryptography"),
    ("PIL", "Pillow"),
    ("numpy", "numpy"),
    ("sklearn", "scikit-learn"),
    ("pandas", "pandas"),
    ("networkx", "networkx"),
    ("pytesseract", "pytesseract"),
    ("playwright", "playwright"),
    ("xgboost", "xgboost"),
)


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    status: str
    detail: str


def _doctor_python() -> DoctorCheck:
    version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info < (3, 10):
        return DoctorCheck("Python", "FAIL", f"{version} (requires 3.10 or newer)")
    return DoctorCheck("Python", "PASS", version)


def _doctor_dependencies() -> DoctorCheck:
    missing: list[str] = []
    broken: list[str] = []
    for module, package in _REQUIRED_MODULES:
        try:
            importlib.import_module(module)
        except ModuleNotFoundError as exc:
            if exc.name == module:
                missing.append(package)
            else:
                broken.append(f"{package} (missing {exc.name})")
        except Exception as exc:
            broken.append(f"{package} ({type(exc).__name__}: {exc})")
    if missing:
        return DoctorCheck(
            "Dependencies",
            "FAIL",
            "missing " + ", ".join(missing) + "; run: pip install -e .",
        )
    if broken:
        return DoctorCheck("Dependencies", "FAIL", "cannot import " + "; ".join(broken))
    return DoctorCheck("Dependencies", "PASS", f"{len(_REQUIRED_MODULES)} required packages")


def _doctor_knowledge() -> DoctorCheck:
    from . import knowledge

    try:
        brands = len(knowledge.brands())
        trackers = len(knowledge.tracker_defs()[0])
        processors = len(knowledge.payment_processor_domains())
        patterns = len(knowledge.dark_pattern_defs())
        tlds = knowledge.tld_data()
    except Exception as exc:
        return DoctorCheck(
            "Knowledge files", "FAIL", f"{type(exc).__name__}: {exc} (reinstall the package)"
        )
    detail = (
        f"{brands} brands, {trackers} trackers, {processors} payment domains, "
        f"{patterns} dark patterns, {len(tlds.get('suspicious_tlds', []))} suspicious TLDs"
    )
    return DoctorCheck("Knowledge files", "PASS", detail)


def _doctor_psl() -> DoctorCheck:
    from .security import registrable_domain

    path = PACKAGE_ROOT / "data" / "public_suffix_list.dat"
    if not path.is_file():
        return DoctorCheck("Public suffix list", "FAIL", f"missing {path}")
    try:
        domain = registrable_domain("www.example.co.uk")
    except Exception as exc:
        return DoctorCheck("Public suffix list", "FAIL", f"{type(exc).__name__}: {exc}")
    if domain != "example.co.uk":
        return DoctorCheck("Public suffix list", "FAIL", f"unexpected parse result: {domain}")
    return DoctorCheck("Public suffix list", "PASS", "example.co.uk resolves correctly")


def _doctor_dashboard(web_dir: Path) -> DoctorCheck:
    required = (
        web_dir / "index.html",
        web_dir / "static" / "app.js",
        web_dir / "static" / "styles.css",
        web_dir / "static" / "favicon.svg",
    )
    missing = [str(path.name) for path in required if not path.is_file()]
    if missing:
        return DoctorCheck("Dashboard assets", "FAIL", f"missing {', '.join(missing)} in {web_dir}")
    return DoctorCheck("Dashboard assets", "PASS", str(web_dir))


def _doctor_extension() -> DoctorCheck:
    extension_dir = PROJECT_ROOT / "extension"
    manifest_path = extension_dir / "manifest.json"
    if not manifest_path.is_file():
        return DoctorCheck(
            "Browser extension", "WARN", "not bundled in this install; use a source checkout"
        )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return DoctorCheck("Browser extension", "FAIL", f"invalid manifest.json: {exc}")
    required = ("background.js", "popup.html", "popup.js")
    missing = [name for name in required if not (extension_dir / name).is_file()]
    icons = manifest.get("icons", {})
    missing.extend(
        f"icons/{Path(path).name}" for path in icons.values() if not (extension_dir / path).is_file()
    )
    if missing:
        return DoctorCheck("Browser extension", "FAIL", f"missing {', '.join(missing)}")
    return DoctorCheck(
        "Browser extension", "PASS", f"v{manifest.get('version', '?')} at {extension_dir}"
    )


def _doctor_data_dir(config: Any) -> DoctorCheck:
    try:
        config.ensure_dirs()
        with tempfile.NamedTemporaryFile(dir=config.data_dir, prefix=".doctor-", delete=True) as probe:
            probe.write(b"ok")
            probe.flush()
    except OSError as exc:
        return DoctorCheck("Data directory", "FAIL", f"{config.data_dir}: {exc}")
    return DoctorCheck("Data directory", "PASS", str(config.data_dir))


def _doctor_database(config: Any) -> DoctorCheck:
    connection: sqlite3.Connection | None = None
    try:
        config.db_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(config.db_path, timeout=5)
        connection.execute("CREATE TABLE IF NOT EXISTS _doctor_probe (value INTEGER)")
        connection.execute("DELETE FROM _doctor_probe")
        connection.execute("INSERT INTO _doctor_probe VALUES (1)")
        connection.execute("DROP TABLE _doctor_probe")
        connection.commit()
    except sqlite3.Error as exc:
        return DoctorCheck("SQLite database", "FAIL", f"{config.db_path}: {exc}")
    finally:
        if connection is not None:
            connection.close()
    return DoctorCheck("SQLite database", "PASS", str(config.db_path))


def _doctor_chromium(config: Any) -> DoctorCheck:
    if not config.enable_playwright:
        return DoctorCheck("Chromium", "SKIP", "Playwright disabled by TRUSTLENS_ENABLE_PLAYWRIGHT")
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            executable = Path(playwright.chromium.executable_path)
    except Exception as exc:
        return DoctorCheck("Chromium", "FAIL", f"Playwright unavailable: {type(exc).__name__}: {exc}")
    if not executable.is_file():
        return DoctorCheck(
            "Chromium",
            "FAIL",
            f"not installed at {executable}; run: python -m playwright install chromium",
        )
    return DoctorCheck("Chromium", "PASS", str(executable))


def _doctor_tesseract() -> DoctorCheck:
    binary = shutil.which("tesseract")
    if not binary and sys.platform == "win32":
        for root in (Path("C:/Program Files"), Path("C:/Program Files (x86)")):
            candidate = root / "Tesseract-OCR" / "tesseract.exe"
            if candidate.is_file():
                binary = str(candidate)
                break
    if not binary:
        return DoctorCheck("Tesseract OCR", "WARN", "not found; OCR evidence stays unavailable")
    return DoctorCheck("Tesseract OCR", "PASS", binary)


def _doctor_port(config: Any) -> DoctorCheck:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((config.host, config.port))
    except OSError as exc:
        return DoctorCheck(
            "Server port",
            "WARN",
            f"{config.host}:{config.port} unavailable ({exc}); another server may be running",
        )
    return DoctorCheck("Server port", "PASS", f"{config.host}:{config.port} is free")


def _doctor_checks(config: Any) -> list[DoctorCheck]:
    return [
        _doctor_python(),
        _doctor_dependencies(),
        _doctor_knowledge(),
        _doctor_psl(),
        _doctor_dashboard(config.web_dir),
        _doctor_extension(),
        _doctor_data_dir(config),
        _doctor_database(config),
        _doctor_chromium(config),
        _doctor_tesseract(),
        _doctor_port(config),
    ]


def _doctor(args: argparse.Namespace) -> int:
    config = settings()
    checks = _doctor_checks(config)
    failed = [check for check in checks if check.status == "FAIL"]
    warned = [check for check in checks if check.status == "WARN"]
    paths = {
        "data_dir": str(config.data_dir),
        "database": str(config.db_path),
        "web_dir": str(config.web_dir),
        "models_dir": str(config.models_dir),
    }
    extension_dir = PROJECT_ROOT / "extension"
    if extension_dir.is_dir():
        paths["extension_dir"] = str(extension_dir)
    if args.json:
        print(
            json.dumps(
                {
                    "version": ENGINE_VERSION,
                    "ready": not failed,
                    "checks": [asdict(check) for check in checks],
                    "paths": paths,
                },
                indent=2,
            )
        )
    else:
        print(f"TrustLens doctor ({ENGINE_VERSION})")
        for check in checks:
            print(f"  {check.status:<4}  {check.name:<20} {check.detail}")
        print()
        for name, path in paths.items():
            print(f"  {name}: {path}")
        print()
        if failed:
            print(f"NOT READY: {len(failed)} check(s) failed, {len(warned)} warning(s)")
        elif warned:
            print(f"READY with {len(warned)} warning(s)")
        else:
            print("READY: all checks passed")
    return 1 if failed else 0


def serve() -> None:
    import uvicorn

    config = settings()
    uvicorn.run(
        "trustlens.api:app",
        host=config.host,
        port=config.port,
        log_level="info",
    )


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "scan":
        return asyncio.run(_scan(args))
    if args.command == "guard":
        return asyncio.run(_guard(args))
    if args.command == "batch":
        return asyncio.run(_batch(args))
    if args.command == "label":
        storage.init_db()
        storage.upsert_domain_label(
            args.domain,
            args.label,
            args.source,
            max(0.0, min(1.0, args.confidence)),
            args.note,
        )
        print(f"Labeled {args.domain} as {args.label}")
        return 0
    if args.command == "import-labels":
        return _import_labels(Path(args.file), args.source, args.label)
    if args.command == "research":
        return _research(args)
    if args.command == "stats":
        storage.init_db()
        print(json.dumps(storage.stats(), indent=2))
        return 0
    if args.command == "list":
        storage.init_db()
        for row in storage.list_assessments(limit=20):
            print(f"{row['created_at'][:19]}  {row['overall_level']:<8} "
                  f"{row['overall_risk']:5.1f}  {row['domain']:<32} {row['headline']}")
        return 0
    if args.command == "init":
        storage.init_db()
        print(f"Database ready: {storage.db_path()}")
        return 0
    if args.command == "doctor":
        return _doctor(args)
    if args.command == "serve":
        import uvicorn

        settings().ensure_dirs()
        uvicorn.run(
            "trustlens.api:app",
            host=args.host,
            port=args.port,
            reload=args.reload,
            log_level="info",
        )
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
