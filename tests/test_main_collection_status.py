from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import pytest

from trustlens.research import annotations, collection
from trustlens.research.candidates import GATED_COLLECTION

from .factories import make_assessment


def _write_candidates(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["candidate_id", "url", "domain", "stratum", "collection_gate"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def _write_export(path: Path, assessments, failures: list[tuple[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [assessment.model_dump_json() for assessment in assessments]
    lines.extend(json.dumps({"url": url, "error": error}) for url, error in failures)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _fake_root(tmp_path: Path) -> Path:
    domains = [f"site{index}.com" for index in range(4)]
    _write_candidates(
        tmp_path / "data" / "candidates" / "main.csv",
        [
            {
                "candidate_id": f"m_{index}",
                "url": f"https://{domain}/",
                "domain": domain,
                "stratum": "established",
            }
            for index, domain in enumerate(domains)
        ],
    )
    _write_candidates(
        tmp_path / "data" / "candidates" / "main_reserve.csv",
        [{"candidate_id": "r_0", "url": "https://reserve.com/", "domain": "reserve.com"}],
    )
    batch_path = tmp_path / "data" / "candidates" / "main_batch_01.csv"
    _write_candidates(
        batch_path,
        [
            {
                "candidate_id": f"m_{index}",
                "url": f"https://{domain}/",
                "domain": domain,
                "stratum": "established",
            }
            for index, domain in enumerate(domains)
        ],
    )
    (tmp_path / "data" / "candidates" / "main_batches.json").write_text(
        json.dumps(
            {
                "batches": [
                    {
                        "batch": "01",
                        "path": "data/candidates/main_batch_01.csv",
                        "sha256": hashlib.sha256(batch_path.read_bytes()).hexdigest(),
                    }
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (tmp_path / "data" / "candidates" / "main_manifest.json").write_text(
        json.dumps(
            {
                "domains_total": 5,
                "selected": {"established": 4, "scam_feed": 1},
                "reserve": {"established": 1},
            }
        ),
        encoding="utf-8",
    )
    return tmp_path


def test_status_tracks_collection_annotation_and_freeze(tmp_path: Path) -> None:
    root = _fake_root(tmp_path)
    domains = [f"site{index}.com" for index in range(4)]
    assessments = [make_assessment(domain, minutes_ago=30) for domain in domains]
    export = root / "data" / "exports" / "main" / "batch_01.jsonl"
    _write_export(
        export,
        assessments,
        [("http://dead.example/", "Could not resolve hostname: dead.example")],
    )

    status = collection.build_collection_status(root)
    assert status["progress"]["assessments_collected"] == 4
    assert status["progress"]["collection_failures"] == 1
    assert status["batches"][0]["next_action"] == "build queue"
    assert all(
        check["ok"]
        for check in status["integrity_checks"]
        if not check.get("informational")
    )

    annotations.build_queue(
        assessments,
        root / "data" / "annotations" / "main" / "batch_01",
        single_annotator=True,
        seed=42,
    )
    status = collection.build_collection_status(root)
    assert status["batches"][0]["next_action"] == "label"
    assert status["progress"]["sites_queued"] == 4
    assert status["progress"]["sites_pending"] == 4

    sheet = root / "data" / "annotations" / "main" / "batch_01" / "annotator_a.csv"
    rows = annotations.read_csv_rows(sheet)
    rows[0]["label"] = "benign"
    rows[0]["confidence"] = "0.9"
    annotations.write_csv(sheet, annotations.ANNOTATION_FIELDS, rows)
    status = collection.build_collection_status(root)
    assert status["batches"][0]["next_action"] == "continue labelling"
    assert status["progress"]["labels_by_class"]["benign"] == 1

    for row in rows[1:]:
        row["label"] = "benign"
        row["confidence"] = "0.9"
    annotations.write_csv(sheet, annotations.ANNOTATION_FIELDS, rows)
    annotations.freeze_sheet(
        sheet, root / "data" / "annotations" / "main" / "batch_01" / "key.json"
    )
    status = collection.build_collection_status(root)
    batch = status["batches"][0]
    assert batch["next_action"] == "complete"
    assert batch["annotation"]["frozen"] is True
    assert status["progress"]["batches_frozen"] == 1
    window = batch["annotation_window"]
    assert window["assessable"] is True
    assert window["within_window"] is True


def test_redirect_landing_domain_is_recorded_not_a_failure(tmp_path: Path) -> None:
    root = _fake_root(tmp_path)
    assessments = [
        make_assessment("site0.com", minutes_ago=10),
        make_assessment("land.com", url="http://redirecting.com/", minutes_ago=10),
    ]
    _write_export(
        root / "data" / "exports" / "main" / "batch_01.jsonl", assessments, []
    )
    annotations.build_queue(
        assessments,
        root / "data" / "annotations" / "main" / "batch_01",
        single_annotator=True,
        seed=42,
    )
    status = collection.build_collection_status(root)
    redirect = status["batches"][0]["collection"]["redirects"][0]
    assert redirect["final_domain"] == "land.com"
    assert redirect["requested_domain"] == "redirecting.com"
    assert status["progress"]["cross_domain_redirects"] == 1
    informational = [
        check for check in status["integrity_checks"] if check.get("informational")
    ]
    assert informational and informational[0]["detail"]["redirects"]
    assert all(
        check["ok"]
        for check in status["integrity_checks"]
        if not check.get("informational")
    )


def test_status_flags_tampered_batch_and_unexpected_domain(tmp_path: Path) -> None:
    root = _fake_root(tmp_path)
    assessments = [make_assessment("site0.com", minutes_ago=5)]
    _write_export(root / "data" / "exports" / "main" / "batch_01.jsonl", assessments, [])
    annotations.build_queue(
        assessments,
        root / "data" / "annotations" / "main" / "batch_01",
        single_annotator=True,
        seed=42,
    )
    extra = root / "data" / "candidates" / "main_batch_01.csv"
    with extra.open("a", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["m_99", "https://other.com/", "other.com", "established", ""])
    status = collection.build_collection_status(root)
    by_id = {check["id"]: check for check in status["integrity_checks"]}
    assert by_id["batch_hashes_match_manifest"]["ok"] is False
    assert by_id["sheet_matches_collection_batch_01"]["ok"] is True


def test_gated_batch_rows_are_counted(tmp_path: Path) -> None:
    root = _fake_root(tmp_path)
    batch = root / "data" / "candidates" / "main_batch_01.csv"
    rows = list(csv.DictReader(batch.open(encoding="utf-8")))
    rows[0]["collection_gate"] = GATED_COLLECTION
    _write_candidates(
        batch,
        [
            {
                "candidate_id": row["candidate_id"],
                "url": row["url"],
                "domain": row["domain"],
                "stratum": row["stratum"],
                "collection_gate": row["collection_gate"],
            }
            for row in rows
        ],
    )
    (root / "data" / "candidates" / "main_batches.json").write_text(
        json.dumps(
            {
                "batches": [
                    {
                        "batch": "01",
                        "path": "data/candidates/main_batch_01.csv",
                        "sha256": hashlib.sha256(batch.read_bytes()).hexdigest(),
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    status = collection.build_collection_status(root)
    assert status["batches"][0]["candidates"]["gated"] == 1
    failed = {
        check["id"] for check in status["integrity_checks"] if not check["ok"]
    }
    assert "safe_batches_have_no_gated_rows" in failed


def test_write_status_and_markdown(tmp_path: Path) -> None:
    root = _fake_root(tmp_path)
    path = collection.write_status(root)
    assert path == root / "data" / "main_collection_status.json"
    status = json.loads(path.read_text(encoding="utf-8"))
    markdown = collection.status_markdown(status)
    assert "# Main collection status" in markdown
    assert "| Batch |" in markdown
    assert "batch 01" not in markdown or "collect" in markdown


def test_missing_batch_metadata_yields_empty_status(tmp_path: Path) -> None:
    status = collection.build_collection_status(tmp_path)
    assert status["batches"] == []
    assert status["progress"]["assessments_collected"] == 0


@pytest.mark.parametrize("key", ["protocol", "targets", "gated_collection", "reserve_policy"])
def test_status_sections_always_present(tmp_path: Path, key: str) -> None:
    status = collection.build_collection_status(tmp_path)
    assert key in status
