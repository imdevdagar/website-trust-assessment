from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import pytest

from website_trust_assessment.cli import _load_uninspected_domains

ROOT = Path(__file__).resolve().parents[1]
BATCH_DIR = ROOT / "data" / "annotations" / "main" / "batch_01"


def test_loader_accepts_csv_and_json_records(tmp_path: Path) -> None:
    csv_path = tmp_path / "non_inspections.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["sample_id", "domain", "classification"])
        writer.writeheader()
        writer.writerow({"sample_id": "s_1", "domain": "Refused.Example", "classification": "x"})
    json_path = tmp_path / "record.json"
    json_path.write_text(
        json.dumps(
            {
                "excluded_domains": ["timeout.example"],
                "rows": [{"domain": "listed.example", "classification": "no_response"}],
            }
        ),
        encoding="utf-8",
    )
    domains, counts = _load_uninspected_domains([str(csv_path), str(json_path)])
    assert domains == {"refused.example", "timeout.example", "listed.example"}
    assert counts == {csv_path.name: 1, json_path.name: 2}


def test_loader_rejects_an_empty_or_missing_record(tmp_path: Path) -> None:
    empty = tmp_path / "empty.csv"
    empty.write_text("sample_id\ns_1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="no domain column"):
        _load_uninspected_domains([str(empty)])
    with pytest.raises(FileNotFoundError):
        _load_uninspected_domains([str(tmp_path / "absent.csv")])


@pytest.mark.skipif(
    not (BATCH_DIR / "frozen").exists(), reason="batch 1 has not been frozen in this checkout"
)
def test_batch_1_freeze_and_non_inspection_artifacts_agree() -> None:
    records = sorted((BATCH_DIR / "frozen").glob("*.freeze.json"))
    assert records, "a freeze record must exist alongside the archive"
    record = json.loads(records[-1].read_text(encoding="utf-8"))
    archive = BATCH_DIR / "frozen" / record["archive"]
    assert record["sha256"] == hashlib.sha256(archive.read_bytes()).hexdigest()
    assert record["annotated"] == record["expected"]

    csv_path = BATCH_DIR / "non_inspections.csv"
    json_path = BATCH_DIR / "amendments" / "main_batch_01_non_inspections.json"
    if not csv_path.exists():
        pytest.skip("the non-inspection record has not been generated in this checkout")
    rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    sheet = {
        row["domain"]: row
        for row in csv.DictReader(
            (BATCH_DIR / "annotator_a.csv").open(encoding="utf-8")
        )
    }

    assert payload["changes_labels"] is False
    assert payload["excluded_domains"] == sorted(row["domain"] for row in rows)
    assert payload["frozen_sheet"]["archive_sha256"] == record["sha256"]
    assert payload["counts"]["labelled_sites"] == len(sheet)
    assert {row["classification"] for row in rows} == {"server_refusal", "no_response"}
    for row in rows:
        assert row["domain"] in sheet, "only labelled sites can be classified"
        assert row["label"] == sheet[row["domain"]]["label"]
        assert row["annotator_note"] == sheet[row["domain"]]["notes"]
    assert not any(
        row["classification"] == "server_refusal" and int(row["transport_status"] or 0) < 400
        for row in rows
    )


@pytest.mark.skipif(
    not (BATCH_DIR / "frozen").exists(), reason="batch 1 has not been frozen in this checkout"
)
def test_no_reachable_page_is_marked_not_inspectable() -> None:
    json_path = BATCH_DIR / "amendments" / "main_batch_01_non_inspections.json"
    triage = json.loads(
        (BATCH_DIR / "reachability_triage.json").read_text(encoding="utf-8")
    )
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    excluded = set(payload["excluded_domains"])
    for item in triage["results"]:
        reachable = item["outcome"] == "reachable" and item.get("status") == 200
        assert not (reachable and item["domain"] in excluded), item["domain"]
        if item["outcome"] == "no_http_response":
            assert item["domain"] in excluded
