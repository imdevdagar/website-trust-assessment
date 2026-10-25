from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from website_trust_assessment.research import annotations

from .factories import make_assessment


def _fill_sheet(
    path: Path,
    labels: dict[str, str],
    fallback: str = "benign",
) -> None:
    rows = annotations.read_csv_rows(path)
    filled = []
    for row in rows:
        sample_id = row["sample_id"]
        filled.append(
            {
                **row,
                "label": labels.get(sample_id, fallback),
                "confidence": "0.9",
                "notes": "synthetic",
            }
        )
    annotations.write_csv(path, annotations.ANNOTATION_FIELDS, filled)


def test_queue_is_blinded_and_assignments_add_up(tmp_path: Path) -> None:
    assessments = [
        make_assessment(f"queue{index}.com", malicious=index % 2 == 0) for index in range(10)
    ]
    key = annotations.build_queue(assessments, tmp_path, overlap=0.4, seed=7)
    assert key["sample_count"] == 10
    assert key["assignments"] == {"overlap": 4, "a_only": 3, "b_only": 3}
    assert key["annotator_a_count"] == 7
    assert key["annotator_b_count"] == 7
    queue_rows = annotations.read_csv_rows(tmp_path / "queue.csv")
    assert "label" not in queue_rows[0]
    assert "rule_risk" not in queue_rows[0]
    assert (tmp_path / "key.json").exists()
    with pytest.raises(FileExistsError):
        annotations.build_queue(assessments, tmp_path, overlap=0.4, seed=7)


def test_single_annotator_queue_assigns_every_site_to_a(tmp_path: Path) -> None:
    assessments = [
        make_assessment(f"single{index}.com", malicious=index % 2 == 0)
        for index in range(8)
    ]
    key = annotations.build_queue(
        assessments, tmp_path, seed=9, single_annotator=True
    )
    assert key["single_annotator"] is True
    assert key["overlap"] == 0.0
    assert key["assignments"] == {"a_only": 8}
    assert key["annotator_a_count"] == 8
    assert key["annotator_b_count"] == 0
    assert len(annotations.read_csv_rows(tmp_path / "annotator_a.csv")) == 8
    assert annotations.read_csv_rows(tmp_path / "annotator_b.csv") == []
    assert all(
        item["assignment"] == "a_only" for item in key["samples"]
    )

    sheet = tmp_path / "annotator_a.csv"
    _fill_sheet(sheet, {})
    report = annotations.validate_sheet(sheet, key)
    assert report["ok"] is True
    assert report["annotated"] == 8

    a_rows = annotations.load_annotations(sheet)
    consensus, disagreements, summary = annotations.merge_annotations(
        a_rows, {}, key
    )
    assert len(consensus) == 8
    assert disagreements == []
    assert summary["sources"] == {"single_annotator": 8}


def test_agreement_and_consensus_with_adjudication(tmp_path: Path) -> None:
    assessments = [
        make_assessment(f"agree{index}.com", malicious=index % 2 == 0) for index in range(10)
    ]
    key = annotations.build_queue(assessments, tmp_path, overlap=0.4, seed=11)
    a_path = tmp_path / "annotator_a.csv"
    b_path = tmp_path / "annotator_b.csv"
    _fill_sheet(a_path, {})
    _fill_sheet(b_path, {})
    a_rows = annotations.load_annotations(a_path)
    b_rows = annotations.load_annotations(b_path)
    shared = sorted(set(a_rows) & set(b_rows))
    assert len(shared) == 4
    disputed = shared[0]
    a_rows[disputed]["label"] = "malicious"
    b_rows[disputed]["label"] = "benign"

    report = annotations.agreement_report(a_rows, b_rows)
    assert report["n_overlap"] == 4
    assert report["observed_agreement"] == 0.75
    assert report["cohen_kappa"] < 1.0
    assert len(report["disagreements"]) == 1

    consensus, disagreements, summary = annotations.merge_annotations(
        a_rows, b_rows, key
    )
    assert summary["unresolved_count"] == 1
    assert len(consensus) == 9
    assert len(disagreements) == 1
    assert disagreements[0]["resolved"] is False
    assert summary["sources"]["single_annotator"] == 6
    assert summary["sources"]["double_agreement"] == 3

    adjudication = {
        disputed: {
            "sample_id": disputed,
            "label": "suspicious",
            "confidence": 1.0,
            "notes": "coordinator decision",
        }
    }
    consensus, disagreements, summary = annotations.merge_annotations(
        a_rows, b_rows, key, adjudication
    )
    assert summary["unresolved_count"] == 0
    assert len(consensus) == 10
    assert summary["sources"]["adjudicated"] == 1
    assert disagreements[0]["resolved"] is True
    assert disagreements[0]["adjudicated_label"] == "suspicious"

    annotations.write_merge_outputs(
        tmp_path / "consensus.csv",
        tmp_path / "disagreements.csv",
        consensus,
        disagreements,
        summary,
    )
    assert (tmp_path / "consensus.csv").exists()
    assert (tmp_path / "disagreements.csv").exists()
    assert (tmp_path / "consensus_summary.json").exists()
    reloaded = annotations.load_annotations(tmp_path / "disagreements.csv")
    assert reloaded[disputed]["label"] == "suspicious"


def test_perfect_agreement_and_label_validation() -> None:
    a_rows = {
        "s1": {"sample_id": "s1", "label": "benign", "confidence": 1.0, "notes": ""},
        "s2": {"sample_id": "s2", "label": "malicious", "confidence": 1.0, "notes": ""},
    }
    b_rows = {key: dict(value) for key, value in a_rows.items()}
    report = annotations.agreement_report(a_rows, b_rows)
    assert report["cohen_kappa"] == 1.0
    assert report["disagreements"] == []
    bad = {"s1": {"sample_id": "s1", "label": "unknown", "confidence": 1.0, "notes": ""}}
    with pytest.raises(ValueError):
        annotations.merge_annotations(a_rows, bad, {"samples": []})


def test_audit_queue_is_blind_and_reports_intra_rater_agreement(tmp_path: Path) -> None:
    assessments = [
        make_assessment(f"audit{index}.com", malicious=index % 2 == 0)
        for index in range(20)
    ]
    key = annotations.build_queue(
        assessments, tmp_path, seed=17, single_annotator=True
    )
    sheet = tmp_path / "annotator_a.csv"
    labels = {
        row["sample_id"]: ("malicious" if index % 3 == 0 else "benign")
        for index, row in enumerate(annotations.read_csv_rows(sheet))
    }
    _fill_sheet(sheet, labels)
    audit_dir = tmp_path / "audit"
    reference = annotations.build_audit_queue(
        sheet,
        tmp_path / "key.json",
        audit_dir,
        fraction=0.5,
        min_domains=10,
        seed=5,
    )
    assert reference["selected"] == 10
    assert reference["available"] == 20
    assert set(reference["by_label"]) == {"benign", "malicious"}
    assert sum(reference["by_label"].values()) == 10
    assert reference["delay_days"] == 7
    assert reference["not_before"]
    rows = annotations.read_csv_rows(audit_dir / "annotator_a_audit.csv")
    assert len(rows) == 10
    assert all(row["label"] == "" for row in rows)
    assert all("original_label" not in row for row in rows)
    audit_key = json.loads((audit_dir / "audit_key.json").read_text(encoding="utf-8"))
    assert audit_key["purpose"] == "delayed_blind_intra_rater_audit"
    assert audit_key["sample_count"] == 10
    assert audit_key["assignments"] == {"a_only": 10}

    original = {
        row["sample_id"]: {
            "sample_id": row["sample_id"],
            "label": row["label"],
            "confidence": float(row["confidence"]),
            "notes": row["notes"],
        }
        for row in reference["rows"]
    }
    audit = {
        sample_id: {
            "sample_id": sample_id,
            "label": row["label"],
            "confidence": 0.9,
            "notes": row["notes"],
        }
        for sample_id, row in original.items()
    }
    report = annotations.audit_report(original, audit)
    assert report["mode"] == "delayed_blind_intra_rater_audit"
    assert report["n_overlap"] == 10
    assert report["observed_agreement"] == 1.0
    assert "intra-rater" in annotations.audit_markdown(report)


def test_freeze_rejects_an_incomplete_sheet(tmp_path: Path) -> None:
    assessments = [
        make_assessment(f"freeze{index}.com", malicious=index % 2 == 0)
        for index in range(6)
    ]
    annotations.build_queue(assessments, tmp_path, overlap=0.5, seed=3)
    report = annotations.validate_sheet(
        tmp_path / "annotator_a.csv",
        annotations.load_key(tmp_path / "key.json"),
    )
    assert report["ok"] is False
    assert report["annotated"] == 0
    assert any("missing label" in issue for issue in report["issues"])
    with pytest.raises(ValueError, match="missing label"):
        annotations.freeze_sheet(
            tmp_path / "annotator_a.csv", tmp_path / "key.json"
        )
    assert not (tmp_path / "frozen").exists()


def test_freeze_requires_notes_for_malicious_labels(tmp_path: Path) -> None:
    assessments = [
        make_assessment(f"notes{index}.com", malicious=index % 2 == 0)
        for index in range(4)
    ]
    annotations.build_queue(assessments, tmp_path, overlap=1.0, seed=5)
    sheet = tmp_path / "annotator_a.csv"
    _fill_sheet(sheet, {})
    rows = annotations.read_csv_rows(sheet)
    rows[0]["label"] = "malicious"
    rows[0]["notes"] = ""
    annotations.write_csv(sheet, annotations.ANNOTATION_FIELDS, rows)

    report = annotations.validate_sheet(
        sheet, annotations.load_key(tmp_path / "key.json")
    )
    assert not report["ok"]
    assert any("notes are required" in issue for issue in report["issues"])
    with pytest.raises(ValueError, match="notes are required"):
        annotations.freeze_sheet(sheet, tmp_path / "key.json")


def test_freeze_rejects_a_sheet_for_the_other_annotator(tmp_path: Path) -> None:
    assessments = [
        make_assessment(f"role{index}.com", malicious=index % 2 == 0)
        for index in range(10)
    ]
    annotations.build_queue(assessments, tmp_path, overlap=0.4, seed=7)
    sheet = tmp_path / "annotator_a.csv"
    _fill_sheet(sheet, {})
    report = annotations.validate_sheet(
        sheet,
        annotations.load_key(tmp_path / "key.json"),
        role="b",
    )
    assert not report["ok"]
    assert any("not assigned to annotator B" in issue for issue in report["issues"])


def test_freeze_writes_a_read_only_archive_and_hash_record(tmp_path: Path) -> None:
    assessments = [
        make_assessment(f"archive{index}.com", malicious=index % 2 == 0)
        for index in range(6)
    ]
    key = annotations.build_queue(assessments, tmp_path, overlap=0.5, seed=13)
    sheet = tmp_path / "annotator_a.csv"
    key_path = tmp_path / "key.json"
    _fill_sheet(sheet, {})

    archive, record_path, record = annotations.freeze_sheet(sheet, key_path)
    try:
        assert record["role"] == "a"
        assert record["annotated"] == key["annotator_a_count"]
        assert record["expected"] == key["annotator_a_count"]
        assert archive.read_bytes() == sheet.read_bytes()
        assert record["sha256"] == hashlib.sha256(sheet.read_bytes()).hexdigest()
        assert not os.access(archive, os.W_OK)
        stored = json.loads(record_path.read_text(encoding="utf-8"))
        assert stored["sha256"] == record["sha256"]
        assert stored["key_sha256"] == hashlib.sha256(key_path.read_bytes()).hexdigest()
        assert (tmp_path / "frozen" / record["archive"]).exists()
    finally:
        os.chmod(archive, stat.S_IWRITE | stat.S_IREAD)
