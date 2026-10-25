from __future__ import annotations

import json
from pathlib import Path

import pytest

from trustlens.research import dataset
from trustlens.scoring.model import FEATURE_SCHEMA_VERSION
from trustlens.schemas import Dimension, Evidence, Severity

from .factories import make_assessment


def _labels(count: int) -> dict[str, dict]:
    return {
        f"dataset{index}.com": {
            "domain": f"dataset{index}.com",
            "label": "malicious" if index % 2 else "benign",
            "source": "synthetic",
            "confidence": 1.0,
            "note": "",
        }
        for index in range(count)
    }


def _assessments(count: int) -> list:
    return [
        make_assessment(
            f"dataset{index}.com",
            malicious=index % 2 == 1,
            minutes_ago=index,
        )
        for index in range(count)
    ]


def test_build_dataset_is_grouped_stratified_and_reproducible(tmp_path: Path) -> None:
    out = tmp_path / "dataset"
    manifest = dataset.build_dataset(_assessments(40), _labels(40), out, seed=5)
    assert manifest["samples"] == 40
    assert manifest["domains"] == 40
    assert manifest["feature_schema_version"] == FEATURE_SCHEMA_VERSION
    assert all(info["samples"] > 0 for info in manifest["splits"].values())
    samples, loaded_manifest = dataset.load_dataset(out / "dataset.jsonl")
    assert len(samples) == 40
    assert loaded_manifest["samples"] == 40
    domains = {
        split: {row["domain"] for row in samples if row["split"] == split}
        for split in dataset.SPLITS
    }
    assert not (domains["train"] & domains["val"])
    assert not (domains["train"] & domains["test"])
    assert not (domains["val"] & domains["test"])
    targets = {
        split: {int(row["target"]) for row in samples if row["split"] == split}
        for split in dataset.SPLITS
    }
    assert len(targets["train"]) == 2
    assert len(targets["val"]) == 2
    assert len(targets["test"]) == 2
    assert (out / "dataset.csv").exists()
    assert (out / "manifest.json").exists()
    with pytest.raises(FileExistsError):
        dataset.build_dataset(_assessments(40), _labels(40), out, seed=5)
    manifest_again = dataset.build_dataset(
        _assessments(40), _labels(40), out, seed=5, force=True
    )
    assert manifest_again["splits"] == manifest["splits"]


def test_leakage_and_suspicious_exclusions(tmp_path: Path) -> None:
    assessments = _assessments(20)
    leaky = make_assessment(
        "leaky-label.com",
        malicious=True,
        extra_evidence=[
            Evidence(
                dimension=Dimension.SECURITY,
                code="known_malicious_label",
                title="Local label",
                detail="Synthetic label evidence.",
                severity=Severity.CRITICAL,
                risk_points=50,
                confidence=1.0,
                source="synthetic",
            )
        ],
        meta_extra={"floors": ["known_malicious_label"]},
    )
    labels = _labels(20)
    labels["leaky-label.com"] = {
        "domain": "leaky-label.com",
        "label": "malicious",
        "source": "synthetic",
        "confidence": 1.0,
        "note": "",
    }
    labels["suspicious-site.com"] = {
        "domain": "suspicious-site.com",
        "label": "suspicious",
        "source": "synthetic",
        "confidence": 0.8,
        "note": "",
    }
    suspicious = make_assessment("suspicious-site.com", risk=45.0)
    manifest = dataset.build_dataset(
        [*assessments, leaky, suspicious], labels, tmp_path / "clean"
    )
    assert manifest["samples"] == 20
    assert manifest["exclusions"]["label_leakage"] == 1
    assert manifest["exclusions"]["excluded_suspicious"] == 1
    allowed = dataset.build_dataset(
        [*assessments, leaky, suspicious],
        labels,
        tmp_path / "allowed",
        allow_leakage=True,
        include_suspicious=True,
    )
    assert allowed["samples"] == 22
    assert allowed["labels"]["suspicious"] == 1


def test_deduplication_and_per_domain_limit(tmp_path: Path) -> None:
    older = make_assessment("dup.com", malicious=False, risk=10.0, minutes_ago=10)
    newer = make_assessment("dup.com", malicious=True, risk=90.0, minutes_ago=1)
    second_page = make_assessment(
        "dup.com", malicious=True, risk=80.0, url="https://dup.com/second", minutes_ago=2
    )
    labels = {
        "dup.com": {
            "domain": "dup.com",
            "label": "malicious",
            "source": "synthetic",
            "confidence": 1.0,
            "note": "",
        }
    }
    manifest = dataset.build_dataset(
        [older, newer, second_page], labels, tmp_path / "dedupe", per_domain_limit=1
    )
    assert manifest["samples"] == 1
    assert manifest["duplicates_removed"] == 1
    assert manifest["exclusions"]["per_domain_limit"] == 1
    samples, _ = dataset.load_dataset(tmp_path / "dedupe" / "dataset.jsonl")
    assert samples[0]["url"].endswith("dup.com/")
    assert samples[0]["features"]["overall_rule_risk"] == 0.9


def test_label_loading_normalises_urls_and_plaintext_blocklists(tmp_path: Path) -> None:
    csv_path = tmp_path / "labels.csv"
    csv_path.write_text(
        "url,expected,source,confidence\n"
        "https://www.Example.com/path,Benign,manual,0.9\n"
        "https://evil-phish.com/phish,Malicious,feed,0.8\n",
        encoding="utf-8",
    )
    labels, stats = dataset.load_labels(csv_path)
    assert labels["example.com"]["label"] == "benign"
    assert labels["evil-phish.com"]["label"] == "malicious"
    assert stats["imported_domains"] == 2
    blocklist = tmp_path / "blocklist.txt"
    blocklist.write_text(
        "# comment\n0.0.0.0 bad-example.com\n||worse-example.net^\n", encoding="utf-8"
    )
    labels, _ = dataset.load_labels(blocklist)
    assert labels["bad-example.com"]["label"] == "malicious"
    assert labels["worse-example.net"]["label"] == "malicious"


def test_assessment_file_loader_reports_bad_rows(tmp_path: Path) -> None:
    path = tmp_path / "assessments.jsonl"
    payload = make_assessment("file-load.com").model_dump(mode="json")
    path.write_text(
        json.dumps(payload) + "\n" + json.dumps({"url": "https://summary-only.com"}) + "\n",
        encoding="utf-8",
    )
    assessments, errors = dataset.load_assessment_files([path])
    assert len(assessments) == 1
    assert assessments[0].domain == "file-load.com"
    assert len(errors) == 1
    assert errors[0]["line"] == 2


def test_not_inspectable_domains_are_excluded_and_reported(tmp_path: Path) -> None:
    out = tmp_path / "dataset"
    manifest = dataset.build_dataset(
        _assessments(40),
        _labels(40),
        out,
        seed=5,
        uninspected_domains=["Dataset0.COM", "dataset1.com", ""],
    )
    assert manifest["samples"] == 38
    assert manifest["domains"] == 38
    assert manifest["exclusions"]["annotator_did_not_inspect"] == 2
    assert set(manifest["exclusion_examples"]["annotator_did_not_inspect"]) == {
        "dataset0.com",
        "dataset1.com",
    }
    assert any("failed load" in warning for warning in manifest["warnings"])
    rows = [
        json.loads(line)
        for line in (out / "dataset.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert "dataset0.com" not in {row["domain"] for row in rows}


def test_uninspected_filter_applies_before_the_suspicious_split(tmp_path: Path) -> None:
    labels = _labels(6)
    labels["dataset3.com"]["label"] = "suspicious"
    excluded = dataset.build_dataset(
        _assessments(6),
        labels,
        tmp_path / "primary",
        seed=5,
        uninspected_domains=["dataset3.com"],
    )
    sensitivity = dataset.build_dataset(
        _assessments(6),
        labels,
        tmp_path / "sensitivity",
        seed=5,
        uninspected_domains=["dataset3.com"],
        include_suspicious=True,
    )
    assert excluded["exclusions"]["annotator_did_not_inspect"] == 1
    assert sensitivity["exclusions"]["annotator_did_not_inspect"] == 1
    assert excluded["samples"] == sensitivity["samples"]
