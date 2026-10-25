from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from tests.factories import make_assessment
from trustlens.research import annotations
from trustlens.research.labeling import create_app

TOKEN = "test-annotation-token"
HEADERS = {"X-Annotation-Token": TOKEN}


def _build(tmp_path: Path) -> tuple[TestClient, Path, dict]:
    assessments = [
        make_assessment(f"labelui{index}.com", malicious=index % 2 == 0)
        for index in range(6)
    ]
    key = annotations.build_queue(assessments, tmp_path, overlap=0.5, seed=7)
    sheet = tmp_path / "annotator_a.csv"
    app = create_app(sheet, TOKEN)
    return TestClient(app), sheet, key


def test_label_ui_loads_only_the_blind_sheet(tmp_path: Path) -> None:
    client, _, key = _build(tmp_path)
    with client:
        response = client.get("/api/sites", headers=HEADERS)
        assert response.status_code == 200
        payload = response.json()
        assert payload["sheet"] == "annotator_a.csv"
        assert payload["role"] == "A"
        assert len(payload["sites"]) == key["annotator_a_count"]
        assert payload["progress"] == {
            "labeled": 0,
            "total": key["annotator_a_count"],
            "by_label": {"benign": 0, "suspicious": 0, "malicious": 0},
            "complete": False,
        }
        assert payload["frozen"] is False
        site = payload["sites"][0]
        assert set(site) == {
            "sample_id",
            "url",
            "domain",
            "action",
            "label",
            "confidence",
            "notes",
            "openable",
            "snapshot",
        }
        assert site["snapshot"] == {"available": False, "state": "unavailable"}
        assert payload["snapshots"]["sites"] == key["annotator_a_count"]
        assert "rule_risk" not in response.text
        assert "rule_level" not in response.text
        assert "assignment" not in response.text


def test_label_ui_requires_the_annotation_token(tmp_path: Path) -> None:
    client, _, _ = _build(tmp_path)
    with client:
        assert client.get("/api/sites").status_code == 403
        assert client.get("/api/sites", headers={"X-Annotation-Token": "wrong"}).status_code == 403
        assert client.get("/").status_code == 403
        assert client.get("/", params={"token": TOKEN}).status_code == 200
        assert "Blind annotation" in client.get("/", params={"token": TOKEN}).text


def test_label_ui_saves_a_human_label_to_the_csv(tmp_path: Path) -> None:
    client, sheet, _ = _build(tmp_path)
    with client:
        site = client.get("/api/sites", headers=HEADERS).json()["sites"][0]
        response = client.post(
            "/api/annotations",
            headers=HEADERS,
            json={
                "sample_id": site["sample_id"],
                "label": "benign",
                "confidence": 0.85,
                "notes": "established identity and consistent contact page",
            },
        )
        assert response.status_code == 200
        saved = response.json()["site"]
        assert saved["label"] == "benign"
        assert saved["confidence"] == 0.85
        assert response.json()["progress"]["labeled"] == 1

    rows = annotations.read_csv_rows(sheet)
    row = next(item for item in rows if item["sample_id"] == site["sample_id"])
    assert row["label"] == "benign"
    assert row["confidence"] == "0.85"
    assert row["notes"] == "established identity and consistent contact page"


def test_label_ui_requires_notes_for_suspicious_and_malicious(tmp_path: Path) -> None:
    client, sheet, _ = _build(tmp_path)
    with client:
        sites = client.get("/api/sites", headers=HEADERS).json()["sites"]
        for label in ("suspicious", "malicious"):
            response = client.post(
                "/api/annotations",
                headers=HEADERS,
                json={
                    "sample_id": sites[0]["sample_id"],
                    "label": label,
                    "confidence": 0.7,
                    "notes": "   ",
                },
            )
            assert response.status_code == 422
            assert "notes are required" in response.json()["detail"]

    rows = annotations.read_csv_rows(sheet)
    assert all(not row["label"] for row in rows)


def test_label_ui_rejects_invalid_confidence_and_unknown_samples(tmp_path: Path) -> None:
    client, _, _ = _build(tmp_path)
    with client:
        site = client.get("/api/sites", headers=HEADERS).json()["sites"][0]
        for confidence in (-0.1, 1.5):
            response = client.post(
                "/api/annotations",
                headers=HEADERS,
                json={
                    "sample_id": site["sample_id"],
                    "label": "benign",
                    "confidence": confidence,
                    "notes": "",
                },
            )
            assert response.status_code == 422
        response = client.post(
            "/api/annotations",
            headers=HEADERS,
            json={
                "sample_id": "s_not_in_this_sheet",
                "label": "benign",
                "confidence": 0.9,
                "notes": "",
            },
        )
        assert response.status_code == 404


def test_label_ui_is_read_only_after_freeze(tmp_path: Path) -> None:
    client, sheet, _ = _build(tmp_path)
    frozen = tmp_path / "frozen"
    frozen.mkdir()
    (frozen / "annotator_a_20990101T000000Z.freeze.json").write_text(
        json.dumps(
            {
                "source_sheet": "annotator_a.csv",
                "frozen_at": "2099-01-01T00:00:00+00:00",
                "sha256": "test",
            }
        ),
        encoding="utf-8",
    )
    with client:
        payload = client.get("/api/sites", headers=HEADERS).json()
        assert payload["frozen"] is True
        site = payload["sites"][0]
        response = client.post(
            "/api/annotations",
            headers=HEADERS,
            json={
                "sample_id": site["sample_id"],
                "label": "benign",
                "confidence": 0.9,
                "notes": "",
            },
        )
        assert response.status_code == 409
        assert "frozen" in response.json()["detail"]

    rows = annotations.read_csv_rows(sheet)
    assert all(not row["label"] for row in rows)
