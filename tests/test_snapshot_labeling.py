"""Snapshot-assisted labeling: the captured page image is joined to the annotator's own sheet.

These tests pin the two properties that matter: the join never exposes a verdict field, and a
snapshot is only reachable through a sample_id that exists in the annotator's sheet.
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from tests.factories import make_assessment
from website_trust_assessment.research import annotations
from website_trust_assessment.research.labeling import create_app
from website_trust_assessment.research.snapshots import build_snapshot_index, snapshot_stats

TOKEN = "test-annotation-token"
HEADERS = {"X-Annotation-Token": TOKEN}
PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4"
    "890000000a49444154789c636000000200010000050001"
    "0d0a2db40000000049454e44ae426082"
)


def _write_capture(screenshots: Path, filename: str, *, pad: int = 0) -> str:
    screenshots.mkdir(parents=True, exist_ok=True)
    (screenshots / filename).write_bytes(PNG + b"\x00" * pad)
    return filename


def _export(tmp_path: Path, rows: list[dict]) -> Path:
    path = tmp_path / "export.jsonl"
    path.write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n",
        encoding="utf-8",
    )
    return path


def _fixture(tmp_path: Path):
    """Six queue sites: two unique captures, two identical large captures, two identical blank ones."""
    screenshots = tmp_path / "screenshots"
    assessments = []
    plan = [
        ("capa.com", _write_capture(screenshots, "capa.png", pad=9000)),
        ("capb.com", _write_capture(screenshots, "capb.png", pad=9013)),
        ("capc.com", _write_capture(screenshots, "shared.png", pad=9026)),
        ("capd.com", _write_capture(screenshots, "shared.png", pad=9026)),
        ("cape.com", _write_capture(screenshots, "blank.png")),
        ("capf.com", _write_capture(screenshots, "blank.png")),
    ]
    for index, (domain, filename) in enumerate(plan):
        assessments.append(
            make_assessment(
                domain,
                malicious=index % 2 == 0,
                url=f"http://{domain}/",
                meta_extra={"screenshot_file": filename},
            )
        )
    rows = [assessment.model_dump(mode="json") for assessment in assessments]
    for assessment, row in zip(assessments, rows):
        assert row["meta"]["screenshot_file"] == assessment.meta["screenshot_file"]
    export = _export(tmp_path, rows)

    key = annotations.build_queue(assessments, tmp_path, overlap=0.5, seed=7)
    sheet = tmp_path / "annotator_a.csv"
    index = build_snapshot_index([export], screenshots)
    return key, sheet, index, export, screenshots


def test_index_keys_by_the_url_the_sheet_carries(tmp_path: Path) -> None:
    _, sheet, index, _, _ = _fixture(tmp_path)
    sheet_urls = {row["url"] for row in annotations.read_csv_rows(sheet)}
    assert sheet_urls <= set(index)
    states = {url: index[url].state for url in sorted(sheet_urls)}
    assert states["http://capa.com/"] == "ok"
    assert states["http://capc.com/"] == "duplicate"
    assert states["http://capd.com/"] == "duplicate"
    assert states["http://cape.com/"] == "likely_blank"
    assert index["http://capa.com/"].identical_captures == 1
    assert index["http://capc.com/"].identical_captures == 2


def test_unique_but_tiny_capture_is_still_suspect(tmp_path: Path) -> None:
    screenshots = tmp_path / "screenshots"
    name = _write_capture(screenshots, "tiny.png")
    export = _export(
        tmp_path,
        [
            make_assessment(
                "tiny.com", url="http://tiny.com/", meta_extra={"screenshot_file": name}
            ).model_dump(mode="json")
        ],
    )
    index = build_snapshot_index([export], screenshots)
    ref = index["http://tiny.com/"]
    assert (ref.state, ref.identical_captures) == ("likely_blank", 1)


def test_missing_assessment_file_is_reported(tmp_path: Path) -> None:
    try:
        build_snapshot_index([tmp_path / "absent.jsonl"], tmp_path / "screenshots")
    except FileNotFoundError as exc:
        assert "absent.jsonl" in str(exc)
    else:
        raise AssertionError("a missing export must raise")


def test_snapshot_stats_count_the_sheet(tmp_path: Path) -> None:
    _, _, index, _, _ = _fixture(tmp_path)
    urls = ["http://capa.com/", "http://capc.com/", "http://cape.com/", "http://nope.com/"]
    stats = snapshot_stats(index, urls)
    assert stats == {
        "sites": 4,
        "usable_snapshots": 2,
        "suspect_snapshots": 1,
        "ok": 1,
        "duplicate": 1,
        "likely_blank": 1,
        "missing": 1,
    }


def test_sheet_receives_snapshot_metadata_without_paths_or_verdicts(tmp_path: Path) -> None:
    key, sheet, index, _, _ = _fixture(tmp_path)
    client = TestClient(create_app(sheet, TOKEN, index))
    with client:
        payload = client.get("/api/sites", headers=HEADERS).json()
        assert payload["snapshots"]["sites"] == key["annotator_a_count"]
        by_domain = {site["domain"]: site for site in payload["sites"]}
        assert by_domain["capa.com"]["snapshot"] == {
            "available": True,
            "state": "ok",
            "bytes": by_domain["capa.com"]["snapshot"]["bytes"],
            "identical_captures": 1,
        }
        assert by_domain["capf.com"]["snapshot"]["state"] == "likely_blank"
        text = json.dumps(payload)
        for banned in ("capa.png", "screenshots", "rule_level", "rule_risk", "screenshot_file", "stratum"):
            assert banned not in text


def test_snapshot_endpoint_serves_only_assigned_sample_ids(tmp_path: Path) -> None:
    key, sheet, index, _, screenshots = _fixture(tmp_path)
    client = TestClient(create_app(sheet, TOKEN, index))
    with client:
        site = client.get("/api/sites", headers=HEADERS).json()["sites"][0]
        served = client.get(f"/api/snapshot?sample_id={site['sample_id']}&token={TOKEN}")
        assert served.status_code == 200
        assert served.headers["content-type"] == "image/png"
        assert served.content.startswith(PNG[:8])
        assert client.get("/api/snapshot", params={"sample_id": site["sample_id"]}).status_code == 403
        assert (
            client.get("/api/snapshot", params={"sample_id": "not-in-the-sheet", "token": TOKEN}).status_code
            == 404
        )
        other = {row["sample_id"] for row in annotations.read_csv_rows(tmp_path / "annotator_b.csv")}
        hidden = sorted(other - {row["sample_id"] for row in annotations.read_csv_rows(sheet)})
        if hidden:
            denied = client.get("/api/snapshot", params={"sample_id": hidden[0], "token": TOKEN})
            assert denied.status_code == 404
        assert screenshots.exists()


def test_snapshot_is_absent_when_no_index_is_given(tmp_path: Path) -> None:
    _, sheet, _, _, _ = _fixture(tmp_path)
    client = TestClient(create_app(sheet, TOKEN))
    with client:
        payload = client.get("/api/sites", headers=HEADERS).json()
        assert all(site["snapshot"] == {"available": False, "state": "unavailable"} for site in payload["sites"])
        assert payload["snapshots"]["sites"] == len(payload["sites"])
        assert payload["snapshots"]["missing"] == len(payload["sites"])
        site = payload["sites"][0]
        assert client.get(
            "/api/snapshot", params={"sample_id": site["sample_id"], "token": TOKEN}
        ).status_code == 404


def test_saved_annotation_keeps_the_snapshot(tmp_path: Path) -> None:
    _, sheet, index, _, _ = _fixture(tmp_path)
    client = TestClient(create_app(sheet, TOKEN, index))
    with client:
        site = client.get("/api/sites", headers=HEADERS).json()["sites"][0]
        saved = client.post(
            "/api/annotations",
            headers=HEADERS,
            json={"sample_id": site["sample_id"], "label": "benign", "confidence": 0.9, "notes": ""},
        ).json()
        assert saved["site"]["snapshot"] == site["snapshot"]
        assert saved["site"]["snapshot"]["available"] is True
