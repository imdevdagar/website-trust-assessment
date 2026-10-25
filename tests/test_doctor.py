from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from website_trust_assessment.cli import _doctor, _doctor_checks
from website_trust_assessment.config import PACKAGE_ROOT, Settings


def make_settings(tmp_path: Path, *, web_dir: Path | None = None) -> Settings:
    return Settings(
        data_dir=tmp_path / "data",
        db_path=tmp_path / "data" / "website_trust_assessment.db",
        screenshots_dir=tmp_path / "data" / "screenshots",
        annotations_dir=tmp_path / "data" / "annotations",
        models_dir=tmp_path / "models",
        web_dir=web_dir or PACKAGE_ROOT / "web",
        enable_playwright=False,
        host="127.0.0.1",
        port=0,
    )


def test_doctor_reports_no_failures(tmp_path: Path) -> None:
    checks = _doctor_checks(make_settings(tmp_path))
    failed = [check for check in checks if check.status == "FAIL"]
    assert not failed, failed
    statuses = {check.name: check.status for check in checks}
    assert statuses["Knowledge files"] == "PASS"
    assert statuses["Dashboard assets"] == "PASS"
    assert statuses["SQLite database"] == "PASS"
    assert statuses["Chromium"] == "SKIP"
    assert (tmp_path / "data").is_dir()


def test_doctor_flags_missing_dashboard(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "website_trust_assessment.cli.settings", lambda: make_settings(tmp_path, web_dir=tmp_path / "missing")
    )
    assert _doctor(SimpleNamespace(json=True)) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["ready"] is False
    dashboard = next(check for check in payload["checks"] if check["name"] == "Dashboard assets")
    assert dashboard["status"] == "FAIL"
