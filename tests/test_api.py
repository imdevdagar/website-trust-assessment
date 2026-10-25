from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.factories import make_assessment
from trustlens import storage
from trustlens.api import create_app
from trustlens.config import PACKAGE_ROOT, Settings
from trustlens.schemas import Action
from trustlens.security import check_url_structure


class FakeAssessor:
    """Replaces the crawler so API tests never touch the network."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, Action, bool]] = []

    async def assess(
        self,
        url: str,
        action: Action = Action.BROWSE,
        *,
        force_refresh: bool = False,
    ):
        parts = check_url_structure(url)
        self.calls.append((parts.url, action, force_refresh))
        risky = "risky" in parts.host
        assessment = make_assessment(
            parts.registrable_domain,
            malicious=risky,
            action=action,
        ).model_copy(
            update={
                "url": parts.url,
                "normalized_url": parts.url,
                "final_url": parts.url,
                "cached": force_refresh,
            }
        )
        storage.save_assessment(assessment)
        return assessment


def make_settings(tmp_path: Path, *, rate_limit: int = 100) -> Settings:
    return Settings(
        data_dir=tmp_path / "data",
        db_path=tmp_path / "data" / "trustlens.db",
        screenshots_dir=tmp_path / "data" / "screenshots",
        annotations_dir=tmp_path / "data" / "annotations",
        models_dir=tmp_path / "models",
        web_dir=PACKAGE_ROOT / "web",
        enable_playwright=False,
        rate_limit_per_minute=rate_limit,
    )


@contextmanager
def running_client(tmp_path: Path, *, rate_limit: int = 100) -> Iterator[TestClient]:
    app = create_app(make_settings(tmp_path, rate_limit=rate_limit))
    with TestClient(app) as client:
        app.state.assessor = FakeAssessor()
        yield client


@pytest.fixture()
def client(tmp_path: Path) -> Iterator[TestClient]:
    with running_client(tmp_path) as test_client:
        yield test_client


@pytest.fixture()
def rate_limited_client(tmp_path: Path) -> Iterator[TestClient]:
    with running_client(tmp_path, rate_limit=1) as test_client:
        yield test_client


def test_health_reports_local_capabilities_and_security_headers(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["playwright_enabled"] is False
    assert isinstance(body["ocr_available"], bool)
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]


def test_docs_are_exempt_from_csp_but_keep_other_headers(client: TestClient) -> None:
    response = client.get("/docs")

    assert response.status_code == 200
    assert "Content-Security-Policy" not in response.headers
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_root_redirects_to_dashboard_and_dashboard_is_served(client: TestClient) -> None:
    redirect = client.get("/", follow_redirects=False)
    assert redirect.status_code in {302, 307}
    assert redirect.headers["location"] == "/dashboard"

    dashboard = client.get("/dashboard")
    assert dashboard.status_code == 200
    assert dashboard.headers["content-type"].startswith("text/html")
    assert "Website Trust Assessment" in dashboard.text


def test_assessment_flow_persists_listing_detail_feedback_and_stats(client: TestClient) -> None:
    response = client.post(
        "/v1/assess",
        json={"url": "https://example.com/", "action": "signup"},
    )

    assert response.status_code == 200
    body = response.json()
    assessment_id = body["id"]
    assert body["action"] == "signup"
    assert body["domain"] == "example.com"
    assert body["overall_level"] == "low"
    assert body["evidence"]
    assert response.headers["X-Website-Trust-Assessment"] == assessment_id
    assert response.headers["X-Website-Trust-Cache"] == "miss"
    assert response.headers["Cache-Control"] == "no-store"

    listing = client.get("/v1/assessments", params={"domain": "example.com"})
    assert listing.status_code == 200
    rows = listing.json()
    assert [row["id"] for row in rows] == [assessment_id]

    detail = client.get(f"/v1/assessments/{assessment_id}")
    assert detail.status_code == 200
    assert detail.json()["id"] == assessment_id
    assert detail.json()["meta"]["engine_version"] == "test"

    feedback = client.post(
        "/v1/feedback",
        json={"assessment_id": assessment_id, "verdict": "agree", "note": "clear evidence"},
    )
    assert feedback.status_code == 200
    assert feedback.json()["ok"] is True

    stats = client.get("/v1/stats")
    assert stats.status_code == 200
    assert stats.json()["total_assessments"] == 1
    assert stats.json()["feedback_count"] == 1


def test_guard_returns_actionable_verdicts(client: TestClient) -> None:
    blocked = client.post(
        "/v1/guard",
        json={"url": "https://risky.com/", "requested_action": "purchase"},
    )
    assert blocked.status_code == 200
    blocked_body = blocked.json()
    assert blocked_body["verdict"] == "block"
    assert blocked_body["overall_level"] == "high"
    assert blocked_body["reasons"]
    assert blocked_body["assessment_id"]

    allowed = client.post("/v1/guard", json={"url": "https://example.com/"})
    assert allowed.status_code == 200
    assert allowed.json()["verdict"] == "allow"


def test_unsafe_url_and_invalid_payloads_are_rejected(client: TestClient) -> None:
    unsafe = client.post("/v1/assess", json={"url": "http://127.0.0.1/"})
    assert unsafe.status_code == 400
    assert unsafe.json()["detail"].startswith("URL cannot be assessed safely")

    short_url = client.post("/v1/assess", json={"url": ""})
    assert short_url.status_code == 422

    bad_action = client.post("/v1/assess", json={"url": "https://example.com/", "action": "delete"})
    assert bad_action.status_code == 422

    bad_level = client.get("/v1/assessments", params={"level": "severe"})
    assert bad_level.status_code == 422

    assert client.get("/v1/assessments/does-not-exist").status_code == 404

    missing_feedback = client.post(
        "/v1/feedback",
        json={"assessment_id": "missing-id", "verdict": "unsure"},
    )
    assert missing_feedback.status_code == 404


def test_assessment_rate_limit_is_enforced(rate_limited_client: TestClient) -> None:
    first = rate_limited_client.post("/v1/assess", json={"url": "https://example.com/"})
    second = rate_limited_client.post("/v1/assess", json={"url": "https://example.com/"})

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.headers["Retry-After"] == "60"
    assert "Too many assessments" in second.json()["detail"]
