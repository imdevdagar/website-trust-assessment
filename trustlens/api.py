"""FastAPI application for the local website trust assessment service."""

from __future__ import annotations

import logging
import time
from collections import deque
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from . import ENGINE_VERSION, storage
from .config import Settings, settings
from .evidence.visual import tesseract_available
from .pipeline import Assessor, guard_decision
from .schemas import (
    Assessment,
    AssessmentListItem,
    AssessmentRequest,
    FeedbackRequest,
    GuardRequest,
    GuardResponse,
    StatsResponse,
    SubmissionResponse,
)
from .security import UnsafeURLError

logger = logging.getLogger("trustlens.api")

CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "font-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)
DOC_PATHS = ("/docs", "/redoc", "/openapi.json")


class RateLimiter:
    def __init__(self, limit: int, window_seconds: float = 60.0) -> None:
        self.limit = max(1, limit)
        self.window = window_seconds
        self._events: dict[str, deque[float]] = {}

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        bucket = self._events.setdefault(key, deque())
        cutoff = now - self.window
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= self.limit:
            return False
        bucket.append(now)
        if len(self._events) > 2048:
            self._events = {
                name: values for name, values in self._events.items() if values and values[-1] >= cutoff
            }
        return True


def _assessor(request: Request) -> Assessor:
    assessor = getattr(request.app.state, "assessor", None)
    if assessor is None:
        raise HTTPException(status_code=503, detail="Assessment engine is not ready")
    return assessor


def _rate_limit(request: Request) -> None:
    limiter: RateLimiter | None = getattr(request.app.state, "rate_limiter", None)
    if limiter is None:
        return
    client = request.client.host if request.client else "local"
    if not limiter.allow(client):
        raise HTTPException(
            status_code=429,
            detail="Too many assessments in the last minute",
            headers={"Retry-After": "60"},
        )


def create_app(cfg: Settings | None = None) -> FastAPI:
    config = cfg or settings()
    config.ensure_dirs()
    limiter = RateLimiter(config.rate_limit_per_minute)

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        storage.configure(config)
        storage.init_db()
        application.state.assessor = Assessor(config)
        application.state.rate_limiter = limiter
        logger.info("Website Trust Assessment System %s ready on %s:%s", ENGINE_VERSION, config.host, config.port)
        yield

    application = FastAPI(
        title="Website Trust Assessment System",
        version=ENGINE_VERSION,
        summary="Evidence-grounded, multi-dimensional website trust assessment",
        description=(
            "Local-first research prototype. The system crawls a public page, gathers security, "
            "identity, privacy, and manipulation evidence, and returns an action-aware risk "
            "profile with confidence and abstention. Scores are advisory, not verdicts."
        ),
        lifespan=lifespan,
    )

    if config.allowed_origins:
        application.add_middleware(
            CORSMiddleware,
            allow_origins=list(config.allowed_origins),
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Content-Type"],
            max_age=600,
        )

    @application.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
        if not request.url.path.startswith(DOC_PATHS):
            response.headers.setdefault("Content-Security-Policy", CSP)
        return response

    @application.exception_handler(UnsafeURLError)
    async def unsafe_url_handler(request: Request, exc: UnsafeURLError):
        return JSONResponse(
            status_code=400,
            content={"detail": f"URL cannot be assessed safely: {exc}"},
        )

    @application.exception_handler(Exception)
    async def unhandled_handler(request: Request, exc: Exception):
        logger.exception("Unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal assessment error. Check the server log for details."},
        )

    @application.get("/", include_in_schema=False)
    async def root() -> RedirectResponse:
        return RedirectResponse("/dashboard")

    @application.get("/health", tags=["system"])
    async def health() -> dict[str, Any]:
        try:
            assessments = storage.count_assessments()
        except Exception:
            assessments = None
        return {
            "status": "ok",
            "version": ENGINE_VERSION,
            "assessments": assessments,
            "playwright_enabled": config.enable_playwright,
            "ocr_available": tesseract_available(),
            "cache_ttl_seconds": config.cache_ttl_seconds,
        }

    @application.post(
        "/v1/assess",
        response_model=SubmissionResponse,
        tags=["assessment"],
        dependencies=[Depends(_rate_limit)],
    )
    async def assess(
        payload: AssessmentRequest,
        request: Request,
        response: Response,
        assessor: Assessor = Depends(_assessor),
    ) -> SubmissionResponse:
        try:
            result = await assessor.assess(
                payload.url,
                payload.action,
                force_refresh=payload.force_refresh,
            )
        except UnsafeURLError:
            raise
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        response.headers["X-Website-Trust-Assessment"] = result.id
        response.headers["X-Website-Trust-Cache"] = "hit" if result.cached else "miss"
        response.headers["Cache-Control"] = "no-store"
        return SubmissionResponse.from_assessment(result)

    @application.get(
        "/v1/assessments",
        response_model=list[AssessmentListItem],
        tags=["assessment"],
    )
    async def list_assessments(
        limit: int = Query(default=20, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
        domain: str | None = Query(default=None, max_length=253),
        level: str | None = Query(
            default=None, pattern="^(low|medium|high|critical|unknown)$"
        ),
    ) -> list[AssessmentListItem]:
        rows = storage.list_assessments(
            limit=limit,
            offset=offset,
            domain=domain.lower().strip() if domain else None,
            level=level,
        )
        return [AssessmentListItem(**row) for row in rows]

    @application.get(
        "/v1/assessments/{assessment_id}",
        response_model=Assessment,
        tags=["assessment"],
    )
    async def get_assessment(assessment_id: str, response: Response) -> Assessment:
        assessment = storage.get_assessment(assessment_id)
        if assessment is None:
            raise HTTPException(status_code=404, detail="Assessment not found")
        response.headers["Cache-Control"] = "no-store"
        return assessment

    @application.get("/v1/stats", response_model=StatsResponse, tags=["system"])
    async def stats() -> StatsResponse:
        return StatsResponse(**storage.stats())

    @application.post("/v1/feedback", tags=["feedback"])
    async def feedback(payload: FeedbackRequest) -> dict[str, Any]:
        if storage.get_assessment(payload.assessment_id) is None:
            raise HTTPException(status_code=404, detail="Assessment not found")
        feedback_id = storage.add_feedback(
            payload.assessment_id,
            payload.verdict,
            payload.suggested_label,
            payload.note,
        )
        return {"ok": True, "id": feedback_id}

    @application.post(
        "/v1/guard",
        response_model=GuardResponse,
        tags=["guard"],
        dependencies=[Depends(_rate_limit)],
    )
    async def guard(
        payload: GuardRequest,
        assessor: Assessor = Depends(_assessor),
    ) -> GuardResponse:
        result = await assessor.assess(
            payload.url,
            payload.requested_action,
            force_refresh=payload.force_refresh,
        )
        verdict, reasons = guard_decision(result)
        return GuardResponse(
            url=result.url,
            domain=result.domain,
            verdict=verdict,
            overall_risk=result.overall_risk,
            overall_level=result.overall_level,
            confidence=result.confidence,
            headline=result.headline,
            reasons=reasons,
            assessment_id=result.id,
            assessed_at=result.created_at,
            cached=result.cached,
        )

    @application.get("/dashboard", include_in_schema=False)
    async def dashboard() -> FileResponse:
        index = config.web_dir / "index.html"
        if not index.exists():
            raise HTTPException(status_code=503, detail="Dashboard assets are not installed")
        return FileResponse(
            index,
            media_type="text/html",
            headers={"Cache-Control": "no-cache"},
        )

    application.mount(
        "/static",
        StaticFiles(directory=config.web_dir / "static", check_dir=False),
        name="static",
    )
    application.mount(
        "/screenshots",
        StaticFiles(directory=config.screenshots_dir, check_dir=False),
        name="screenshots",
    )
    return application


app = create_app()
