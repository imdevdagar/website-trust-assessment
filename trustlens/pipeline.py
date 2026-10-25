"""Assessment pipeline: crawl, enrich, extract evidence, score, explain, persist."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from . import ENGINE_VERSION, storage
from .config import Settings, settings
from .crawler import CrawlData, crawl
from .evidence import ASYNC_EXTRACTORS, SYNC_EXTRACTORS, domain_intel
from .evidence.base import ScanContext
from .schemas import Action, Assessment, Evidence, RiskLevel
from .scoring import aggregate, compose, load_calibrator
from .scoring.calibration import Calibrator
from .security import (
    URLParts,
    UnsafeURLError,
    check_url_structure,
    normalize_url,
)


class Assessor:
    """Owns configuration, concurrency limits, and optional calibration."""

    def __init__(
        self,
        cfg: Settings | None = None,
        *,
        calibrator: Calibrator | None = None,
    ) -> None:
        self.cfg = cfg or settings()
        self.cfg.ensure_dirs()
        storage.configure(self.cfg)
        storage.init_db()
        self.calibrator = calibrator if calibrator is not None else load_calibrator(self.cfg.models_dir)
        self._semaphore = asyncio.Semaphore(max(1, self.cfg.assessment_concurrency))

    async def assess(
        self,
        url: str,
        action: Action = Action.BROWSE,
        *,
        force_refresh: bool = False,
    ) -> Assessment:
        normalized = normalize_url(url)
        parts = check_url_structure(normalized)

        if not force_refresh and self.cfg.cache_ttl_seconds > 0:
            cached = storage.get_cached_assessment(
                normalized, action.value, self.cfg.cache_ttl_seconds
            )
            if cached is not None:
                return cached

        async with self._semaphore:
            try:
                return await asyncio.wait_for(
                    self._assess_uncached(url, normalized, parts, action),
                    timeout=self.cfg.assess_timeout_seconds,
                )
            except TimeoutError:
                return self._timeout_assessment(
                    url, normalized, parts.registrable_domain, action
                )

    async def _assess_uncached(
        self, url: str, normalized: str, parts: URLParts, action: Action
    ) -> Assessment:
        started = time.monotonic()
        page = await crawl(normalized, self.cfg)
        if page.error and page.error.startswith("unsafe_url:"):
            raise UnsafeURLError(page.error.split(":", 1)[1].strip() or "Unsafe URL")

        ctx = ScanContext(url=normalized, parts=parts, page=page, settings=self.cfg)
        evidence: list[Evidence] = []

        for name, extractor in SYNC_EXTRACTORS:
            try:
                evidence.extend(extractor(ctx))
            except Exception as exc:
                ctx.errors[name] = f"{type(exc).__name__}: {str(exc)[:200]}"

        async def enrich_safe() -> list[Evidence]:
            try:
                return await domain_intel.enrich(ctx)
            except Exception as exc:
                ctx.errors["domain_intel"] = f"{type(exc).__name__}: {str(exc)[:200]}"
                return []

        async def extract_safe(name: str, extractor) -> list[Evidence]:
            try:
                return await extractor(ctx)
            except Exception as exc:
                ctx.errors[name] = f"{type(exc).__name__}: {str(exc)[:200]}"
                return []

        parallel = [
            extract_safe(name, extractor)
            for name, extractor in ASYNC_EXTRACTORS
            if name != "infrastructure"
        ]
        results = await asyncio.gather(enrich_safe(), *parallel)
        for items in results:
            evidence.extend(items)

        for name, extractor in ASYNC_EXTRACTORS:
            if name != "infrastructure":
                continue
            try:
                evidence.extend(await extractor(ctx))
            except Exception as exc:
                ctx.errors[name] = f"{type(exc).__name__}: {str(exc)[:200]}"

        if not ctx.page_available:
            ctx.add_missing(
                "Page content could not be collected, so page-based evidence is unavailable"
            )

        result = aggregate(
            evidence,
            ctx.sources,
            action,
            calibrator=self.calibrator,
        )
        explanation = compose(
            result,
            action=action,
            final_domain=ctx.final_domain,
            missing_evidence=ctx.missing_evidence,
        )
        duration_ms = int((time.monotonic() - started) * 1000)
        notes = _json_safe(ctx.notes)
        meta: dict[str, Any] = {
            "engine_version": ENGINE_VERSION,
            "duration_ms": duration_ms,
            "requested_url": normalized,
            "final_url": ctx.final_url,
            "redirected": ctx.final_url != normalized,
            "crawl_engine": page.engine,
            "http_status": page.status,
            "blocked_requests": len(page.blocked_requests),
            "page_fingerprint": page.page_fingerprint(),
            "sources": ctx.sources,
            "notes": notes,
            "floors": result.floors,
            "action_weights": result.action_weights,
            "errors": {**ctx.errors, **({"page": page.error} if page.error else {})},
            "page_errors": list(dict.fromkeys(page.errors))[:20],
            "calibration": self.calibrator.method if self.calibrator else None,
        }
        if page.screenshot:
            meta["screenshot_file"] = page.screenshot

        assessment = Assessment(
            url=url,
            normalized_url=normalized,
            final_url=ctx.final_url,
            domain=ctx.final_domain,
            action=action,
            overall_risk=result.overall_risk,
            overall_level=result.overall_level,
            confidence=result.confidence,
            calibrated_probability=result.calibrated_probability,
            recommendation=explanation.recommendation,
            headline=explanation.headline,
            rationale=explanation.rationale,
            dimensions=result.dimensions,
            evidence=result.evidence,
            missing_evidence=ctx.missing_evidence,
            coverage=result.coverage,
            meta=meta,
            screenshot_url=f"/screenshots/{page.screenshot}" if page.screenshot else None,
        )
        try:
            storage.save_assessment(assessment)
        except Exception as exc:
            assessment.meta["persistence_error"] = f"{type(exc).__name__}: {str(exc)[:160]}"
        return assessment

    def _timeout_assessment(self, url: str, normalized: str, domain: str, action: Action) -> Assessment:
        result = aggregate([], {}, action, calibrator=self.calibrator)
        explanation = compose(
            result,
            action=action,
            final_domain=domain,
            missing_evidence=["The assessment did not finish within the configured time limit"],
        )
        assessment = Assessment(
            url=url,
            normalized_url=normalized,
            final_url=normalized,
            domain=domain,
            action=action,
            overall_risk=result.overall_risk,
            overall_level=result.overall_level,
            confidence=result.confidence,
            recommendation=explanation.recommendation,
            headline=explanation.headline,
            rationale=explanation.rationale,
            dimensions=result.dimensions,
            evidence=[],
            missing_evidence=["The assessment did not finish within the configured time limit"],
            coverage=result.coverage,
            meta={
                "engine_version": ENGINE_VERSION,
                "duration_ms": int(self.cfg.assess_timeout_seconds * 1000),
                "requested_url": normalized,
                "final_url": normalized,
                "errors": {"page": "assessment_timeout"},
                "floors": [],
            },
        )
        try:
            storage.save_assessment(assessment)
        except Exception:
            pass
        return assessment


def assess_captured_page(
    page: CrawlData,
    *,
    url: str,
    action: Action = Action.BROWSE,
    cfg: Settings | None = None,
    calibrator: Calibrator | None = None,
    drop_evidence_codes: frozenset[str] = frozenset(),
) -> Assessment:
    """Score a page that was already captured, using only page-derived evidence.

    No network enrichment runs, so absolute scores are not interchangeable with live
    assessments. This is the path the controlled isolation study uses: two variants of
    one page must differ only in the page bytes given to the parser.
    """
    cfg = cfg or settings()
    normalized = normalize_url(url)
    parts = check_url_structure(normalized)
    started = time.monotonic()
    ctx = ScanContext(url=normalized, parts=parts, page=page, settings=cfg)

    evidence: list[Evidence] = []
    for name, extractor in SYNC_EXTRACTORS:
        try:
            items = extractor(ctx)
        except Exception as exc:
            ctx.errors[name] = f"{type(exc).__name__}: {str(exc)[:200]}"
            continue
        evidence.extend(
            item for item in items if item.code not in drop_evidence_codes
        )

    if not ctx.page_available:
        ctx.add_missing(
            "Page content could not be collected, so page-based evidence is unavailable"
        )

    result = aggregate(evidence, ctx.sources, action, calibrator=calibrator)
    explanation = compose(
        result,
        action=action,
        final_domain=ctx.final_domain,
        missing_evidence=ctx.missing_evidence,
    )
    meta: dict[str, Any] = {
        "engine_version": ENGINE_VERSION,
        "duration_ms": int((time.monotonic() - started) * 1000),
        "requested_url": normalized,
        "final_url": ctx.final_url,
        "crawl_engine": page.engine,
        "http_status": page.status,
        "page_fingerprint": page.page_fingerprint(),
        "sources": ctx.sources,
        "notes": _json_safe(ctx.notes),
        "floors": result.floors,
        "action_weights": result.action_weights,
        "errors": {**ctx.errors, **({"page": page.error} if page.error else {})},
        "scoring_path": "captured_page",
        "dropped_evidence_codes": sorted(drop_evidence_codes),
    }
    return Assessment(
        url=url,
        normalized_url=normalized,
        final_url=ctx.final_url,
        domain=ctx.final_domain,
        action=action,
        overall_risk=result.overall_risk,
        overall_level=result.overall_level,
        confidence=result.confidence,
        calibrated_probability=result.calibrated_probability,
        recommendation=explanation.recommendation,
        headline=explanation.headline,
        rationale=explanation.rationale,
        dimensions=result.dimensions,
        evidence=result.evidence,
        missing_evidence=ctx.missing_evidence,
        coverage=result.coverage,
        meta=meta,
    )


def guard_decision(assessment: Assessment) -> tuple[str, list[str]]:
    """Map an assessment to allow/warn/block without hiding uncertainty."""
    level = assessment.overall_level
    if level is RiskLevel.CRITICAL:
        verdict = "block"
    elif level is RiskLevel.HIGH:
        verdict = "block" if assessment.confidence >= 0.6 else "warn"
    elif level in {RiskLevel.MEDIUM, RiskLevel.UNKNOWN}:
        verdict = "warn"
    else:
        verdict = "allow"

    if verdict == "allow":
        strengths = sorted(
            (item for item in assessment.evidence if item.trust_points > 0),
            key=lambda item: item.trust_points * item.confidence,
            reverse=True,
        )
        reasons = [item.title for item in strengths[:3]]
        if not reasons:
            reasons = [assessment.headline]
        return verdict, list(dict.fromkeys(reasons))[:4]

    risks = sorted(
        (item for item in assessment.evidence if item.risk_points > 0),
        key=lambda item: item.risk_points * item.confidence,
        reverse=True,
    )
    reasons = [item.title for item in risks[:3]]
    if level is RiskLevel.UNKNOWN:
        reasons.insert(0, "There is not enough reliable evidence to clear this site")
    if not reasons:
        reasons = [assessment.headline]
    floors = assessment.meta.get("floors") or []
    if any(str(floor).startswith("known_") for floor in floors):
        reasons.append("A locally imported reputation label was applied")
    return verdict, list(dict.fromkeys(reasons))[:4]


def _json_safe(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, default=str))
    except (TypeError, ValueError):
        return {}
