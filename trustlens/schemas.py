"""Typed data contracts shared by the API, pipeline, scripts, and tests."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Dimension(str, Enum):
    SECURITY = "security"
    IDENTITY = "identity"
    PRIVACY = "privacy"
    MANIPULATION = "manipulation"


DIMENSION_LABELS: dict[Dimension, str] = {
    Dimension.SECURITY: "Security & Fraud",
    Dimension.IDENTITY: "Identity & Legitimacy",
    Dimension.PRIVACY: "Privacy & Data",
    Dimension.MANIPULATION: "Manipulation & Deception",
}


class RiskLevel(str, Enum):
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(str, Enum):
    BROWSE = "browse"
    SIGNUP = "signup"
    PURCHASE = "purchase"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Evidence(BaseModel):
    """A single auditable observation.

    risk_points/trust_points are contributions *within* a dimension, already
    normalised so that a full set of severe observations approaches 100.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: f"ev_{uuid4().hex[:12]}")
    dimension: Dimension
    code: str
    title: str
    detail: str
    severity: Severity
    risk_points: float = Field(default=0.0, ge=0.0, le=60.0)
    trust_points: float = Field(default=0.0, ge=0.0, le=30.0)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    source: str
    observed_at: datetime = Field(default_factory=utc_now)
    provenance: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)

    @field_validator("title", "detail")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("must not be empty")
        return value


class DimensionAssessment(BaseModel):
    dimension: Dimension
    label: str
    risk_score: float = Field(ge=0.0, le=100.0)
    risk_level: RiskLevel
    confidence: float = Field(ge=0.0, le=1.0)
    coverage: float = Field(default=0.0, ge=0.0, le=1.0)
    applicable: bool = True
    abstained: bool = False
    summary: str
    evidence_ids: list[str] = Field(default_factory=list)
    calibrated_probability: float | None = Field(default=None, ge=0.0, le=1.0)


class Assessment(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    url: str
    normalized_url: str
    final_url: str
    domain: str
    action: Action = Action.BROWSE
    overall_risk: float = Field(ge=0.0, le=100.0)
    overall_level: RiskLevel
    confidence: float = Field(ge=0.0, le=1.0)
    calibrated_probability: float | None = None
    recommendation: str
    headline: str
    rationale: str
    dimensions: dict[str, DimensionAssessment]
    evidence: list[Evidence]
    missing_evidence: list[str] = Field(default_factory=list)
    coverage: dict[str, float] = Field(default_factory=dict)
    meta: dict[str, Any] = Field(default_factory=dict)
    screenshot_url: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    cached: bool = False

    def summary_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "url": self.url,
            "domain": self.domain,
            "action": self.action.value,
            "overall_risk": self.overall_risk,
            "overall_level": self.overall_level.value,
            "confidence": self.confidence,
            "headline": self.headline,
            "recommendation": self.recommendation,
            "created_at": self.created_at.isoformat(),
            "screenshot_url": self.screenshot_url,
        }


class AssessmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=4, max_length=2048)
    action: Action = Action.BROWSE
    force_refresh: bool = False


class FeedbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assessment_id: str = Field(min_length=4, max_length=64)
    verdict: Literal["agree", "disagree", "unsure"]
    suggested_label: Literal["benign", "suspicious", "malicious"] | None = None
    note: str = Field(default="", max_length=1000)


class GuardRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=4, max_length=2048)
    requested_action: Action = Action.BROWSE
    force_refresh: bool = False


class GuardResponse(BaseModel):
    url: str
    domain: str
    verdict: Literal["allow", "warn", "block"]
    overall_risk: float
    overall_level: RiskLevel
    confidence: float
    headline: str
    reasons: list[str]
    assessment_id: str
    assessed_at: datetime = Field(default_factory=utc_now)
    cached: bool = False
    disclaimer: str = (
        "Automated risk signals are advisory. They can be wrong and do not guarantee "
        "that a site is safe or malicious."
    )


class SubmissionResponse(BaseModel):
    id: str
    url: str
    final_url: str = ""
    domain: str
    action: Action = Action.BROWSE
    created_at: datetime = Field(default_factory=utc_now)
    overall_risk: float
    overall_level: RiskLevel
    confidence: float
    calibrated_probability: float | None = None
    recommendation: str
    headline: str
    rationale: str = ""
    evidence: list[Evidence]
    dimensions: dict[str, DimensionAssessment]
    missing_evidence: list[str]
    coverage: dict[str, float] = Field(default_factory=dict)
    meta: dict[str, Any]
    screenshot_url: str | None = None
    cached: bool = False
    disclaimer: str = (
        "Automated risk signals are advisory. They can be wrong and do not guarantee "
        "that a site is safe or malicious."
    )

    @classmethod
    def from_assessment(cls, assessment: Assessment) -> "SubmissionResponse":
        return cls(
            id=assessment.id,
            url=assessment.url,
            final_url=assessment.final_url,
            domain=assessment.domain,
            action=assessment.action,
            created_at=assessment.created_at,
            overall_risk=assessment.overall_risk,
            overall_level=assessment.overall_level,
            confidence=assessment.confidence,
            calibrated_probability=assessment.calibrated_probability,
            recommendation=assessment.recommendation,
            headline=assessment.headline,
            rationale=assessment.rationale,
            evidence=assessment.evidence,
            dimensions=assessment.dimensions,
            missing_evidence=assessment.missing_evidence,
            coverage=assessment.coverage,
            meta=assessment.meta,
            screenshot_url=assessment.screenshot_url,
            cached=assessment.cached,
        )


class AssessmentListItem(BaseModel):
    id: str
    url: str
    domain: str
    action: str
    overall_risk: float
    overall_level: str
    confidence: float
    headline: str
    created_at: datetime
    screenshot_url: str | None = None


class StatsResponse(BaseModel):
    total_assessments: int
    assessments_24h: int
    by_level: dict[str, int]
    average_risk: float | None
    average_duration_ms: float | None
    feedback_count: int
    labeled_domains: int
    malicious_domains: int
    top_domains: list[dict[str, Any]]
