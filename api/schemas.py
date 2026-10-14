from pydantic import BaseModel, HttpUrl, validator
from typing import Optional, Dict, Any


class URLPredictRequest(BaseModel):
    url: str
    threshold: Optional[float] = 0.70

    @validator("threshold")
    def threshold_range(cls, v):
        if not 0.0 <= v <= 1.0:
            raise ValueError("threshold must be between 0.0 and 1.0")
        return v


class FeaturePredictRequest(BaseModel):
    features: Dict[str, float]
    threshold: Optional[float] = 0.70


class ExplainRequest(BaseModel):
    url: str
    threshold: Optional[float] = 0.70


class PredictionResponse(BaseModel):
    prediction: str
    confidence: float
    needs_review: bool
    probabilities: Dict[str, float]
    threshold_used: float
    mode: str = "live_url"
    explanation: Optional[Any] = None


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    model_name: str
    num_features: int


class ModelInfoResponse(BaseModel):
    model_name: str
    model_type: str
    num_features: int
    features: list
    label_map: Dict[str, str]
    confidence_threshold: float
    calibrated: bool


class ComprehensiveAssessmentResponse(BaseModel):
    url: str
    prediction: str
    confidence: float
    needs_review: bool
    probabilities: Dict[str, float]
    scam_subtype: Optional[str] = None
    scam_subtype_confidence: Optional[float] = None
    trust_score: int
    risk_label: str
    consensus_status: str
    divergence_index: float
    safety_net_triggered: bool
    flags: list
    counterfactual_actions: list = []

