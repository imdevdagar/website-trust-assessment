"""
api/main.py
FastAPI backend for the Website Trust Assessment System.

Endpoints:
  GET  /health            — Health check
  POST /predict/url       — Predict from raw URL string
  POST /predict/features  — Predict from feature dict
  POST /explain           — Predict + SHAP explanation
  GET  /model/info        — Model metadata
  GET  /model/features    — Feature list
"""
import sys, json, logging
from pathlib import Path
from typing import Dict, Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from api.schemas import (
    URLPredictRequest, FeaturePredictRequest, ExplainRequest,
    PredictionResponse, HealthResponse, ModelInfoResponse,
    ComprehensiveAssessmentResponse,
)
from src.features.url_features import extract_url_features
from src.features.domain_features import extract_domain_features
from src.scoring.risk_scorer import compute_risk_score
from src.explainability.shap_explainer import generate_counterfactual_explanation
from src.models.predict import predict_single
from src.models.train import load_model
import pandas as pd
import numpy as np

logger = logging.getLogger("api")
logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="Website Trust Assessment API",
    description="Multi-layer AI trust assessment, consensus safety engine, and counterfactual XAI.",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Model state ────────────────────────────────────────────────────────────
_state: Dict[str, Any] = {
    "model":                None,
    "model_name":           "XGBoost Multi-Class",
    "features":             [],
    "label_map":            {0: "Legitimate", 1: "Phishing", 2: "Scam"},
    "threshold":            0.70,
    "scam_model":           None,
    "scam_labels":          [],
    "top_legit_domains":    set(),
    "class_thresholds":     {},
}


def _load_model_on_startup():
    """Load multiclass models, subcategory classifier, and Tranco baseline."""
    models_dir = PROJECT_ROOT / "models"
    mc_path = models_dir / "XGBoost_multiclass.pkl"
    mc_feats_path = models_dir / "multiclass_features.json"
    mc_thresh_path = models_dir / "multiclass_thresholds.json"

    if mc_path.exists() and mc_feats_path.exists():
        try:
            _state["model"] = load_model(str(mc_path))
            _state["features"] = json.loads(mc_feats_path.read_text(encoding="utf-8"))
            if mc_thresh_path.exists():
                _state["class_thresholds"] = json.loads(mc_thresh_path.read_text(encoding="utf-8"))
            logger.info("Loaded XGBoost Multi-Class model.")
        except Exception as e:
            logger.warning(f"Failed to load multiclass model: {e}")

    sub_model_path = models_dir / "scam_subcategory_model.pkl"
    sub_labels_path = models_dir / "scam_subcategory_labels.json"
    if sub_model_path.exists() and sub_labels_path.exists():
        try:
            _state["scam_model"] = load_model(str(sub_model_path))
            _state["scam_labels"] = json.loads(sub_labels_path.read_text(encoding="utf-8"))
            logger.info("Loaded Scam Subcategory model.")
        except Exception as e:
            logger.warning(f"Failed to load subcategory model: {e}")

    tranco_csv = PROJECT_ROOT / "data" / "processed" / "tranco_top50k_clean.csv"
    if not tranco_csv.exists():
        tranco_csv = PROJECT_ROOT / "data" / "raw" / "tranco_top1m.csv"
    if tranco_csv.exists():
        try:
            tdf = pd.read_csv(tranco_csv, nrows=100000)
            col = "domain" if "domain" in tdf.columns else tdf.columns[1]
            _state["top_legit_domains"] = set(tdf[col].astype(str).str.lower().str.strip())
            logger.info(f"Loaded {len(_state['top_legit_domains'])} authoritative Tranco domains.")
        except Exception as e:
            logger.warning(f"Failed to load Tranco list: {e}")



@app.on_event("startup")
async def startup_event():
    _load_model_on_startup()


@app.get("/health", response_model=HealthResponse, tags=["System"])
def health():
    return HealthResponse(
        status="ok" if _state["model"] is not None else "no_model",
        model_loaded=_state["model"] is not None,
        model_name=_state["model_name"],
        num_features=len(_state["features"]),
    )


@app.get("/model/info", response_model=ModelInfoResponse, tags=["Model"])
def model_info():
    if _state["model"] is None:
        raise HTTPException(status_code=503, detail="Model not loaded. Run run_pipeline.py first.")
    return ModelInfoResponse(
        model_name=_state["model_name"],
        model_type=type(_state["model"]).__name__,
        num_features=len(_state["features"]),
        features=_state["features"],
        label_map={str(k): v for k, v in _state["label_map"].items()},
        confidence_threshold=_state["threshold"],
        calibrated=_state["calibrated"],
    )


@app.get("/model/features", tags=["Model"])
def model_features():
    return {"features": _state["features"], "count": len(_state["features"])}


@app.post("/predict/url", response_model=PredictionResponse, tags=["Prediction"])
def predict_url(request: URLPredictRequest):
    if _state["model"] is None:
        raise HTTPException(status_code=503, detail="Model not loaded. Run run_pipeline.py first.")

    url = request.url.strip()
    if not url:
        raise HTTPException(status_code=422, detail="URL cannot be empty.")

    # Extract features
    features = extract_url_features(url)
    if not features:
        raise HTTPException(status_code=422, detail="Could not extract features from URL.")

    threshold    = request.threshold if request.threshold is not None else _state["threshold"]
    feature_cols = _state["features"]
    label_map    = _state["label_map"]

    # Check feature compatibility
    live_features = set(features.keys())
    model_features = set(feature_cols)
    missing = model_features - live_features
    if missing:
        return PredictionResponse(
            prediction="INCOMPATIBLE",
            confidence=0.0,
            needs_review=True,
            probabilities={},
            threshold_used=threshold,
            mode="live_url",
            explanation=(
                f"Live URL mode is missing {len(missing)} features required by the model. "
                f"Missing: {sorted(missing)[:5]}... "
                "The model was trained on dataset features including HTML/page features "
                "not extractable from URL alone. Use /predict/features with full feature dict."
            )
        )

    result = predict_single(
        _state["model"], features, feature_cols,
        threshold=threshold, label_map=label_map,
    )

    probs = {k: v for k, v in result.items() if k.startswith("prob_")}
    prob_clean = {k.replace("prob_", ""): v for k, v in probs.items()}

    return PredictionResponse(
        prediction=result["prediction"],
        confidence=result["confidence"],
        needs_review=result["needs_review"],
        probabilities=prob_clean,
        threshold_used=threshold,
        mode="live_url",
    )


@app.post("/predict/features", response_model=PredictionResponse, tags=["Prediction"])
def predict_features(request: FeaturePredictRequest):
    if _state["model"] is None:
        raise HTTPException(status_code=503, detail="Model not loaded. Run run_pipeline.py first.")

    threshold    = request.threshold if request.threshold is not None else _state["threshold"]
    feature_cols = _state["features"]
    label_map    = _state["label_map"]

    result = predict_single(
        _state["model"], request.features, feature_cols,
        threshold=threshold, label_map=label_map,
    )

    probs = {k: v for k, v in result.items() if k.startswith("prob_")}
    prob_clean = {k.replace("prob_", ""): v for k, v in probs.items()}

    return PredictionResponse(
        prediction=result["prediction"],
        confidence=result["confidence"],
        needs_review=result["needs_review"],
        probabilities=prob_clean,
        threshold_used=threshold,
        mode="features",
    )


@app.post("/explain", tags=["Explainability"])
def explain(request: ExplainRequest):
    if _state["model"] is None:
        raise HTTPException(status_code=503, detail="Model not loaded.")

    url      = request.url.strip()
    features = extract_url_features(url)
    threshold    = request.threshold if request.threshold is not None else _state["threshold"]
    feature_cols = _state["features"]
    label_map    = _state["label_map"]

    result = predict_single(
        _state["model"], features, feature_cols,
        threshold=threshold, label_map=label_map,
    )

    probs = {k.replace("prob_", ""): v for k, v in result.items() if k.startswith("prob_")}

    available_features = {c: features.get(c, 0) for c in feature_cols}

    return {
        "url":         url,
        "prediction":  result["prediction"],
        "confidence":  result["confidence"],
        "needs_review": result["needs_review"],
        "probabilities": probs,
        "features_used": available_features,
        "explanation_note": (
            "SHAP explanations require the full pipeline to be loaded with training data. "
            "Run scripts/run_pipeline.py to generate full SHAP outputs in results/shap/."
        ),
    }


@app.post("/api/v1/assess", response_model=ComprehensiveAssessmentResponse, tags=["Assessment"])
def assess_website(request: URLPredictRequest):
    """
    Comprehensive Assessment Endpoint:
    Combines Multiclass ML, Subcategory Taxonomy, Objective Domain Forensics,
    and Consensus Safety Net Arbitration into a production-grade response.
    """
    if _state["model"] is None:
        raise HTTPException(status_code=503, detail="Primary model not initialized.")

    url_clean = request.url.strip()
    if not url_clean:
        raise HTTPException(status_code=422, detail="URL cannot be empty.")

    # 1. Feature Extraction
    features = extract_url_features(url_clean)
    domain_feats = extract_domain_features(url_clean)
    features.update(domain_feats)
    
    age_days = domain_feats.get("DomainAgeDays", -1)
    if age_days < 0:
        features["DomainAgeProxy"] = 1
    elif age_days < 90:
        features["DomainAgeProxy"] = 0
    elif age_days < 365:
        features["DomainAgeProxy"] = 1
    else:
        features["DomainAgeProxy"] = 2

    active_features = _state["features"]
    active_pipeline = _state["model"]

    # 2. Raw ML Probabilities
    feat_df = pd.DataFrame([{k: features.get(k, 0) for k in active_features}])
    proba = active_pipeline.predict_proba(feat_df)[0].copy()

    # 3. Ground-Truth Calibration (Tranco & Age)
    from urllib.parse import urlparse as _urlparse
    _host = _urlparse(url_clean if url_clean.startswith("http") else "http://" + url_clean).netloc.split(":")[0].replace("www.", "").lower()
    
    # Extract apex root domain (e.g. mail.google.com -> google.com, amazon.co.uk -> amazon.co.uk)
    _host_parts = _host.split(".")
    if len(_host_parts) >= 3 and _host_parts[-2] in ("co", "com", "org", "net", "gov", "edu"):
        _root_domain = ".".join(_host_parts[-3:])
    elif len(_host_parts) >= 2:
        _root_domain = ".".join(_host_parts[-2:])
    else:
        _root_domain = _host

    is_tranco = (_host in _state["top_legit_domains"]) or (_root_domain in _state["top_legit_domains"])
    is_old = age_days > 730
    no_attacks = (
        features.get("HasBrandImpersonation", 0) == 0 and
        features.get("HasTyposquatting", 0) == 0 and
        features.get("HasHomographChar", 0) == 0 and
        features.get("HasSuspiciousTLD", 0) == 0 and
        features.get("IsDomainIP", 0) == 0
    )
    if (is_tranco or is_old) and no_attacks:
        proba = np.array([0.985, 0.010, 0.005])

    # 4. Multi-class Decision & Active Attack Override
    # A. Direct Phishing Overrides: IP addresses, brand impersonation, typosquatting
    if features.get("IsDomainIP", 0) or features.get("HasBrandImpersonation", 0) or features.get("HasTyposquatting", 0) or features.get("HasHomographChar", 0):
        if proba[2] >= 0.40:
            pred_idx = 2
        else:
            pred_idx = 1
        proba = np.array([0.02, 0.78, 0.20]) if pred_idx == 1 else np.array([0.02, 0.20, 0.78])
    # B. High-Risk Scam Overrides: Suspicious abuse TLD combined with predatory lures (crypto, invest, fast loan, outlet)
    elif features.get("HasSuspiciousTLD", 0) and (features.get("HasInvestKeyword", 0) or features.get("HasCryptoKeyword", 0) or features.get("HasShopKeyword", 0) or features.get("HasPhishKeyword", 0)):
        pred_idx = 2
        proba = np.array([0.03, 0.15, 0.82])
    else:
        scam_thresh = _state["class_thresholds"].get("Scam", 0.48)
        if proba[2] >= scam_thresh:
            pred_idx = 2
        else:
            pred_idx = int(proba[:2].argmax())

    label_map = {0: "Legitimate", 1: "Phishing", 2: "Scam"}
    pred_label = label_map[pred_idx]
    confidence = float(proba[pred_idx])
    needs_review = confidence < request.threshold

    # 5. Scam Sub-Category
    scam_subtype = None
    sub_conf = None
    if pred_label == "Scam" and _state["scam_model"] is not None:
        try:
            sub_p = _state["scam_model"].predict_proba(feat_df)[0]
            sub_i = int(sub_p.argmax())
            sub_conf = float(sub_p[sub_i])
            raw_sub = _state["scam_labels"][sub_i]
            scam_subtype = raw_sub.item() if hasattr(raw_sub, "item") else str(raw_sub)
        except Exception:
            pass

    # 6. Consensus & Safety Net Scoring
    risk_res = compute_risk_score(
        url=url_clean,
        url_features=features,
        domain_features=domain_feats,
        model_proba=list(proba)
    )

    # 7. Actionable Counterfactuals
    recs = []
    if pred_label in ("Phishing", "Scam"):
        try:
            cf = generate_counterfactual_explanation(active_pipeline, features, active_features, max_changes=3)
            recs = [r["description"] for r in cf.get("recommendations", [])]
        except Exception:
            pass

    return ComprehensiveAssessmentResponse(
        url=url_clean,
        prediction=pred_label,
        confidence=round(confidence, 4),
        needs_review=needs_review,
        probabilities={label_map[i]: round(float(proba[i]), 4) for i in range(len(proba))},
        scam_subtype=scam_subtype,
        scam_subtype_confidence=round(sub_conf, 4) if sub_conf else None,
        trust_score=risk_res.trust_score,
        risk_label=risk_res.risk_label,
        consensus_status=risk_res.consensus_status,
        divergence_index=risk_res.divergence_index,
        safety_net_triggered=risk_res.safety_net_triggered,
        flags=risk_res.flags,
        counterfactual_actions=recs,
    )

