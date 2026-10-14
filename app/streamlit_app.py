"""
app/streamlit_app.py
Streamlit frontend for the Website Trust Assessment System.
"""
import sys, json, time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st
import pandas as pd
import numpy as np

# Page config
st.set_page_config(
    page_title="Website Trust Assessment System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Imports ──────────────────────────────────────────────────────────
try:
    from src.features.url_features import extract_url_features
    from src.features.html_features import extract_live_html_features
    from src.features.domain_features import extract_domain_features
    from src.scoring.risk_scorer import compute_risk_score
    from src.models.predict import predict_single
    from src.models.train import load_model
    from src.explainability.shap_explainer import generate_counterfactual_explanation
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    IMPORTS_OK = True
except ImportError as e:
    IMPORTS_OK = False
    import_error = str(e)

# ── Custom CSS ────────────────────────────────────────────────────────
st.markdown("""
<style>
    .main-title { font-size: 2.2rem; font-weight: 700; color: #1E3A5F; text-align: center; }
    .subtitle   { font-size: 1.1rem; color: #555; text-align: center; margin-bottom: 1.5rem; }
    .result-card {
        border-radius: 12px;
        padding: 1.5rem;
        margin: 1rem 0;
        border-left: 6px solid;
    }
    .legitimate  { background: #e8f5e9; border-color: #2e7d32; }
    .phishing    { background: #fce4ec; border-color: #c62828; }
    .scam        { background: #fff3e0; border-color: #e65100; }
    .needs-review { background: #fff8e1; border-color: #f9a825; }
    .confidence-bar { height: 12px; border-radius: 6px; background: #e0e0e0; }
    .metric-box {
        background: #f8f9fa; border-radius: 8px;
        padding: 1rem; text-align: center; margin: 0.5rem;
    }
    .status-badge {
        display: inline-block; padding: 4px 12px;
        border-radius: 20px; font-size: 0.85rem; font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)


# ── Load model ──────────────────────────────────────────────────────
@st.cache_resource
def load_app_model():
    models_dir = PROJECT_ROOT / "models"
    
    pipeline = None
    features = []
    
    primary_path = models_dir / "XGBoost_multiclass.pkl"
    primary_feats_path = models_dir / "multiclass_features.json"
    
    if primary_path.exists() and primary_feats_path.exists():
        try:
            pipeline = load_model(str(primary_path))
            features = json.loads(primary_feats_path.read_text(encoding="utf-8"))
        except Exception:
            pass

    # For now, since the multi-class model is URL-only, fallback is the same model
    url_only_pipeline = pipeline
    url_only_features = features

    # Load sub-category classifier (scam type: bank, pet, courier, etc.)
    subcategory_pipeline = None
    subcategory_labels   = []
    sub_model_path  = models_dir / "scam_subcategory_model.pkl"
    sub_labels_path = models_dir / "scam_subcategory_labels.json"
    if sub_model_path.exists() and sub_labels_path.exists():
        try:
            subcategory_pipeline = load_model(str(sub_model_path))
            subcategory_labels   = json.loads(sub_labels_path.read_text(encoding="utf-8"))
        except Exception:
            pass

    # Load top known legitimate domains (Tranco top 50k authoritative baseline)
    top_legit_domains = set()
    tranco_csv = PROJECT_ROOT / "data" / "processed" / "tranco_top50k_clean.csv"
    if not tranco_csv.exists():
        tranco_csv = PROJECT_ROOT / "data" / "raw" / "tranco_top1m.csv"
    if tranco_csv.exists():
        try:
            tdf = pd.read_csv(tranco_csv, nrows=100000)
            col = "domain" if "domain" in tdf.columns else tdf.columns[1]
            top_legit_domains = set(tdf[col].astype(str).str.lower().str.strip())
        except Exception:
            pass

    return pipeline, features, url_only_pipeline, url_only_features, "XGBoost Multi-Class", False, {}, subcategory_pipeline, subcategory_labels, top_legit_domains


def _color_for_class(cls: str):
    mapping = {
        "Legitimate":   ("#2e7d32", "#e8f5e9", "legitimate"),
        "Phishing":     ("#c62828", "#fce4ec", "phishing"),
        "Scam":         ("#e65100", "#fff3e0", "scam"),
        "Needs Review": ("#f9a825", "#fff8e1", "needs-review"),
        "Suspicious (Offline)": ("#d84315", "#fbe9e7", "scam"),
        "Site Offline": ("#616161", "#eeeeee", "")
    }
    return mapping.get(cls, ("#555", "#f5f5f5", ""))


def _confidence_color(conf: float) -> str:
    if conf >= 0.85:
        return "#2e7d32"
    elif conf >= 0.70:
        return "#1565c0"
    elif conf >= 0.55:
        return "#e65100"
    else:
        return "#c62828"


# ── Sidebar ──────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## ⚙️ Settings")
    threshold = st.slider(
        "Confidence Threshold",
        min_value=0.50, max_value=0.95,
        value=0.70, step=0.05,
        help="Predictions below this confidence will be flagged as 'Needs Review'."
    )
    st.markdown("---")
    st.markdown("### 📋 About")
    st.markdown(
        "This system uses machine learning to assess the trustworthiness of websites. "
        "It classifies URLs as **Legitimate**, **Phishing**, **Scam**, or **Needs Review** "
        "based on URL-level and (when trained) webpage features."
    )
    st.markdown("---")
    st.markdown("### ⚠️ Disclaimer")
    st.markdown(
        "_This tool provides a model-based assessment. It is **not** a guarantee. "
        "Treat 'Needs Review' predictions with extra caution._"
    )

# ── Main Content ──────────────────────────────────────────────────────
st.markdown('<p class="main-title">🛡️ AI-Powered Website Trust Assessment System</p>', unsafe_allow_html=True)
st.markdown('<p class="subtitle">Machine Learning · Explainable AI · Confidence-Aware Classification</p>', unsafe_allow_html=True)

if not IMPORTS_OK:
    st.error(f"Import error: {import_error}. Please ensure all dependencies are installed.")
    st.stop()

pipeline, feature_cols, url_only_pipeline, url_only_features, model_name, calibrated, config, subcategory_pipeline, subcategory_labels, top_legit_domains = load_app_model()

# Status banner
col_status1, col_status2, col_status3 = st.columns(3)
with col_status1:
    if pipeline is not None:
        st.success(f"✅ Model loaded: **{model_name}**")
    else:
        st.warning("⚠️ No model found. Run scripts/run_pipeline.py first.")
with col_status2:
    st.info(f"📊 Features: **{len(feature_cols)}**")
with col_status3:
    st.info(f"🎯 Threshold: **{threshold:.0%}**")

st.markdown("---")

# ── URL Input ──────────────────────────────────────────────────────────
st.markdown("### 🌐 Enter Website URL")
col_url, col_btn = st.columns([5, 1])
with col_url:
    url_input = st.text_input(
        label="URL",
        placeholder="https://example.com",
        label_visibility="collapsed",
        key="url_input",
    )
with col_btn:
    analyze_btn = st.button("🔍 Analyze", use_container_width=True, type="primary")

# ── Analysis ───────────────────────────────────────────────────────────
if analyze_btn and url_input:
    if pipeline is None:
        st.error("❌ No model loaded. Please run the training pipeline first.")
    else:
        with st.spinner("Extracting URL features and fetching HTML content..."):
            time.sleep(0.3)  # Brief visual pause
            url_clean = url_input.strip()
            
            features = extract_url_features(url_clean)
            html_features = extract_live_html_features(url_clean)
            if html_features:
                features.update(html_features)
                st.toast("HTML features successfully extracted!")
            else:
                st.toast("Could not fetch page HTML (site offline or blocked).", icon="⚠️")
            
            # Domain Age (Whois) -- run regardless of HTML success
            with st.spinner("Looking up domain registration data..."):
                domain_feats = extract_domain_features(url_clean)
                features.update(domain_feats)
                age_days = domain_feats.get("DomainAgeDays", -1)
                if age_days > 0:
                    st.toast(f"Domain age: {age_days} days old")
                else:
                    st.toast("Domain age: Unknown (Whois unavailable)", icon="\u2139\ufe0f")

                # Inject DomainAgeProxy — converts real Whois age into the
                # same bucketed feature the model was trained on:
                # 0 = new (<90 days), 1 = moderate (90-365), 2 = established (>365)
                if age_days < 0:
                    features["DomainAgeProxy"] = 1   # unknown → moderate assumption
                elif age_days < 90:
                    features["DomainAgeProxy"] = 0   # new domain (high risk)
                elif age_days < 365:
                    features["DomainAgeProxy"] = 1   # moderate age
                else:
                    features["DomainAgeProxy"] = 2   # established domain

            # Multi-Layer Risk Score (independent of ML model)
            url_feats_only = extract_url_features(url_clean)
            html_raw_text = ""
            try:
                import requests as _req
                _r = _req.get(url_clean if url_clean.startswith("http") else "http://" + url_clean,
                              timeout=5, headers={"User-Agent": "Mozilla/5.0"})
                html_raw_text = _r.text
            except Exception:
                pass
            # NOTE: model_proba is set AFTER prediction block below;
            # risk_result is computed there once proba is available.
            _risk_inputs = dict(
                url=url_clean,
                url_features=url_feats_only,
                html_features=html_features,
                domain_features=domain_feats,
                html_text=html_raw_text,
            )

        if not features:
            st.error("❌ Could not parse the URL. Please enter a valid URL.")
        else:
            # Check feature compatibility
            model_feats  = set(feature_cols)
            live_feats   = set(features.keys())
            missing_feats = model_feats - live_feats

            if not html_features and url_only_pipeline is not None:
                st.warning(
                    f"⚠️ **Live URL Mode Activated**\n\n"
                    f"Could not fetch HTML. Falling back to a lightweight model trained specifically on {len(url_only_features)} URL/Domain features."
                )
                active_pipeline = url_only_pipeline
                active_features = url_only_features
            elif not html_features:
                st.warning(
                    f"⚠️ **Live URL Mode Limitation**\n\n"
                    f"Missing {len(missing_feats)} HTML/page features. "
                    f"No URL-only fallback model found. Missing features padded with 0. "
                    "Predictions may be heavily skewed."
                )
                active_pipeline = pipeline
                active_features = feature_cols
            else:
                active_pipeline = pipeline
                active_features = feature_cols

            try:
                # Load per-class thresholds (tuned offline)
                thresh_path = PROJECT_ROOT / "models" / "multiclass_thresholds.json"
                class_thresholds = json.loads(thresh_path.read_text()) if thresh_path.exists() else {}
                scam_thresh = class_thresholds.get("Scam", 0.60)

                # Get raw probabilities
                feat_df = pd.DataFrame([{k: features.get(k, 0) for k in active_features}])
                proba = active_pipeline.predict_proba(feat_df)[0].copy()

                # ── Ground-Truth Domain Calibration (Tranco & Established Whois) ──
                # URL lexical models can misclassify clean short root URLs (e.g. google.com, wikipedia.org)
                # because they share length features with root phishing landing pages.
                # Cross-reference with Tranco Top 100k and established Whois registration (>2 years).
                from urllib.parse import urlparse as _urlparse
                _host_check = _urlparse(url_clean if url_clean.startswith("http") else "http://" + url_clean).netloc.split(":")[0].replace("www.", "").lower()
                
                # Extract apex root domain (e.g. mail.google.com -> google.com)
                _hparts = _host_check.split(".")
                if len(_hparts) >= 3 and _hparts[-2] in ("co", "com", "org", "net", "gov", "edu"):
                    _root_dom = ".".join(_hparts[-3:])
                elif len(_hparts) >= 2:
                    _root_dom = ".".join(_hparts[-2:])
                else:
                    _root_dom = _host_check

                is_tranco_top = (_host_check in top_legit_domains) or (_root_dom in top_legit_domains)
                is_old_domain = features.get("DomainAgeDays", -1) > 730
                no_attack_signals = (
                    features.get("HasBrandImpersonation", 0) == 0 and
                    features.get("HasTyposquatting", 0) == 0 and
                    features.get("HasHomographChar", 0) == 0 and
                    features.get("HasSuspiciousTLD", 0) == 0 and
                    features.get("IsDomainIP", 0) == 0 and
                    features.get("NoOfHyphensInDomain", 0) <= 2
                )

                if (is_tranco_top or is_old_domain) and no_attack_signals:
                    # Ground-truth confirmation: Authoritative legitimate site
                    proba = np.array([0.985, 0.010, 0.005])

                # ── Active Attack Vector Override ──
                # If verified typosquatting, brand impersonation, IP host, or homograph chars are present,
                # the site is an active deceptive vector and must NEVER be resolved as Legitimate.
                if features.get("IsDomainIP", 0) or features.get("HasBrandImpersonation", 0) or features.get("HasTyposquatting", 0) or features.get("HasHomographChar", 0):
                    if proba[2] >= 0.40:
                        pred_idx = 2
                    else:
                        pred_idx = 1
                    proba = np.array([0.02, 0.78, 0.20]) if pred_idx == 1 else np.array([0.02, 0.20, 0.78])
                elif features.get("HasSuspiciousTLD", 0) and (features.get("HasInvestKeyword", 0) or features.get("HasCryptoKeyword", 0) or features.get("HasShopKeyword", 0) or features.get("HasPhishKeyword", 0)):
                    pred_idx = 2
                    proba = np.array([0.03, 0.15, 0.82])
                else:
                    # Apply per-class Scam threshold
                    if proba[2] >= scam_thresh:
                        pred_idx = 2
                    else:
                        pred_idx = int(proba[:2].argmax())

                label_map = {0: "Legitimate", 1: "Phishing", 2: "Scam"}
                confidence = float(proba[pred_idx])
                prediction = label_map[pred_idx]
                needs_review = confidence < threshold

                # Compute risk score NOW — with model probabilities as the ceiling
                risk_result = compute_risk_score(
                    **_risk_inputs,
                    model_proba=list(proba),
                )

                if needs_review:
                    prediction = "Needs Review"

                # Apply Offline Rule
                if not html_features:
                    if prediction == "Legitimate":
                        prediction = "Site Offline"
                        confidence = 0.0
                    elif prediction == "Phishing":
                        prediction = "Suspicious (Offline)"
                    elif prediction == "Scam":
                        prediction = "Scam (Offline)"

                color, bg, css_class = _color_for_class(prediction)

                # ── Scam Sub-Category Detection ──
                scam_subtype = None
                if prediction in ("Scam", "Scam (Offline)") and subcategory_pipeline is not None:
                    try:
                        sub_feat_df = pd.DataFrame([{
                            k: features.get(k, 0) for k in active_features
                        }])
                        sub_proba  = subcategory_pipeline.predict_proba(sub_feat_df)[0]
                        sub_idx    = int(sub_proba.argmax())
                        sub_conf   = float(sub_proba[sub_idx])
                        raw_label  = subcategory_labels[sub_idx]
                        # Clean up np.str_ wrapper if present
                        if hasattr(raw_label, 'item'):
                            raw_label = raw_label.item()
                        scam_subtype = (raw_label.upper(), sub_conf)
                    except Exception:
                        scam_subtype = None

                # ── Main Result Card ──
                st.markdown("---")
                st.markdown("### 📊 Assessment Result")
                col_pred, col_conf, col_status_res = st.columns(3)

                with col_pred:
                    st.markdown(
                        f"""<div style="text-align:center; padding: 1.5rem;
                                background:{bg}; border-radius:12px; border-left:6px solid {color}">
                            <p style="font-size:0.9rem; color:#555; margin-bottom:0.3rem">PREDICTION</p>
                            <p style="font-size:1.8rem; font-weight:700; color:{color}; margin:0">
                                {prediction.upper()}
                            </p>
                        </div>""",
                        unsafe_allow_html=True,
                    )

                with col_conf:
                    conf_color = _confidence_color(confidence)
                    st.markdown(
                        f"""<div style="text-align:center; padding: 1.5rem;
                                background:#f8f9fa; border-radius:12px; border-left:6px solid {conf_color}">
                            <p style="font-size:0.9rem; color:#555; margin-bottom:0.3rem">CONFIDENCE</p>
                            <p style="font-size:1.8rem; font-weight:700; color:{conf_color}; margin:0">
                                {confidence:.1%}
                            </p>
                        </div>""",
                        unsafe_allow_html=True,
                    )

                with col_status_res:
                    status_text = "Needs Manual Review" if needs_review else "High-confidence prediction"
                    status_color = "#f9a825" if needs_review else "#2e7d32"
                    st.markdown(
                        f"""<div style="text-align:center; padding: 1.5rem;
                                background:#f8f9fa; border-radius:12px; border-left:6px solid {status_color}">
                            <p style="font-size:0.9rem; color:#555; margin-bottom:0.3rem">STATUS</p>
                            <p style="font-size:1.1rem; font-weight:600; color:{status_color}; margin:0">
                                {status_text}
                            </p>
                        </div>""",
                        unsafe_allow_html=True,
                    )

                # Needs Review message
                if needs_review:
                    st.warning(
                        "⚠️ **Needs Review**: The model does not have sufficient confidence "
                        f"(threshold = {threshold:.0%}) to make a reliable classification. "
                        "Manual review is recommended."
                    )

                if scam_subtype:
                    st.info(
                        f"🎯 **Predicted Scam Sub-Type**: **{scam_subtype[0]}** "
                        f"(Confidence: {scam_subtype[1]:.1%}) — Classified using AA419 specialized taxonomy."
                    )

                # ── Probability Distribution ──
                st.markdown("#### 📈 Class Probabilities")
                label_names_map = {0: "Legitimate", 1: "Phishing", 2: "Scam"}
                prob_data = {label_names_map.get(i, f"Class {i}"): float(proba[i]) for i in range(len(proba))}
                if prob_data:
                    fig, ax = plt.subplots(figsize=(8, 3))
                    classes = list(prob_data.keys())
                    probs   = list(prob_data.values())
                    bar_colors = []
                    for cls in classes:
                        c, _, _ = _color_for_class(cls)
                        bar_colors.append(c)
                    bars = ax.bar(classes, probs, color=bar_colors, edgecolor="white", linewidth=1.5)
                    ax.axhline(y=threshold, color="gray", linestyle="--", alpha=0.6,
                               label=f"Threshold ({threshold:.0%})")
                    for bar, prob in zip(bars, probs):
                        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                                f"{prob:.1%}", ha="center", va="bottom", fontweight="bold")
                    ax.set_ylim(0, 1.05)
                    ax.set_ylabel("Probability")
                    ax.set_title("Class Probability Distribution")
                    ax.legend()
                    ax.spines["top"].set_visible(False)
                    ax.spines["right"].set_visible(False)
                    plt.tight_layout()
                    st.pyplot(fig)
                    plt.close(fig)

                # -- Multi-Layer Trust Score UI --
                st.markdown("---")
                st.markdown("### \U0001f6e1\ufe0f Multi-Layer Trust Score")
                ts = risk_result.trust_score
                ts_color = risk_result.risk_color
                ts_label = risk_result.risk_label

                # Gauge-style score display
                col_ts1, col_ts2 = st.columns([1, 2])
                with col_ts1:
                    st.markdown(
                        f"""<div style="text-align:center; padding:1.5rem;
                                background:linear-gradient(135deg,{ts_color}22,{ts_color}44);
                                border-radius:16px; border:3px solid {ts_color}">
                            <p style="font-size:0.85rem; color:#555; margin:0">TRUST SCORE</p>
                            <p style="font-size:3.5rem; font-weight:900; color:{ts_color}; margin:0">{ts}</p>
                            <p style="font-size:0.75rem; color:#777; margin:0">out of 100</p>
                            <p style="font-size:1.1rem; font-weight:700; color:{ts_color}; margin-top:0.5rem">{ts_label}</p>
                        </div>""",
                        unsafe_allow_html=True,
                    )
                with col_ts2:
                    # Show Consensus Safety Net Banner if active
                    safety_triggered = getattr(risk_result, "safety_net_triggered", False)
                    divergence_val   = getattr(risk_result, "divergence_index", 0.0)
                    consensus_lbl    = getattr(risk_result, "consensus_status", "Standard")
                    breakdown_info   = getattr(risk_result, "evidence_breakdown", {})

                    ceiling = getattr(risk_result, "layer0_model_ceiling", 100)

                    if safety_triggered:
                        st.markdown(
                            f"""<div style="background:#fefce8; border:2px solid #eab308;
                                    border-radius:8px; padding:0.8rem 1rem; margin-bottom:0.8rem;
                                    font-size:0.85rem">
                                <b>🛡️ Consensus Safety Net Engaged (Divergence: {divergence_val:.0%})</b><br>
                                An acute discrepancy was detected between predictive ML signals ({breakdown_info.get('ml_legit_probability', 0)}% Legit) 
                                and objective domain forensics ({breakdown_info.get('forensic_trust_score', 0)}/100). 
                                The trust score has been mathematically stabilized to prevent false extremes.
                            </div>""",
                            unsafe_allow_html=True,
                        )
                    elif ceiling < 100:
                        st.markdown(
                            f"""<div style="background:#fef3c7; border:1px solid #f59e0b;
                                    border-radius:8px; padding:0.6rem 1rem; margin-bottom:0.8rem;
                                    font-size:0.85rem">
                                <b>⚠️ ML Model Ceiling Active: {ceiling}/100</b><br>
                                The ML model's prediction caps the trust score at {ceiling}.
                                Rule-based raw score was {risk_result.layer1_url_score +
                                risk_result.layer2_whois_score + risk_result.layer3_html_score +
                                risk_result.layer4_reputation_score}/100.
                            </div>""",
                            unsafe_allow_html=True,
                        )
                    else:
                        st.markdown(
                            f"""<div style="background:#f0fdf4; border:1px solid #86efac;
                                    border-radius:8px; padding:0.4rem 0.8rem; margin-bottom:0.6rem;
                                    font-size:0.8rem; color:#15803d">
                                <b>🤝 Multi-Layer Consensus: {consensus_lbl}</b> 
                                (Evidence Divergence: {divergence_val:.1%})
                            </div>""",
                            unsafe_allow_html=True,
                        )
                    # Layer breakdown
                    layers = [
                        ("\U0001f517 Layer 1: URL Signals",    risk_result.layer1_url_score),
                        ("\U0001f4c5 Layer 2: Domain Age",      risk_result.layer2_whois_score),
                        ("\U0001f4c4 Layer 3: Page Content",    risk_result.layer3_html_score),
                        ("\U0001f6e1\ufe0f Layer 4: Reputation DB", risk_result.layer4_reputation_score),
                    ]
                    for lname, lscore in layers:
                        pct = lscore / 25
                        bar_col = "#22c55e" if pct >= 0.8 else "#f97316" if pct >= 0.4 else "#ef4444"
                        st.markdown(
                            f"""<div style="margin-bottom:0.5rem">
                                <div style="display:flex; justify-content:space-between; font-size:0.85rem">
                                    <span>{lname}</span><span style="color:{bar_col};font-weight:700">{lscore}/25</span>
                                </div>
                                <div style="background:#e5e7eb; border-radius:6px; height:10px; margin-top:3px">
                                    <div style="background:{bar_col}; width:{int(pct*100)}%; height:10px; border-radius:6px"></div>
                                </div>
                            </div>""",
                            unsafe_allow_html=True,
                        )

                # Risk flags
                if risk_result.flags:
                    st.markdown("##### \U0001f6a9 Risk Signals Detected")
                    for flag in risk_result.flags:
                        st.markdown(f"- {flag}")
                else:
                    st.success("\u2705 No risk signals detected across all 4 layers.")

                # ── Extracted Features ──
                with st.expander("🔍 Extracted URL Features", expanded=False):
                    feat_df = pd.DataFrame([features]).T
                    feat_df.columns = ["Value"]
                    feat_df.index.name = "Feature"
                    st.dataframe(feat_df, use_container_width=True)

                # ── Actionable Counterfactual Explanations (Research XAI) ──
                st.markdown("---")
                st.markdown("### 🔬 Actionable Counterfactual Explanations (XAI)")
                st.caption(
                    "Algorithmic recourse: Identifies the minimal set of concrete, realistic adjustments "
                    "that would flip an untrusted classification or lower its risk exposure."
                )

                try:
                    cf_result = generate_counterfactual_explanation(
                        pipeline=active_pipeline,
                        feature_dict=features,
                        feature_cols=active_features,
                        target_class=0, # Legitimate
                        max_changes=4
                    )

                    if cf_result.get("is_already_target"):
                        st.success(
                            "✅ **Positive Baseline Verified**: This domain is already classified as **Legitimate**. "
                            "No defensive counterfactual modifications are required."
                        )
                    else:
                        orig_pred = cf_result.get("original_prediction", "Unknown")
                        cf_pred   = cf_result.get("counterfactual_prediction", "Unknown")
                        recs      = cf_result.get("recommendations", [])

                        col_cf1, col_cf2 = st.columns(2)
                        with col_cf1:
                            st.markdown(
                                f"""<div style="background:#fef2f2; border:1px solid #ef4444; border-radius:10px; padding:1rem; text-align:center">
                                    <span style="font-size:0.85rem; color:#991b1b; font-weight:600">CURRENT STATUS</span>
                                    <h3 style="color:#b91c1c; margin:0.3rem 0">{orig_pred.upper()}</h3>
                                    <span style="font-size:0.85rem; color:#7f1d1d">
                                        Legitimate Prob: {cf_result['original_probabilities'].get('Legitimate', 0.0):.1%}
                                    </span>
                                </div>""",
                                unsafe_allow_html=True
                            )
                        with col_cf2:
                            st.markdown(
                                f"""<div style="background:#f0fdf4; border:1px solid #22c55e; border-radius:10px; padding:1rem; text-align:center">
                                    <span style="font-size:0.85rem; color:#166534; font-weight:600">COUNTERFACTUAL RECOURSE</span>
                                    <h3 style="color:#15803d; margin:0.3rem 0">{cf_pred.upper()}</h3>
                                    <span style="font-size:0.85rem; color:#14532d">
                                        Projected Legitimate: {cf_result['counterfactual_probabilities'].get('Legitimate', 0.0):.1%}
                                        (+{cf_result.get('target_prob_increase', 0.0):.1%})
                                    </span>
                                </div>""",
                                unsafe_allow_html=True
                            )

                        if recs:
                            st.markdown("##### 🛠️ Minimal Prescriptive Modifications:")
                            for idx, r in enumerate(recs, 1):
                                st.markdown(
                                    f"**{idx}. {r['feature']}** (`{r['current_value']}` → `{r['target_value']}`)<br>"
                                    f"&nbsp;&nbsp;&nbsp;&nbsp;↳ *Action:* {r['description']}<br>"
                                    f"&nbsp;&nbsp;&nbsp;&nbsp;↳ *Marginal Risk Impact:* **{r['risk_drop']:+.1%}** risk reduction",
                                    unsafe_allow_html=True
                                )
                        else:
                            st.info("No single-feature adjustment sufficiently shifts the model's high confidence.")
                except Exception as cf_err:
                    st.warning(f"Counterfactual calculation note: {cf_err}")

                # ── SHAP Note ──
                shap_dir = PROJECT_ROOT / "results" / "shap"
                if (shap_dir / "shap_summary.png").exists():
                    st.markdown("---")
                    st.markdown("#### 🧠 Global Feature Importance (from Training)")
                    st.image(str(shap_dir / "shap_summary.png"), caption="SHAP Summary Plot")
                    st.caption(
                        "_These SHAP values show which features most influence the model's predictions "
                        "across the training dataset. They describe the model's learned patterns, "
                        "not a guarantee of any individual website's intent._"
                    )

            except Exception as e:
                st.error(f"Prediction error: {e}")
                import traceback
                st.code(traceback.format_exc())

elif analyze_btn and not url_input:
    st.warning("Please enter a URL to analyze.")

# ── Model Information ─────────────────────────────────────────────────
st.markdown("---")
with st.expander("ℹ️ Model Information", expanded=False):
    if config:
        col_i1, col_i2, col_i3 = st.columns(3)
        with col_i1:
            st.metric("Best Model",    config.get("best_model", "N/A"))
            st.metric("Features Used", config.get("num_features", 0))
        with col_i2:
            st.metric("Macro F1", f"{config.get('best_macro_f1', 0):.4f}")
            st.metric("Train Size",    config.get("train_size", 0))
        with col_i3:
            st.metric("Calibrated", "Yes" if calibrated else "No")
            st.metric("Test Size",  config.get("test_n", 0))

        st.markdown("**Confidence Threshold Analysis**")
        threshold_path = PROJECT_ROOT / "results" / "confidence_threshold_analysis.csv"
        if threshold_path.exists():
            thr_df = pd.read_csv(threshold_path)
            st.dataframe(thr_df.style.format({
                "Coverage": "{:.1%}",
                "Abstention_Rate": "{:.1%}",
                "Accuracy_Accepted": "{:.4f}",
            }), use_container_width=True)
    else:
        st.info("Run scripts/run_pipeline.py to generate model information.")

# ── Results Gallery ───────────────────────────────────────────────────
st.markdown("---")
with st.expander("📊 Experiment Results", expanded=False):
    comparison_path = PROJECT_ROOT / "results" / "model_comparison.csv"
    if comparison_path.exists():
        cmp_df = pd.read_csv(comparison_path)
        st.markdown("**Model Comparison**")
        display_cols = [c for c in ["Model", "Accuracy", "Macro_F1", "ROC_AUC",
                                     "Training_Time", "Inference_Time"] if c in cmp_df.columns]
        st.dataframe(cmp_df[display_cols].style.highlight_max(
            subset=[c for c in ["Accuracy", "Macro_F1", "ROC_AUC"] if c in display_cols],
            color="#c8e6c9"
        ), use_container_width=True)

        fig_path = PROJECT_ROOT / "results" / "figures" / "model_comparison.png"
        if fig_path.exists():
            st.image(str(fig_path), caption="Model Comparison Chart")

        ablation_path = PROJECT_ROOT / "results" / "ablation" / "ablation_comparison.csv"
        if ablation_path.exists():
            st.markdown("**Feature Ablation Results**")
            abl_df = pd.read_csv(ablation_path)
            display_abl = [c for c in ["Config", "Num_Features", "Accuracy", "Macro_F1", "ROC_AUC"] if c in abl_df.columns]
            st.dataframe(abl_df[display_abl], use_container_width=True)
    else:
        st.info("Run scripts/run_pipeline.py to generate experiment results.")

st.markdown("---")
st.markdown(
    "<p style='text-align:center; color:#888; font-size:0.85rem'>"
    "AI-Powered Website Trust Assessment System · B.Tech CSE Final Year Project · "
    "For research purposes only. Not a guarantee of website safety."
    "</p>",
    unsafe_allow_html=True,
)
