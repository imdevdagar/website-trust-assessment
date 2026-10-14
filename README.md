# 🛡️ Website Trust Assessment System

An AI-driven, multi-layer website credibility, phishing, and scam risk intelligence engine with Evidence Divergence Index (EDI) consensus safety nets and counterfactual explainable AI (XAI).

---

## 📌 Overview

The **Website Trust Assessment System** evaluates web domains in real-time across four distinct analytical layers:
1. **Lexical & URL Engineering**: Structural decomposition, entropy, obfuscation, brand typo-squatting, and token analysis.
2. **Domain & Network Intelligence**: WHOIS domain registration age, DNS validation, nameserver reputation, and TLD security profiling.
3. **Live HTML & Security Inspection**: Active SSL certificate validation, DOM security heuristics, hidden forms, and external resource ratios.
4. **Consensus Safety Engine (EDI)**: An Evidence Divergence Index that cross-examines pure URL predictions against live network reality to prevent false positives on trusted educational, government, and enterprise domains.

---

## 🗂️ Clean Project Directory Structure

```text
website-trust-assessment/
│
├── app/                        # Interactive Streamlit Web UI
│   └── streamlit_app.py        # Dashboard with trust gauges, SHAP analysis & recourse
│
├── api/                        # Production FastAPI REST Backend
│   ├── main.py                 # Endpoints (/health, /predict/url, /explain, etc.)
│   └── schemas.py              # Pydantic request & response validation schemas
│
├── src/                        # Core Engine & Modular Libraries
│   ├── data/                   # Dataset loaders, cleaning, and domain-aware splitters
│   │   ├── clean.py            # PhiUSIIL & AA419 data sanitizer
│   │   ├── load_data.py        # CSV ingestion & distribution reporting
│   │   └── split.py            # Standard and domain-grouped train/test splitters
│   ├── features/               # Feature extraction pipelines
│   │   ├── url_features.py     # 40+ lexical, syntactic & statistical URL features
│   │   ├── domain_features.py  # Live WHOIS age & DNS infrastructure checks
│   │   └── html_features.py    # Active web page inspection & security signals
│   ├── models/                 # Model registry, training & inference
│   │   ├── train.py            # Scikit-learn & XGBoost pipeline builders
│   │   ├── predict.py          # Confidence-aware inference with abstention
│   │   ├── calibrate.py        # Isotonic probability calibration
│   │   └── evaluate.py         # Precision, Recall, F1 & Confusion matrix tools
│   ├── scoring/                # Multi-dimensional trust scoring
│   │   └── risk_scorer.py      # Trust Score (0-100), EDI, and Safety Net rules
│   ├── explainability/         # XAI Modules
│   │   └── shap_explainer.py   # TreeSHAP values & Algorithmic Recourse recommendations
│   └── utils/                  # Centralized logging, path resolution & config
│
├── models/                     # Serialized production models & feature maps
│   ├── XGBoost_multiclass.pkl  # Primary 3-class classifier (Legitimate/Phishing/Scam)
│   ├── scam_subcategory_model.pkl # 10-class AA419 taxonomy classifier
│   └── multiclass_features.json# Active model feature schemas
│
├── scripts/                    # Automation & Maintenance Pipelines
│   ├── pipeline/               # 5-step reproducible training and validation suite
│   │   ├── pipeline_step1_clean.py
│   │   ├── pipeline_step2_tranco.py
│   │   ├── pipeline_step3_eda.py
│   │   ├── pipeline_step4_subcategory.py
│   │   ├── pipeline_step5_final_retrain.py
│   │   └── tune_thresholds.py
│   └── data_collection/        # Scrapers & API fetchers for threat feeds
│       └── scrape_aa419.py
│
├── tests/                      # Automated Test Suite (100% Passing)
│   ├── test_features.py        # Verification of URL and domain extraction
│   ├── test_models.py          # Prediction integrity and bounds
│   ├── test_confidence.py      # Confidence abstention and edge cases
│   ├── test_data.py            # Data integrity and leak detection
│   └── benchmarks/             # Adversarial and robustness testing
│
├── data/                       # Datasets (raw, interim, processed - gitignored)
├── results/                    # Academic metrics, plots, and research manuscripts
├── Dockerfile                  # Container definition
├── docker-compose.yml          # Multi-service composition (API + UI)
├── requirements.txt            # Python dependencies
└── config.yaml                 # System configurations
```

---

## 🚀 Quickstart

### 1. Installation
Ensure Python 3.10+ is installed:
```bash
git clone <repo-url>
cd website-trust-assessment
pip install -r requirements.txt
```

### 2. Run the Streamlit Dashboard
```bash
python -m streamlit run app/streamlit_app.py
```
*Access the interface at `http://localhost:8501`.*

### 3. Run the FastAPI REST Server
```bash
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```
*Interactive Swagger docs available at `http://localhost:8000/docs`.*

### 4. Run the Test Suite
```bash
python -m pytest tests/
```

---

## 🧠 Key Innovations

1. **Multi-Class Threat Classification**: Rather than simple binary detection, the system classifies URLs into **Legitimate**, **Phishing**, or **Financial / 419 Scam**.
2. **AA419 Scam Taxonomy**: If classified as scam, a secondary model categorizes the threat into 10 forensic subcategories (e.g., *Fake Lottery*, *Inheritance Fraud*, *Employment Scam*, *Cryptocurrency Impersonation*).
3. **Evidence Divergence Index (EDI)**: Solves the classic problem of false positives on university or brand subdomains (such as `s.amizone.net` or `amazon.in`) by checking live DNS, age, and WHOIS records.
4. **Algorithmic Recourse (Counterfactual XAI)**: Tells webmasters exactly what features pushed their site into high-risk status and what specific adjustments would lower their risk score.
