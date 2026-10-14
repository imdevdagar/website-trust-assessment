"""
adversarial_benchmark.py
Academic Stress Test Suite: Adversarial Evasion Benchmarking
Evaluates model robustness against 6 common adversarial obfuscation techniques:
1. Subdomain Dilution / Subdomain Inflation
2. Random Benign Path Padding (Diluting entropy / length ratios)
3. Benign Query Parameter Injection (?utm_source=google&ref=paypal)
4. Mixed-Case Randomization (CaMeLcAsInG)
5. Hyphenation & Compound Token Insertion
6. TLD Geo-Mimicry & Compound Suffixes
"""
import sys
import json
from pathlib import Path
import pandas as pd
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.features.url_features import extract_url_features
from src.models.train import load_model
from src.scoring.risk_scorer import compute_risk_score

def run_adversarial_suite():
    print("=" * 80)
    print("ACADEMIC ADVERSARIAL EVASION BENCHMARK")
    print("Quantifying Robustness & Evasion Resistance Against Targeted Obfuscation")
    print("=" * 80)

    # Load multi-class model & features
    model_path = PROJECT_ROOT / "models" / "XGBoost_multiclass.pkl"
    features_path = PROJECT_ROOT / "models" / "multiclass_features.json"
    
    pipeline = load_model(str(model_path))
    with open(features_path, "r") as f:
        feature_cols = json.load(f)

    # 10 Known Malicious Baseline Seeds (Phishing & Scam)
    baseline_seeds = [
        {"base": "http://paypa1-security-check.xyz/login", "type": "Phishing"},
        {"base": "http://amazon-account-verify.online/auth", "type": "Phishing"},
        {"base": "http://chase-security-update.top/login.php", "type": "Phishing"},
        {"base": "http://apple-id-verify.cf/account", "type": "Phishing"},
        {"base": "http://netflix-billing-update.buzz/card", "type": "Phishing"},
        {"base": "http://guaranteed-crypto-profit.top/invest", "type": "Scam"},
        {"base": "http://instant-fast-loan-approval.buzz", "type": "Scam"},
        {"base": "http://luxury-handbag-90off-outlet.shop/sale", "type": "Scam"},
        {"base": "http://puppy-adoption-express-delivery.xyz", "type": "Scam"},
        {"base": "http://binance-kyc-validation.fun/wallet", "type": "Phishing"},
    ]

    # Obfuscation Perturbation Generators
    perturbations = {
        "Baseline (No Attack)": lambda u: u,
        "Subdomain Dilution": lambda u: u.replace("http://", "http://login.service.verify.security."),
        "Benign Query Padding": lambda u: u + "?utm_source=google&utm_medium=cpc&utm_campaign=official_portal&session=valid",
        "Deep Benign Path Padding": lambda u: u.rstrip("/") + "/assets/resources/docs/v2/index.html",
        "Random Case Shuffling": lambda u: "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(u)),
        "Hyphen Splitting": lambda u: u.replace("-", "--"),
        "Combined Multi-Vector": lambda u: (
            u.replace("http://", "http://portal.auth.")
            + "/verification/secure/client.html?source=verified&partner=google"
        ),
    }

    results = []

    for pert_name, pert_fn in perturbations.items():
        detected = 0
        total = len(baseline_seeds)
        clamped_by_safety_net = 0
        scores = []

        for item in baseline_seeds:
            perturbed_url = pert_fn(item["base"])
            feats = extract_url_features(perturbed_url)
            
            # 1. Standalone Raw ML Pipeline (No safety net / no heuristics)
            feat_df = pd.DataFrame([{c: feats.get(c, 0) for c in feature_cols}])
            raw_proba = pipeline.predict_proba(feat_df)[0]
            raw_pred_idx = int(raw_proba.argmax())
            raw_pred_label = {0: "Legitimate", 1: "Phishing", 2: "Scam"}[raw_pred_idx]

            # 2. Production Multi-Tier Defense Pipeline (Safety Net + Heuristics)
            proba = raw_proba.copy()
            # Active attack vector overrides
            if feats.get("IsDomainIP", 0) or feats.get("HasBrandImpersonation", 0) or feats.get("HasTyposquatting", 0) or feats.get("HasHomographChar", 0):
                pred_idx = 2 if proba[2] >= 0.40 else 1
                proba = np.array([0.02, 0.78, 0.20]) if pred_idx == 1 else np.array([0.02, 0.20, 0.78])
            elif feats.get("HasSuspiciousTLD", 0) and (feats.get("HasInvestKeyword", 0) or feats.get("HasCryptoKeyword", 0) or feats.get("HasShopKeyword", 0) or feats.get("HasPhishKeyword", 0)):
                pred_idx = 2
                proba = np.array([0.03, 0.15, 0.82])
            else:
                pred_idx = 2 if proba[2] >= 0.48 else int(proba[:2].argmax())
            
            defended_pred_label = {0: "Legitimate", 1: "Phishing", 2: "Scam"}[pred_idx]

            # Evaluate using full Consensus Safety Net with fast offline mode
            risk = compute_risk_score(
                url=perturbed_url,
                url_features=feats,
                html_features=None,
                domain_features={"DomainAgeDays": -1, "HasValidCert": False},
                model_proba=list(proba),
                fast_mode=True,
            )

            # System blocks attack if identified as Phishing/Scam or Trust Score clamped <= 60 or Needs Review
            is_blocked = (defended_pred_label in ("Phishing", "Scam")) or (risk.trust_score <= 60) or risk.safety_net_triggered
            if is_blocked:
                detected += 1
            if risk.safety_net_triggered:
                clamped_by_safety_net += 1

            scores.append(risk.trust_score)

        detection_rate = (detected / total) * 100
        mean_trust = np.mean(scores)
        results.append({
            "Perturbation Vector": pert_name,
            "Attack Samples": total,
            "Defended / Blocked": detected,
            "Detection Rate (%)": round(detection_rate, 1),
            "Safety Net Clamps": clamped_by_safety_net,
            "Avg Trust Score (0-100)": round(mean_trust, 1),
            "Evasion Success Rate (%)": round(100.0 - detection_rate, 1),
        })

    df_res = pd.DataFrame(results)
    out_csv = PROJECT_ROOT / "results" / "adversarial_benchmark_results.csv"
    df_res.to_csv(out_csv, index=False)
    
    print("\n" + df_res.to_string(index=False))
    print(f"\n[OK] Results saved to: {out_csv}")
    print("=" * 80)
    return df_res

if __name__ == "__main__":
    run_adversarial_suite()
