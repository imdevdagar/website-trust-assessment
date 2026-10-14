import sys
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.utils.logging import get_logger
logger = get_logger(__name__)

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False
    logger.warning("SHAP not installed. Explainability features disabled.")


def _get_inner_model(pipeline):
    """Extract the inner model from an sklearn Pipeline."""
    if hasattr(pipeline, "named_steps"):
        return pipeline.named_steps.get("model", pipeline)
    if hasattr(pipeline, "estimator"):
        # CalibratedClassifierCV
        base = pipeline.estimator
        if hasattr(base, "named_steps"):
            return base.named_steps.get("model", base)
        return base
    return pipeline


def _get_transformed_X(pipeline, X):
    """Apply pipeline preprocessing (scaler) but not the model step."""
    if hasattr(pipeline, "named_steps"):
        steps = list(pipeline.named_steps.items())
        model_step_name = steps[-1][0]
        X_transformed = X.copy()
        for name, step in steps[:-1]:
            X_transformed = step.transform(X_transformed)
        return X_transformed
    if hasattr(pipeline, "estimator"):
        base = pipeline.estimator
        return _get_transformed_X(base, X)
    return X


def compute_shap_values(pipeline, X_background, X_explain, max_samples: int = 1000):
    """
    Compute SHAP values for predictions.

    Returns:
        shap_values: array or Explanation object
        explainer: the SHAP explainer used
    """
    if not SHAP_AVAILABLE:
        raise RuntimeError("SHAP is not installed. Run: pip install shap")

    inner_model = _get_inner_model(pipeline)
    X_bg  = _get_transformed_X(pipeline, X_background)
    X_exp = _get_transformed_X(pipeline, X_explain)

    if len(X_bg) > max_samples:
        idx = np.random.choice(len(X_bg), max_samples, replace=False)
        X_bg = X_bg[idx] if hasattr(X_bg, '__getitem__') else X_bg.iloc[idx]

    model_type = type(inner_model).__name__
    logger.info(f"Computing SHAP values for {model_type}")

    if model_type in ("RandomForestClassifier", "DecisionTreeClassifier",
                       "XGBClassifier", "LGBMClassifier"):
        explainer   = shap.TreeExplainer(inner_model, data=X_bg)
        shap_values = explainer(X_exp)
    else:
        # Fallback: KernelExplainer
        predict_fn = lambda x: inner_model.predict_proba(x)
        explainer  = shap.KernelExplainer(predict_fn, shap.sample(X_bg, 100))
        shap_values = explainer.shap_values(X_exp)

    logger.info("SHAP values computed")
    return shap_values, explainer


def save_shap_summary_plot(shap_values, X_explain, feature_names: list, out_path: str):
    """Save global SHAP summary (beeswarm) plot."""
    if not SHAP_AVAILABLE:
        return

    if isinstance(X_explain, pd.DataFrame):
        X_vals = X_explain.values
    else:
        X_vals = X_explain

    plt.figure(figsize=(10, 8))
    try:
        if hasattr(shap_values, "values"):
            # Explanation object
            sv = shap_values.values
            if sv.ndim == 3:
                sv = sv[:, :, 1]  # take positive class
            shap.summary_plot(
                sv, X_vals, feature_names=feature_names,
                show=False, max_display=20
            )
        else:
            sv = shap_values
            if isinstance(sv, list):
                sv = sv[1]  # phishing class
            shap.summary_plot(
                sv, X_vals, feature_names=feature_names,
                show=False, max_display=20
            )
    except Exception as e:
        logger.warning(f"SHAP summary plot error: {e}")
        plt.close()
        return

    plt.tight_layout()
    plt.savefig(out_path, dpi=120, bbox_inches="tight")
    plt.close()
    logger.info(f"SHAP summary plot saved: {out_path}")


def save_shap_bar_plot(shap_values, feature_names: list, out_path: str):
    """Save global mean SHAP importance bar plot."""
    if not SHAP_AVAILABLE:
        return

    try:
        if hasattr(shap_values, "values"):
            sv = shap_values.values
        else:
            sv = shap_values
        if isinstance(sv, list):
            sv = sv[1]
        if sv.ndim == 3:
            sv = sv[:, :, 1]
        mean_abs = np.abs(sv).mean(axis=0)
        sorted_idx = np.argsort(mean_abs)[::-1][:20]
        sorted_feats = [feature_names[i] for i in sorted_idx]
        sorted_vals  = mean_abs[sorted_idx]

        fig, ax = plt.subplots(figsize=(9, 7))
        ax.barh(range(len(sorted_feats)), sorted_vals[::-1], color="steelblue")
        ax.set_yticks(range(len(sorted_feats)))
        ax.set_yticklabels(sorted_feats[::-1])
        ax.set_xlabel("Mean |SHAP value|")
        ax.set_title("Global Feature Importance (SHAP)")
        plt.tight_layout()
        plt.savefig(out_path, dpi=120, bbox_inches="tight")
        plt.close(fig)
        logger.info(f"SHAP bar plot saved: {out_path}")
    except Exception as e:
        logger.warning(f"SHAP bar plot error: {e}")
        plt.close()


def explain_single_prediction(
    pipeline,
    X_background,
    x_single: dict,
    feature_names: list,
    label_map: dict = None,
    out_path: str = None,
) -> dict:
    """
    Generate a single-sample SHAP explanation.
    Returns a dict with prediction, confidence, and top features.
    """
    if not SHAP_AVAILABLE:
        return {"error": "SHAP not available"}

    if label_map is None:
        label_map = {0: "Legitimate", 1: "Phishing"}

    X_single = pd.DataFrame([{col: x_single.get(col, 0) for col in feature_names}])
    proba = pipeline.predict_proba(X_single)
    pred_class = int(proba.argmax())
    confidence = float(proba.max())
    prediction = label_map.get(pred_class, f"Class_{pred_class}")

    try:
        shap_vals, _ = compute_shap_values(pipeline, X_background, X_single, max_samples=100)
        if hasattr(shap_vals, "values"):
            sv = shap_vals.values[0]
        else:
            sv = shap_vals
        if isinstance(sv, list):
            sv = sv[pred_class][0]
        if sv.ndim == 2:
            sv = sv[:, pred_class]

        top_idx = np.argsort(np.abs(sv))[::-1][:10]
        top_features = [
            {"feature": feature_names[i], "shap_value": round(float(sv[i]), 6)}
            for i in top_idx
        ]
    except Exception as e:
        logger.warning(f"Single SHAP explanation failed: {e}")
        top_features = []

    result = {
        "prediction":   prediction,
        "confidence":   round(confidence, 6),
        "probabilities": {label_map.get(j, str(j)): round(float(proba[0, j]), 6)
                          for j in range(proba.shape[1])},
        "top_features": top_features,
    }

    if out_path and top_features:
        try:
            fig, ax = plt.subplots(figsize=(9, 5))
            feats = [f["feature"] for f in top_features[::-1]]
            vals  = [f["shap_value"] for f in top_features[::-1]]
            colors = ["tomato" if v > 0 else "steelblue" for v in vals]
            ax.barh(feats, vals, color=colors)
            ax.set_xlabel("SHAP value (contribution to model prediction)")
            ax.set_title(f"Individual Explanation  Pred={prediction} Conf={confidence:.2%}")
            plt.tight_layout()
            plt.savefig(out_path, dpi=120, bbox_inches="tight")
            plt.close(fig)
        except Exception as e:
            logger.warning(f"SHAP individual plot error: {e}")

    return result


def generate_counterfactual_explanation(
    pipeline,
    feature_dict: dict,
    feature_cols: list,
    target_class: int = 0,
    max_changes: int = 4,
) -> dict:
    """
    Generate actionable counterfactual explanations for a prediction.
    Answers: 'What minimal realistic modifications to this website's features
    would shift the prediction to Legitimate (or dramatically reduce risk)?'

    Returns:
        dict containing:
            - original_prediction
            - original_probabilities
            - counterfactual_prediction
            - counterfactual_probabilities
            - recommended_actions (list of dicts with feature, current, target, impact)
    """
    X_orig = pd.DataFrame([{col: feature_dict.get(col, 0) for col in feature_cols}])
    orig_proba = pipeline.predict_proba(X_orig)[0]
    orig_class = int(orig_proba.argmax())
    label_map = {0: "Legitimate", 1: "Phishing", 2: "Scam"}

    if orig_class == target_class:
        return {
            "is_already_target": True,
            "message": "Domain is already classified as Legitimate.",
            "original_probabilities": {label_map[i]: float(orig_proba[i]) for i in range(len(orig_proba))},
            "recommendations": []
        }

    # Actionable levers that website owners or administrators could realistically address
    actionable_levers = {
        "DomainAgeProxy": {
            "target": 2, # Established domain (>365 days)
            "desc": "Wait for domain age to mature past 1 year or preserve established registration tenure."
        },
        "IsHTTPS": {
            "target": 1,
            "desc": "Enforce valid SSL/TLS HTTPS encryption on all requests."
        },
        "HasSuspiciousTLD": {
            "target": 0,
            "desc": "Migrate from high-abuse TLDs (.xyz, .top, .buzz) to standard ccTLD or gTLD (.com, .org)."
        },
        "HasCompoundTLD": {
            "target": 0,
            "desc": "Avoid confusing double/compound extensions (e.g. .com.co, .net.ru)."
        },
        "HasBrandImpersonation": {
            "target": 0,
            "desc": "Remove third-party trademarks, banking brand names, or payment provider tokens from domain host."
        },
        "HasTyposquatting": {
            "target": 0,
            "desc": "Eliminate brand name typosquatting / visually similar brand naming from domain SLD."
        },
        "HasHomographChar": {
            "target": 0,
            "desc": "Remove non-ASCII Unicode / Cyrillic lookalike homograph characters from host."
        },
        "NoOfSubDomain": {
            "target": 0,
            "desc": "Flatten deep multi-level subdomains down to root or single standard prefix."
        },
        "SubdomainDepth": {
            "target": 0,
            "desc": "Remove nested subdomain tiers (e.g., auth.secure.login.example.com)."
        },
        "NoOfHyphensInDomain": {
            "target": 0,
            "desc": "Remove hyphens and word separators from the domain name."
        },
        "HasObfuscation": {
            "target": 0,
            "desc": "Eliminate percent-encoding and redundant path separators (//) from URL."
        },
        "HasPhishKeyword": {
            "target": 0,
            "desc": "Remove sensitive credential tokens ('login', 'verify', 'update') from unauthenticated URL paths."
        },
        "HasInvestKeyword": {
            "target": 0,
            "desc": "Remove get-rich / high-yield investment trigger words ('profit', 'forex', 'guaranteed') from URL."
        },
        "HasCryptoKeyword": {
            "target": 0,
            "desc": "Sanitize URL path of generic crypto token hype terms."
        },
        "NoOfQueryParams": {
            "target": 0,
            "desc": "Minimize URL query parameters on public entry landing pages."
        }
    }

    # Evaluate univariate marginal gains (perturb one feature at a time towards target)
    improvements = []
    for feat, config in actionable_levers.items():
        if feat not in feature_cols:
            continue
        curr_val = feature_dict.get(feat, 0)
        target_val = config["target"]

        # Only evaluate if current value is worse than target
        if curr_val != target_val:
            X_mod = X_orig.copy()
            X_mod[feat] = target_val
            new_proba = pipeline.predict_proba(X_mod)[0]
            
            # Gain in target class probability
            prob_gain = float(new_proba[target_class] - orig_proba[target_class])
            # Drop in malicious classes
            risk_drop = float((orig_proba[1] + orig_proba[2]) - (new_proba[1] + new_proba[2]))
            
            improvements.append({
                "feature": feat,
                "current_value": curr_val,
                "target_value": target_val,
                "description": config["desc"],
                "target_prob_gain": prob_gain,
                "risk_drop": risk_drop,
                "new_proba": new_proba
            })

    # Filter to only beneficial recommendations (where risk drops or legitimate probability increases)
    beneficial = [imp for imp in improvements if imp["risk_drop"] > 0 or imp["target_prob_gain"] > 0]
    beneficial.sort(key=lambda x: max(x["risk_drop"], x["target_prob_gain"]), reverse=True)

    # Now create a greedy cumulative counterfactual
    top_recommendations = beneficial[:max_changes]
    X_cumulative = X_orig.copy()
    for rec in top_recommendations:
        X_cumulative[rec["feature"]] = rec["target_value"]

    cum_proba = pipeline.predict_proba(X_cumulative)[0]
    cum_class = int(cum_proba.argmax())

    return {
        "is_already_target": False,
        "original_prediction": label_map.get(orig_class, "Unknown"),
        "original_probabilities": {label_map[i]: float(orig_proba[i]) for i in range(len(orig_proba))},
        "counterfactual_prediction": label_map.get(cum_class, "Unknown"),
        "counterfactual_probabilities": {label_map[i]: float(cum_proba[i]) for i in range(len(cum_proba))},
        "target_prob_increase": float(cum_proba[target_class] - orig_proba[target_class]),
        "recommendations": top_recommendations
    }

