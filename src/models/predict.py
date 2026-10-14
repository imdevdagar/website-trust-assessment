import sys
from pathlib import Path
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.utils.logging import get_logger
logger = get_logger(__name__)

LABEL_MAP_BINARY    = {0: "Legitimate", 1: "Phishing"}
LABEL_MAP_MULTICLASS = {0: "Legitimate", 1: "Phishing", 2: "Scam"}


def predict_with_abstention(
    pipeline,
    X,
    threshold: float = 0.70,
    label_map: dict = None,
) -> pd.DataFrame:
    """
    Make predictions with confidence-aware abstention.

    Returns DataFrame with columns:
      prediction, confidence, needs_review,
      prob_class_0, prob_class_1, [prob_class_2]
    """
    if label_map is None:
        label_map = LABEL_MAP_BINARY

    proba  = pipeline.predict_proba(X)
    max_p  = proba.max(axis=1)
    pred_i = proba.argmax(axis=1)

    results = []
    for i in range(len(X)):
        confidence   = float(max_p[i])
        needs_review = confidence < threshold
        if needs_review:
            pred_label = "Needs Review"
        else:
            pred_label = label_map.get(int(pred_i[i]), f"Class_{pred_i[i]}")

        row = {
            "prediction":  pred_label,
            "confidence":  round(confidence, 6),
            "needs_review": needs_review,
            "predicted_class": int(pred_i[i]) if not needs_review else -1,
        }
        for j in range(proba.shape[1]):
            class_name = label_map.get(j, f"class_{j}")
            row[f"prob_{class_name}"] = round(float(proba[i, j]), 6)
        results.append(row)

    return pd.DataFrame(results)


def predict_single(
    pipeline,
    feature_dict: dict,
    feature_cols: list,
    threshold: float = 0.70,
    label_map: dict = None,
) -> dict:
    """Predict a single sample given a feature dictionary."""
    if label_map is None:
        label_map = LABEL_MAP_BINARY

    X = pd.DataFrame([{col: feature_dict.get(col, 0) for col in feature_cols}])
    result_df = predict_with_abstention(pipeline, X, threshold=threshold, label_map=label_map)
    return result_df.iloc[0].to_dict()
