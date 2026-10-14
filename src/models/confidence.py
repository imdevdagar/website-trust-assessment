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

THRESHOLDS = [0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95]
BANDS      = [(0.50, 0.60), (0.60, 0.70), (0.70, 0.80), (0.80, 0.90), (0.90, 1.01)]


def threshold_sweep(pipeline, X_test, y_test, thresholds=None) -> pd.DataFrame:
    """
    For each threshold, compute coverage, abstention rate,
    accuracy on accepted, F1 on accepted, and error rate.
    """
    if thresholds is None:
        thresholds = THRESHOLDS

    from sklearn.metrics import accuracy_score, f1_score

    proba  = pipeline.predict_proba(X_test)
    max_p  = proba.max(axis=1)
    pred   = proba.argmax(axis=1)
    y_arr  = np.array(y_test)

    rows = []
    for thr in thresholds:
        accepted_mask = max_p >= thr
        n_total    = len(y_arr)
        n_accepted = accepted_mask.sum()
        n_review   = n_total - n_accepted
        coverage   = n_accepted / n_total

        if n_accepted > 0:
            acc = accuracy_score(y_arr[accepted_mask], pred[accepted_mask])
            try:
                f1 = f1_score(y_arr[accepted_mask], pred[accepted_mask], average="macro", zero_division=0)
            except Exception:
                f1 = None
            err = 1 - acc
        else:
            acc = None
            f1  = None
            err = None

        rows.append({
            "Threshold":       thr,
            "Coverage":        round(float(coverage), 6),
            "Abstention_Rate": round(float(1 - coverage), 6),
            "Needs_Review_N":  int(n_review),
            "Accepted_N":      int(n_accepted),
            "Accuracy_Accepted": round(float(acc), 6) if acc is not None else None,
            "F1_Accepted":       round(float(f1), 6) if f1 is not None else None,
            "Error_Rate_Accepted": round(float(err), 6) if err is not None else None,
        })

    df = pd.DataFrame(rows)
    logger.info(f"Threshold sweep done  ({len(thresholds)} thresholds)")
    return df


def confidence_band_analysis(pipeline, X_test, y_test, bands=None) -> pd.DataFrame:
    """
    For each confidence band, compute sample count, accuracy, error rate.
    Investigates: do low-confidence predictions contain more errors?
    """
    if bands is None:
        bands = BANDS

    from sklearn.metrics import accuracy_score

    proba  = pipeline.predict_proba(X_test)
    max_p  = proba.max(axis=1)
    pred   = proba.argmax(axis=1)
    y_arr  = np.array(y_test)

    rows = []
    for lo, hi in bands:
        mask = (max_p >= lo) & (max_p < hi)
        n = mask.sum()
        if n > 0:
            acc = accuracy_score(y_arr[mask], pred[mask])
            err = 1 - acc
            unique, counts = np.unique(y_arr[mask], return_counts=True)
            class_dist = {int(u): int(c) for u, c in zip(unique, counts)}
        else:
            acc = None
            err = None
            class_dist = {}

        rows.append({
            "Band":       f"{lo:.2f}-{hi:.2f}",
            "Count":      int(n),
            "Accuracy":   round(float(acc), 6) if acc is not None else None,
            "Error_Rate": round(float(err), 6) if err is not None else None,
            "Class_Dist": str(class_dist),
        })

    df = pd.DataFrame(rows)
    logger.info("Confidence band analysis done")
    return df


def save_confidence_coverage_plot(threshold_df: pd.DataFrame, out_path: str):
    """Plot threshold vs coverage and accuracy on accepted predictions."""
    fig, ax1 = plt.subplots(figsize=(9, 5))
    color1 = "steelblue"
    ax1.set_xlabel("Confidence Threshold")
    ax1.set_ylabel("Coverage", color=color1)
    ax1.plot(threshold_df["Threshold"], threshold_df["Coverage"],
             "o-", color=color1, label="Coverage")
    ax1.tick_params(axis="y", labelcolor=color1)

    ax2 = ax1.twinx()
    color2 = "tomato"
    ax2.set_ylabel("Accuracy on Accepted", color=color2)
    valid = threshold_df.dropna(subset=["Accuracy_Accepted"])
    ax2.plot(valid["Threshold"], valid["Accuracy_Accepted"],
             "s--", color=color2, label="Accuracy (accepted)")
    ax2.tick_params(axis="y", labelcolor=color2)

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc="lower left")
    plt.title("Confidence Threshold vs Coverage and Accuracy")
    plt.tight_layout()
    plt.savefig(out_path, dpi=120, bbox_inches="tight")
    plt.close(fig)
    logger.info(f"Confidence-coverage plot saved: {out_path}")
