import time, sys
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.utils.logging import get_logger
logger = get_logger(__name__)


def evaluate_model(
    pipeline,
    X_test,
    y_test,
    model_name: str = "model",
    label_names: list = None,
    multiclass: bool = False,
) -> dict:
    start   = time.perf_counter()
    y_pred  = pipeline.predict(X_test)
    elapsed = time.perf_counter() - start

    try:
        y_proba = pipeline.predict_proba(X_test)
        if multiclass:
            roc_auc = roc_auc_score(y_test, y_proba, multi_class="ovr", average="macro")
        else:
            roc_auc = roc_auc_score(y_test, y_proba[:, 1])
    except Exception as e:
        logger.warning(f"ROC-AUC error: {e}")
        roc_auc = None

    avg = "macro" if multiclass else "binary"
    metrics = {
        "Model":           model_name,
        "Accuracy":        round(accuracy_score(y_test, y_pred), 6),
        "Precision":       round(precision_score(y_test, y_pred, average=avg, zero_division=0), 6),
        "Recall":          round(recall_score(y_test, y_pred, average=avg, zero_division=0), 6),
        "F1":              round(f1_score(y_test, y_pred, average=avg, zero_division=0), 6),
        "Macro_Precision": round(precision_score(y_test, y_pred, average="macro", zero_division=0), 6),
        "Macro_Recall":    round(recall_score(y_test, y_pred, average="macro", zero_division=0), 6),
        "Macro_F1":        round(f1_score(y_test, y_pred, average="macro", zero_division=0), 6),
        "Weighted_F1":     round(f1_score(y_test, y_pred, average="weighted", zero_division=0), 6),
        "ROC_AUC":         round(roc_auc, 6) if roc_auc is not None else None,
        "Inference_Time":  round(elapsed, 6),
    }

    if label_names:
        report = classification_report(
            y_test, y_pred, target_names=label_names,
            output_dict=True, zero_division=0
        )
        for lname in label_names:
            if lname in report:
                metrics[f"{lname}_Precision"] = round(report[lname]["precision"], 6)
                metrics[f"{lname}_Recall"]    = round(report[lname]["recall"], 6)
                metrics[f"{lname}_F1"]        = round(report[lname]["f1-score"], 6)

    logger.info(
        f"{model_name}  Acc={metrics['Accuracy']:.4f}  "
        f"F1={metrics['F1']:.4f}  ROC_AUC={metrics['ROC_AUC']}"
    )
    return metrics


def save_confusion_matrix(y_test, y_pred, model_name, label_names, out_path):
    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Blues",
        xticklabels=label_names, yticklabels=label_names, ax=ax
    )
    ax.set_title(f"Confusion Matrix  {model_name}")
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    plt.tight_layout()
    plt.savefig(out_path, dpi=120, bbox_inches="tight")
    plt.close(fig)
    logger.info(f"Confusion matrix saved: {out_path}")


def save_model_comparison_plot(results_df: pd.DataFrame, out_path: str):
    fig, axes = plt.subplots(1, 3, figsize=(16, 5))
    metrics = ["Accuracy", "Macro_F1", "ROC_AUC"]
    for ax, metric in zip(axes, metrics):
        valid = results_df[results_df[metric].notna()]
        vals  = valid[metric].values
        names = valid["Model"].values
        bars = ax.barh(names, vals, color="steelblue")
        lo = max(0, min(vals) - 0.05) if len(vals) > 0 else 0
        hi = min(1.01, max(vals) + 0.02) if len(vals) > 0 else 1
        ax.set_xlim(lo, hi)
        ax.set_xlabel(metric)
        ax.set_title(metric)
        for bar, v in zip(bars, vals):
            ax.text(v + 0.001, bar.get_y() + bar.get_height() / 2,
                    f"{v:.4f}", va="center", fontsize=8)
    plt.suptitle("Model Comparison", fontsize=14)
    plt.tight_layout()
    plt.savefig(out_path, dpi=120, bbox_inches="tight")
    plt.close(fig)
    logger.info(f"Model comparison plot saved: {out_path}")
