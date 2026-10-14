import sys
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.calibration import CalibratedClassifierCV, CalibrationDisplay
from sklearn.metrics import brier_score_loss

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.utils.logging import get_logger
logger = get_logger(__name__)


def calibrate_model(pipeline, X_train, y_train, method: str = "isotonic", cv: int = 5):
    """
    Calibrate a trained pipeline using CalibratedClassifierCV.
    Returns the calibrated pipeline.
    """
    logger.info(f"Calibrating with method={method} cv={cv}")
    calibrated = CalibratedClassifierCV(
        estimator=pipeline,
        method=method,
        cv=cv,
    )
    calibrated.fit(X_train, y_train)
    logger.info("Calibration complete")
    return calibrated


def compute_brier_score(pipeline, X_test, y_test, binary: bool = True) -> float:
    proba = pipeline.predict_proba(X_test)
    if binary:
        score = brier_score_loss(y_test, proba[:, 1])
    else:
        score = float(np.mean([
            brier_score_loss((y_test == c).astype(int), proba[:, c])
            for c in range(proba.shape[1])
        ]))
    logger.info(f"Brier score: {score:.6f}")
    return score


def save_calibration_curve(
    pipeline_uncal,
    pipeline_cal,
    X_test,
    y_test,
    model_name: str,
    out_path: str,
):
    """Plot reliability diagram comparing calibrated vs uncalibrated."""
    fig, ax = plt.subplots(figsize=(7, 6))
    ax.plot([0, 1], [0, 1], "k--", label="Perfectly calibrated")

    for pipe, label in [(pipeline_uncal, f"{model_name} (uncalibrated)"),
                         (pipeline_cal,   f"{model_name} (calibrated)")]:
        try:
            display = CalibrationDisplay.from_estimator(
                pipe, X_test, y_test, n_bins=10, ax=ax, name=label,
            )
        except Exception as e:
            logger.warning(f"CalibrationDisplay failed: {e}")

    ax.set_title(f"Calibration Curve  {model_name}")
    ax.legend()
    plt.tight_layout()
    plt.savefig(out_path, dpi=120, bbox_inches="tight")
    plt.close(fig)
    logger.info(f"Calibration curve saved: {out_path}")
