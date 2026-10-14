import sys
from pathlib import Path
import pandas as pd
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.models.confidence import threshold_sweep, confidence_band_analysis, save_confidence_coverage_plot
from src.utils.logging import get_logger
logger = get_logger(__name__)


def run_confidence_analysis(
    pipeline,
    X_test,
    y_test,
    figures_dir: Path = None,
) -> tuple:
    """
    Run threshold sweep and confidence band analysis.
    Save results and plots.
    Returns (threshold_df, band_df).
    """
    logger.info("Running confidence threshold sweep...")
    threshold_df = threshold_sweep(pipeline, X_test, y_test)
    logger.info(f"\nThreshold sweep:\n{threshold_df.to_string()}")

    logger.info("\nRunning confidence band analysis...")
    band_df = confidence_band_analysis(pipeline, X_test, y_test)
    logger.info(f"\nConfidence bands:\n{band_df.to_string()}")

    if figures_dir is not None:
        figures_dir = Path(figures_dir)
        figures_dir.mkdir(parents=True, exist_ok=True)
        plot_path = figures_dir / "confidence_vs_coverage.png"
        save_confidence_coverage_plot(threshold_df, str(plot_path))

    return threshold_df, band_df
