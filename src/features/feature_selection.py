import sys
from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.feature_selection import VarianceThreshold

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.utils.logging import get_logger
logger = get_logger(__name__)


def remove_zero_variance(df: pd.DataFrame, feature_cols: list) -> list:
    X = df[feature_cols]
    sel = VarianceThreshold(threshold=0.0)
    sel.fit(X)
    kept = [feature_cols[i] for i, s in enumerate(sel.get_support()) if s]
    removed = set(feature_cols) - set(kept)
    if removed:
        logger.info(f"Removed zero-variance features: {sorted(removed)}")
    return kept


def remove_high_correlation(df: pd.DataFrame, feature_cols: list, threshold: float = 0.95) -> list:
    X = df[feature_cols]
    corr_matrix = X.corr().abs()
    upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
    to_drop = [col for col in upper.columns if any(upper[col] > threshold)]
    kept = [f for f in feature_cols if f not in to_drop]
    if to_drop:
        logger.info(f"Removed {len(to_drop)} highly correlated features (thresh={threshold}): {to_drop}")
    return kept


def select_features(df: pd.DataFrame, feature_cols: list) -> list:
    cols = remove_zero_variance(df, feature_cols)
    cols = remove_high_correlation(df, cols, threshold=0.95)
    logger.info(f"Selected {len(cols)} features from {len(feature_cols)} candidates")
    return cols
