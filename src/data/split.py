import sys
from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, GroupShuffleSplit

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.utils.logging import get_logger
logger = get_logger(__name__)

RANDOM_STATE = 42
TEST_SIZE    = 0.20
TARGET_COLUMN = "label"


def standard_split(df: pd.DataFrame, feature_cols: list, test_size: float = TEST_SIZE):
    X = df[feature_cols]
    y = df[TARGET_COLUMN]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=RANDOM_STATE, stratify=y
    )
    logger.info(f"Standard split  train={X_train.shape}  test={X_test.shape}")
    logger.info(f"Train label dist: {y_train.value_counts().to_dict()}")
    logger.info(f"Test  label dist: {y_test.value_counts().to_dict()}")
    return X_train, X_test, y_train, y_test


def domain_aware_split(
    df: pd.DataFrame,
    feature_cols: list,
    domain_col: pd.Series,
    test_size: float = TEST_SIZE,
):
    if domain_col is None:
        logger.warning("Domain column not available; falling back to standard split.")
        return standard_split(df, feature_cols, test_size)
    df2 = df.copy()
    df2["_domain"] = domain_col.values
    unique_domains = df2["_domain"].unique()
    logger.info(f"Domain-aware split: {len(unique_domains)} unique domains")
    gss = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=RANDOM_STATE)
    X = df2[feature_cols]
    y = df2[TARGET_COLUMN]
    groups = df2["_domain"]
    train_idx, test_idx = next(gss.split(X, y, groups=groups))
    X_train = X.iloc[train_idx]
    X_test  = X.iloc[test_idx]
    y_train = y.iloc[train_idx]
    y_test  = y.iloc[test_idx]
    train_domains = set(df2.iloc[train_idx]["_domain"].unique())
    test_domains  = set(df2.iloc[test_idx]["_domain"].unique())
    overlap = train_domains & test_domains
    logger.info(f"Domain split  train={X_train.shape}  test={X_test.shape}")
    logger.info(f"Domains — train={len(train_domains)}  test={len(test_domains)}  overlap={len(overlap)}")
    if overlap:
        logger.warning(f"Domain overlap: {len(overlap)} shared domains (expected with GroupShuffleSplit)")
    return X_train, X_test, y_train, y_test
