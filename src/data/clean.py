import sys
from pathlib import Path
import pandas as pd
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.utils.logging import get_logger
logger = get_logger(__name__)

REMOVE_COLUMNS  = ["FILENAME", "URL", "Domain", "Title", "TLD"]
FLAGGED_COLUMNS = [
    "URLSimilarityIndex", "CharContinuationRate", "TLDLegitimateProb",
    "URLCharProb", "DomainTitleMatchScore", "URLTitleMatchScore",
]
TARGET_COLUMN = "label"


def clean_phishing(df: pd.DataFrame, keep_flagged: bool = True) -> pd.DataFrame:
    logger.info(f"Cleaning PhiUSIIL  input shape: {df.shape}")
    df = df.copy()
    to_drop = [c for c in REMOVE_COLUMNS if c in df.columns]
    df.drop(columns=to_drop, inplace=True)
    logger.info(f"Dropped leakage columns: {to_drop}")
    if not keep_flagged:
        flagged_drop = [c for c in FLAGGED_COLUMNS if c in df.columns]
        df.drop(columns=flagged_drop, inplace=True)
        logger.info(f"Dropped flagged columns: {flagged_drop}")
    before = len(df)
    df.drop_duplicates(inplace=True)
    logger.info(f"Removed {before - len(df)} duplicate rows")
    num_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    if TARGET_COLUMN in num_cols:
        num_cols.remove(TARGET_COLUMN)
    missing_before = df[num_cols].isnull().sum().sum()
    if missing_before > 0:
        logger.warning(f"Filling {missing_before} missing values with column median")
        for col in num_cols:
            if df[col].isnull().any():
                df[col] = df[col].fillna(df[col].median())
    before_target = len(df)
    df.dropna(subset=[TARGET_COLUMN], inplace=True)
    if len(df) < before_target:
        logger.warning(f"Dropped {before_target - len(df)} rows with missing target")
    valid_labels = {0, 1}
    invalid_mask = ~df[TARGET_COLUMN].isin(valid_labels)
    if invalid_mask.any():
        logger.warning("Dropping rows with invalid labels")
        df = df[~invalid_mask]
    logger.info(f"Cleaned shape: {df.shape}")
    return df


def get_feature_columns(df: pd.DataFrame) -> list:
    num_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    return [c for c in num_cols if c != TARGET_COLUMN]


def get_domain_from_raw(df_raw: pd.DataFrame):
    if "Domain" in df_raw.columns:
        return df_raw["Domain"].copy()
    return None
