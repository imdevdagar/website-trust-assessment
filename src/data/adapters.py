import sys
from pathlib import Path
import pandas as pd
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.data.load_data import load_phishing_raw, load_scam_raw
from src.data.clean import clean_phishing, get_feature_columns
from src.features.url_features import extract_url_features
from src.utils.logging import get_logger
logger = get_logger(__name__)


class PhiUSIILAdapter:
    """Adapter for the PhiUSIIL Phishing URL Dataset."""

    def load(self, nrows=None):
        raw = load_phishing_raw(nrows=nrows)
        domain_col = raw["Domain"].copy() if "Domain" in raw.columns else None
        cleaned = clean_phishing(raw, keep_flagged=True)
        feature_cols = get_feature_columns(cleaned)
        df_out = cleaned[feature_cols + ["label"]].copy()
        df_out["source"] = "PhiUSIIL"
        if domain_col is not None:
            domain_aligned = domain_col.loc[cleaned.index]
            df_out["_domain"] = domain_aligned.values
        return df_out, domain_col, feature_cols

    def load_no_flagged(self, nrows=None):
        raw = load_phishing_raw(nrows=nrows)
        domain_col = raw["Domain"].copy() if "Domain" in raw.columns else None
        cleaned = clean_phishing(raw, keep_flagged=False)
        feature_cols = get_feature_columns(cleaned)
        df_out = cleaned[feature_cols + ["label"]].copy()
        df_out["source"] = "PhiUSIIL"
        if domain_col is not None:
            domain_aligned = domain_col.loc[cleaned.index]
            df_out["_domain"] = domain_aligned.values
        return df_out, domain_col, feature_cols


class ScamFerretAdapter:
    """Adapter for ScamFerret: extracts URL-level features from raw URLs."""

    def load(self) -> pd.DataFrame:
        raw = load_scam_raw()
        logger.info(f"ScamFerret raw: {raw.shape}")
        records = []
        for _, row in raw.iterrows():
            feats = extract_url_features(row["url"])
            feats["label"]    = row["label"]
            feats["source"]   = "ScamFerret"
            feats["category"] = row["category"]
            feats["url"]      = row["url"]
            records.append(feats)
        df = pd.DataFrame(records)
        logger.info(f"ScamFerret after feature extraction: {df.shape}")
        logger.info(f"Label distribution:\n{df['label'].value_counts().to_string()}")
        return df
