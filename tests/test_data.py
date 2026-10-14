"""Tests for data loading and cleaning."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
import pandas as pd
import numpy as np


def test_clean_phishing_removes_leakage_columns():
    from src.data.clean import clean_phishing
    df = pd.DataFrame({
        "FILENAME": ["file1.html"],
        "URL": ["http://test.com"],
        "Domain": ["test.com"],
        "Title": ["Test Page"],
        "TLD": ["com"],
        "URLLength": [20],
        "IsHTTPS": [0],
        "label": [1],
    })
    cleaned = clean_phishing(df)
    for col in ["FILENAME", "URL", "Domain", "Title", "TLD"]:
        assert col not in cleaned.columns, f"{col} should be removed"
    assert "URLLength" in cleaned.columns
    assert "label" in cleaned.columns


def test_clean_phishing_handles_duplicates():
    from src.data.clean import clean_phishing
    df = pd.DataFrame({
        "URLLength": [20, 20],
        "IsHTTPS":   [1, 1],
        "label":     [0, 0],
    })
    cleaned = clean_phishing(df)
    assert len(cleaned) == 1


def test_clean_phishing_keeps_flagged_by_default():
    from src.data.clean import clean_phishing, FLAGGED_COLUMNS
    df = pd.DataFrame({
        "URLLength":          [20],
        "URLSimilarityIndex": [50],
        "TLDLegitimateProb":  [0.9],
        "URLCharProb":        [0.8],
        "DomainTitleMatchScore": [0.5],
        "URLTitleMatchScore": [0.5],
        "CharContinuationRate": [0.3],
        "label":              [1],
    })
    cleaned = clean_phishing(df, keep_flagged=True)
    # Flagged columns should still be present
    for col in FLAGGED_COLUMNS:
        if col in df.columns:
            assert col in cleaned.columns


def test_clean_phishing_removes_flagged_when_requested():
    from src.data.clean import clean_phishing, FLAGGED_COLUMNS
    df = pd.DataFrame({
        "URLLength":          [20],
        "URLSimilarityIndex": [50],
        "label":              [1],
    })
    cleaned = clean_phishing(df, keep_flagged=False)
    assert "URLSimilarityIndex" not in cleaned.columns


def test_get_feature_columns_excludes_target():
    from src.data.clean import get_feature_columns
    df = pd.DataFrame({
        "feature1": [1.0, 2.0],
        "feature2": [3.0, 4.0],
        "label":    [0, 1],
    })
    cols = get_feature_columns(df)
    assert "label" not in cols
    assert "feature1" in cols
    assert "feature2" in cols


def test_missing_dataset_raises():
    from src.data.load_data import load_phishing_raw
    from pathlib import Path
    import src.data.load_data as ld
    orig = ld._PHISHING_SRC
    ld._PHISHING_SRC = Path("/nonexistent/path/file.csv")
    with pytest.raises(FileNotFoundError):
        load_phishing_raw()
    ld._PHISHING_SRC = orig
