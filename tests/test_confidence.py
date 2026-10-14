"""Tests for confidence-aware prediction."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
import numpy as np
import pandas as pd
from unittest.mock import MagicMock


def make_mock_pipeline(proba: list):
    """Create a mock pipeline that returns fixed probabilities."""
    mock = MagicMock()
    mock.predict_proba.return_value = np.array(proba)
    mock.predict.return_value = np.argmax(proba, axis=1)
    return mock


def test_high_confidence_legitimate():
    from src.models.predict import predict_with_abstention
    pipeline = make_mock_pipeline([[0.90, 0.10]])
    X = pd.DataFrame([[0] * 5], columns=[f"f{i}" for i in range(5)])
    result = predict_with_abstention(pipeline, X, threshold=0.70, label_map={0: "Legitimate", 1: "Phishing"})
    assert result.iloc[0]["prediction"] == "Legitimate"
    assert result.iloc[0]["needs_review"] == False
    assert abs(result.iloc[0]["confidence"] - 0.90) < 0.001


def test_high_confidence_phishing():
    from src.models.predict import predict_with_abstention
    pipeline = make_mock_pipeline([[0.08, 0.92]])
    X = pd.DataFrame([[0] * 5], columns=[f"f{i}" for i in range(5)])
    result = predict_with_abstention(pipeline, X, threshold=0.70, label_map={0: "Legitimate", 1: "Phishing"})
    assert result.iloc[0]["prediction"] == "Phishing"
    assert result.iloc[0]["needs_review"] == False


def test_needs_review_low_confidence():
    from src.models.predict import predict_with_abstention
    pipeline = make_mock_pipeline([[0.48, 0.52]])
    X = pd.DataFrame([[0] * 5], columns=[f"f{i}" for i in range(5)])
    result = predict_with_abstention(pipeline, X, threshold=0.70, label_map={0: "Legitimate", 1: "Phishing"})
    assert result.iloc[0]["prediction"] == "Needs Review"
    assert result.iloc[0]["needs_review"] == True


def test_exactly_at_threshold():
    from src.models.predict import predict_with_abstention
    pipeline = make_mock_pipeline([[0.30, 0.70]])
    X = pd.DataFrame([[0] * 5], columns=[f"f{i}" for i in range(5)])
    result = predict_with_abstention(pipeline, X, threshold=0.70, label_map={0: "Legitimate", 1: "Phishing"})
    # confidence = 0.70 >= 0.70: should NOT be needs_review
    assert result.iloc[0]["needs_review"] == False


def test_threshold_sweep_produces_expected_columns():
    from src.models.confidence import threshold_sweep
    pipeline = make_mock_pipeline([[0.90, 0.10]] * 100 + [[0.48, 0.52]] * 100)
    pipeline.predict_proba = MagicMock(
        return_value=np.vstack([
            np.tile([0.90, 0.10], (100, 1)),
            np.tile([0.48, 0.52], (100, 1)),
        ])
    )
    X = pd.DataFrame(np.zeros((200, 3)))
    y = pd.Series([0] * 100 + [1] * 100)
    df = threshold_sweep(pipeline, X, y, thresholds=[0.50, 0.70, 0.90])
    assert "Coverage" in df.columns
    assert "Abstention_Rate" in df.columns
    assert "Accuracy_Accepted" in df.columns
    assert len(df) == 3
