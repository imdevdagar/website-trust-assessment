"""Tests for model registry and training."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
import numpy as np
import pandas as pd
from sklearn.datasets import make_classification


def _make_data(n=200):
    X, y = make_classification(n_samples=n, n_features=10, random_state=42)
    return pd.DataFrame(X, columns=[f"f{i}" for i in range(10)]), pd.Series(y)


def test_registry_returns_five_models():
    from src.models.registry import get_models
    models = get_models()
    assert len(models) == 5
    assert "LogisticRegression" in models
    assert "DecisionTree"       in models
    assert "RandomForest"       in models
    assert "XGBoost"            in models
    assert "LightGBM"           in models


def test_build_pipeline_has_scaler_and_model():
    from src.models.registry import get_models
    from src.models.train import build_pipeline
    model = list(get_models().values())[0]
    pipe  = build_pipeline(model)
    assert "scaler" in pipe.named_steps
    assert "model"  in pipe.named_steps


def test_train_and_predict():
    from src.models.registry import get_models
    from src.models.train import build_pipeline, train_model
    X, y = _make_data()
    X_train, X_test = X.iloc[:160], X.iloc[160:]
    y_train, y_test = y.iloc[:160], y.iloc[160:]
    models = get_models()
    for name, model in models.items():
        pipe, t = train_model(build_pipeline(model), X_train, y_train)
        preds = pipe.predict(X_test)
        assert len(preds) == len(y_test), f"{name} prediction length mismatch"
        assert set(preds).issubset({0, 1}), f"{name} unexpected labels"
        assert t > 0, f"{name} training time should be positive"


def test_evaluate_model_returns_required_metrics():
    from src.models.registry import get_models
    from src.models.train import build_pipeline, train_model
    from src.models.evaluate import evaluate_model
    X, y = _make_data()
    pipe, _ = train_model(build_pipeline(list(get_models().values())[0]), X.iloc[:160], y.iloc[:160])
    metrics = evaluate_model(pipe, X.iloc[160:], y.iloc[160:], model_name="test")
    required = ["Accuracy", "Macro_F1", "Weighted_F1", "Inference_Time"]
    for k in required:
        assert k in metrics, f"Missing metric: {k}"
    assert 0 <= metrics["Accuracy"] <= 1
