from __future__ import annotations

import json
from pathlib import Path

from website_trust_assessment.research import dataset, training
from website_trust_assessment.scoring.model import FEATURE_GROUPS, FEATURE_SCHEMA_VERSION, LinearModel

from .factories import make_assessment


def _make_dataset(root: Path) -> Path:
    count = 80
    assessments = [
        make_assessment(
            f"train{index}.com",
            malicious=index % 2 == 1,
            minutes_ago=index,
        )
        for index in range(count)
    ]
    labels = {
        f"train{index}.com": {
            "domain": f"train{index}.com",
            "label": "malicious" if index % 2 else "benign",
            "source": "synthetic",
            "confidence": 1.0,
            "note": "",
        }
        for index in range(count)
    }
    dataset.build_dataset(assessments, labels, root / "dataset", seed=13)
    return root / "dataset" / "dataset.jsonl"


def test_training_protocol_writes_report_and_artifact(tmp_path: Path) -> None:
    dataset_path = _make_dataset(tmp_path)
    results = training.train_run(
        dataset_path,
        tmp_path / "runs",
        groups=["hybrid"],
        seed=13,
        bootstrap=30,
        cv_folds=2,
    )
    run_dir = Path(results["run_dir"])
    assert (run_dir / "run.json").exists()
    assert (run_dir / "report.md").exists()
    group = results["groups"]["hybrid"]
    artifact = Path(group["artifact"])
    assert artifact.exists()
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    assert payload["feature_group"] == "hybrid"
    assert payload["feature_schema_version"] == FEATURE_SCHEMA_VERSION
    assert len(payload["feature_names"]) == len(FEATURE_GROUPS["hybrid"])
    assert payload["calibration"]["method"] == "platt_logit"
    loaded = LinearModel.load(artifact)
    assert loaded is not None
    assert loaded.feature_group == "hybrid"
    assert loaded.calibration["method"] == "platt_logit"
    probability = loaded.probability({name: 0.0 for name in loaded.feature_names})
    assert 0.0 <= probability <= 1.0
    for model_name in ("rule_engine", "logistic_regression", "hist_gradient_boosting"):
        model_result = group["models"][model_name]
        assert "test" in model_result
        assert "test_raw" in model_result
        assert model_result["test"]["n"] == group["splits"]["test"]["samples"]
        assert model_result["test"]["roc_auc"] is not None
    logistic = group["models"]["logistic_regression"]
    assert logistic["cv"]["folds_completed"] >= 1
    assert logistic["top_coefficients"]
    assert group["models"]["hist_gradient_boosting"]["cv"]["folds_completed"] >= 1


def test_saved_artifact_can_be_evaluated_again(tmp_path: Path) -> None:
    dataset_path = _make_dataset(tmp_path)
    results = training.train_run(
        dataset_path,
        tmp_path / "runs",
        groups=["hybrid"],
        seed=21,
        bootstrap=10,
        cv_folds=2,
    )
    artifact = results["groups"]["hybrid"]["artifact"]
    report = training.evaluate_artifact(
        Path(artifact), dataset_path, split="test", bootstrap=10, seed=21
    )
    assert report["samples"] == results["groups"]["hybrid"]["splits"]["test"]["samples"]
    assert report["metrics"]["roc_auc"] is not None
    assert 0.0 <= report["metrics"]["brier"] <= 1.0
    assert report["bootstrap"]["roc_auc"]["point"] is not None
