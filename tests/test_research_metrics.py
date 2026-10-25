from __future__ import annotations

import math

from trustlens.research import metrics


def test_ranking_metrics_handle_perfect_reversed_and_tied_scores() -> None:
    y = [0, 0, 1, 1]
    assert metrics.roc_auc(y, [0.1, 0.2, 0.8, 0.9]) == 1.0
    assert metrics.roc_auc(y, [0.9, 0.8, 0.2, 0.1]) == 0.0
    assert metrics.roc_auc(y, [0.5, 0.5, 0.5, 0.5]) == 0.5
    assert metrics.roc_auc([0, 0, 0], [0.1, 0.2, 0.3]) is None
    assert metrics.average_precision(y, [0.1, 0.2, 0.8, 0.9]) == 1.0


def test_brier_calibration_and_confusion_metrics() -> None:
    y = [0, 0, 1, 1]
    scores = [0.1, 0.2, 0.8, 0.9]
    assert math.isclose(metrics.brier_score(y, scores), 0.025, rel_tol=1e-9)
    table = metrics.calibration_table(y, scores, bins=10)
    assert math.isclose(table["ece"], 0.15, rel_tol=1e-9)
    assert math.isclose(table["mce"], 0.2, rel_tol=1e-9)
    summary = metrics.binary_metrics(y, scores, 0.5)
    assert summary["f1"] == 1.0
    assert summary["precision"] == 1.0
    assert summary["recall"] == 1.0
    assert summary["confusion"] == {"tp": 2, "fp": 0, "tn": 2, "fn": 0}


def test_threshold_selection_and_risk_coverage() -> None:
    y = [0, 0, 1, 1]
    scores = [0.1, 0.2, 0.8, 0.9]
    threshold = metrics.select_threshold(y, scores)
    assert threshold == 0.5
    coverage = metrics.risk_coverage(y, scores, coverages=(0.5, 1.0))
    assert coverage[0]["coverage_actual"] == 0.5
    assert coverage[0]["accuracy"] == 1.0
    assert coverage[1]["accuracy"] == 1.0


def test_grouped_bootstrap_returns_intervals() -> None:
    y = [0, 0, 1, 1, 0, 1, 0, 1, 0, 1]
    scores = [0.1, 0.2, 0.8, 0.9, 0.15, 0.7, 0.3, 0.85, 0.05, 0.6]
    domains = [f"d{index // 2}.com" for index in range(10)]
    result = metrics.bootstrap_metric_cis(y, scores, domains, n_boot=40, seed=3)
    assert result["roc_auc"]["point"] is not None
    assert result["roc_auc"]["n_valid"] > 0
    if result["roc_auc"]["low"] is not None:
        assert result["roc_auc"]["low"] <= result["roc_auc"]["high"]


def test_metric_input_validation() -> None:
    try:
        metrics.roc_auc([0, 1], [0.5])
    except ValueError as exc:
        assert "same length" in str(exc)
    else:
        raise AssertionError("mismatched lengths should fail")
