from __future__ import annotations

import pytest

from website_trust_assessment.research.training import learning_curve
from website_trust_assessment.scoring.model import FEATURE_GROUPS

SIGNAL = FEATURE_GROUPS["url"][0]


def _rows(positives: int = 20, negatives: int = 20) -> list[dict]:
    rows = []
    for index in range(positives):
        rows.append(
            {
                "domain": f"pos{index}.example",
                "target": 1,
                "split": "train",
                "features": {SIGNAL: 1.0 + 0.01 * index},
            }
        )
    for index in range(negatives):
        rows.append(
            {
                "domain": f"neg{index}.example",
                "target": 0,
                "split": "train",
                "features": {SIGNAL: 0.01 * index},
            }
        )
    return rows


def test_learning_curve_is_deterministic_and_domain_grouped() -> None:
    rows = _rows()
    kwargs = {"fractions": (0.5, 1.0), "repeats": 2, "folds": 2, "seed": 7}
    first = learning_curve(rows, **kwargs)
    second = learning_curve(rows, **kwargs)
    assert first == second
    assert "test split is never scored" in first["protocol"]
    assert first["folds"] == 2

    half, full = first["points"]
    assert full["n_train_domains_mean"] > half["n_train_domains_mean"]
    assert full["auroc"]["mean"] is not None
    assert full["auroc"]["mean"] >= 0.8
    assert first["gain_from_half_to_full"] == round(
        full["auroc"]["mean"] - half["auroc"]["mean"], 6
    )


def test_learning_curve_rejects_mixed_label_domains() -> None:
    rows = []
    for index in range(4):
        rows.append(
            {
                "domain": f"mixed{index}.example",
                "target": 1,
                "split": "train",
                "features": {SIGNAL: 1.0},
            }
        )
        rows.append(
            {
                "domain": f"mixed{index}.example",
                "target": 0,
                "split": "train",
                "features": {SIGNAL: 0.0},
            }
        )
    with pytest.raises(ValueError, match="one label per domain"):
        learning_curve(rows, fractions=(1.0,), repeats=1, folds=2, seed=3)


def test_learning_curve_rejects_invalid_fractions() -> None:
    with pytest.raises(ValueError, match="fractions"):
        learning_curve(_rows(), fractions=(0.0, 1.0), repeats=1, folds=2)
