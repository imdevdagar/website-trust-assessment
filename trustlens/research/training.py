"""Leakage-safe model training, calibration, held-out testing, and research reports.

Protocol:

1. fit candidate models on the training split only;
2. run domain-grouped cross-validation on the training split for variability;
3. fit Platt calibration and choose the decision threshold on validation;
4. evaluate once on the untouched test split;
5. save a JSON logistic artifact for reproducible offline scoring.

The rule engine is a fixed baseline. It is also Platt-calibrated on validation
so that Brier and ECE comparisons are not rigged in favour of learned models.
"""

from __future__ import annotations

import json
import math
import warnings as warnings_module
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np

from ..scoring.model import FEATURE_GROUPS, FEATURE_SCHEMA_VERSION
from . import metrics
from .dataset import SPLITS, load_dataset, subset

MODEL_LABELS = {
    "rule_engine": "Rule engine",
    "logistic_regression": "Logistic regression",
    "hist_gradient_boosting": "HistGradientBoosting",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sigmoid(values: np.ndarray) -> np.ndarray:
    clipped = np.clip(values, -60.0, 60.0)
    return 1.0 / (1.0 + np.exp(-clipped))


def _logit(values: np.ndarray) -> np.ndarray:
    probabilities = np.clip(np.asarray(values, dtype=float), 1e-6, 1.0 - 1e-6)
    return np.log(probabilities / (1.0 - probabilities))


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        return float(value)
    if isinstance(value, np.ndarray):
        return [_json_safe(item) for item in value.tolist()]
    return value


@dataclass
class SplitData:
    samples: list[dict[str, Any]]
    X: np.ndarray
    y: np.ndarray
    groups: np.ndarray

    def __len__(self) -> int:
        return len(self.samples)

    @property
    def domains(self) -> int:
        return len(set(self.groups.tolist()))


def _design(samples: Sequence[dict[str, Any]], group: str) -> SplitData:
    names = FEATURE_GROUPS[group]
    X = np.asarray(
        [
            [float(sample.get("features", {}).get(name, 0.0)) for name in names]
            for sample in samples
        ],
        dtype=float,
    )
    if X.ndim == 1:
        X = X.reshape(len(samples), -1)
    y = np.asarray([int(sample["target"]) for sample in samples], dtype=int)
    groups = np.asarray([str(sample["domain"]) for sample in samples])
    return SplitData(list(samples), X, y, groups)


def _rule_scores(samples: Sequence[dict[str, Any]]) -> np.ndarray:
    return np.asarray(
        [float(sample.get("features", {}).get("overall_rule_risk", 0.0)) for sample in samples],
        dtype=float,
    )


def _rule_confidences(samples: Sequence[dict[str, Any]]) -> np.ndarray:
    return np.asarray(
        [float(sample.get("features", {}).get("overall_confidence", 0.0)) for sample in samples],
        dtype=float,
    )


@dataclass
class PlattCalibrator:
    slope: float = 1.0
    intercept: float = 0.0
    fitted: bool = False
    warning: str = ""

    def apply(self, scores: Sequence[float] | np.ndarray) -> np.ndarray:
        values = np.asarray(list(scores), dtype=float)
        if not self.fitted:
            return np.clip(values, 0.0, 1.0)
        return _sigmoid(self.slope * _logit(values) + self.intercept)

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": "platt_logit",
            "input_transform": "logit",
            "slope": round(float(self.slope), 8),
            "intercept": round(float(self.intercept), 8),
            "fitted": self.fitted,
            "warning": self.warning,
        }


def fit_calibrator(scores: Sequence[float] | np.ndarray, y: Sequence[int] | np.ndarray) -> PlattCalibrator:
    values = np.asarray(list(scores), dtype=float)
    targets = np.asarray(list(y), dtype=int)
    if len(set(targets.tolist())) < 2:
        return PlattCalibrator(warning="validation split contains a single class; calibration skipped")
    transformed = _logit(values)
    if float(np.std(transformed)) < 1e-9:
        return PlattCalibrator(warning="validation scores are constant; calibration skipped")
    from sklearn.linear_model import LogisticRegression

    try:
        with warnings_module.catch_warnings():
            warnings_module.simplefilter("ignore")
            model = LogisticRegression(C=1.0, solver="lbfgs", max_iter=1000)
            model.fit(transformed.reshape(-1, 1), targets)
        slope = float(model.coef_[0][0])
        intercept = float(model.intercept_[0])
    except Exception as exc:
        return PlattCalibrator(warning=f"calibration failed: {type(exc).__name__}: {str(exc)[:160]}")
    if not math.isfinite(slope) or not math.isfinite(intercept) or slope <= 0:
        return PlattCalibrator(
            warning="validation scores were not positively associated with labels; calibration skipped"
        )
    return PlattCalibrator(slope=slope, intercept=intercept, fitted=True)


def _fit_logistic(X: np.ndarray, y: np.ndarray, seed: int):
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    pipeline = Pipeline(
        [
            ("scaler", StandardScaler()),
            (
                "clf",
                LogisticRegression(
                    C=1.0,
                    class_weight="balanced",
                    max_iter=3000,
                    solver="lbfgs",
                    random_state=seed,
                ),
            ),
        ]
    )
    pipeline.fit(X, y)
    return pipeline


def _balanced_weights(y: np.ndarray) -> np.ndarray:
    classes, counts = np.unique(y, return_counts=True)
    weights = {int(label): len(y) / (len(classes) * count) for label, count in zip(classes, counts)}
    return np.asarray([weights[int(label)] for label in y], dtype=float)


def _fit_hgb(X: np.ndarray, y: np.ndarray, seed: int):
    from sklearn.ensemble import HistGradientBoostingClassifier

    small = len(y) < 100
    model = HistGradientBoostingClassifier(
        max_iter=150 if small else 300,
        learning_rate=0.06,
        max_leaf_nodes=7 if small else 15,
        min_samples_leaf=5 if small else 10,
        l2_regularization=1.0,
        early_stopping=False,
        random_state=seed,
    )
    model.fit(X, y, sample_weight=_balanced_weights(y))
    return model


def _predict(model: Any, X: np.ndarray) -> np.ndarray:
    return np.asarray(model.predict_proba(X)[:, 1], dtype=float)


def _grouped_cv(
    kind: str,
    X: np.ndarray,
    y: np.ndarray,
    groups: np.ndarray,
    *,
    seed: int,
    folds: int,
) -> dict[str, Any]:
    from sklearn.model_selection import StratifiedGroupKFold

    unique_groups = len(set(groups.tolist()))
    class_counts = np.bincount(y, minlength=2)
    usable_folds = min(int(folds), unique_groups, int(class_counts.min()))
    if usable_folds < 2:
        return {
            "folds_requested": int(folds),
            "folds_completed": 0,
            "warning": "not enough groups or minority-class samples for grouped cross-validation",
            "mean": {},
            "std": {},
            "per_fold": [],
        }
    splitter = StratifiedGroupKFold(
        n_splits=usable_folds, shuffle=True, random_state=seed
    )
    per_fold: list[dict[str, Any]] = []
    for fold_index, (train_index, test_index) in enumerate(
        splitter.split(X, y, groups), start=1
    ):
        if len(set(y[train_index].tolist())) < 2 or len(test_index) == 0:
            continue
        try:
            model = _fit_logistic(X[train_index], y[train_index], seed) if kind == "logistic" else _fit_hgb(
                X[train_index], y[train_index], seed
            )
            predictions = _predict(model, X[test_index])
            summary = metrics.summarise(y[test_index], predictions)
            per_fold.append(
                {
                    "fold": fold_index,
                    "n": int(len(test_index)),
                    "roc_auc": summary["roc_auc"],
                    "average_precision": summary["average_precision"],
                    "brier": summary["brier"],
                    "ece": summary["ece"],
                }
            )
        except Exception as exc:
            per_fold.append(
                {
                    "fold": fold_index,
                    "error": f"{type(exc).__name__}: {str(exc)[:200]}",
                }
            )
    completed = [fold for fold in per_fold if "error" not in fold]
    mean: dict[str, float | None] = {}
    std: dict[str, float | None] = {}
    for name in ("roc_auc", "average_precision", "brier", "ece"):
        values = [float(fold[name]) for fold in completed if fold.get(name) is not None]
        mean[name] = round(float(np.mean(values)), 6) if values else None
        std[name] = round(float(np.std(values)), 6) if values else None
    return {
        "folds_requested": int(folds),
        "folds_completed": len(completed),
        "warning": None if completed else "no fold completed successfully",
        "mean": mean,
        "std": std,
        "per_fold": per_fold,
    }


def _domain_labels(groups: np.ndarray, y: np.ndarray) -> dict[str, int]:
    labels: dict[str, set[int]] = {}
    for group, target in zip(groups.tolist(), y.tolist()):
        labels.setdefault(str(group), set()).add(int(target))
    mixed = {group: sorted(values) for group, values in labels.items() if len(values) > 1}
    if mixed:
        raise ValueError(
            "domain-grouped subsampling requires one label per domain; mixed: "
            + ", ".join(sorted(mixed)[:5])
        )
    return {group: next(iter(values)) for group, values in labels.items()}


def _subsample_domains(
    train_index: np.ndarray,
    y: np.ndarray,
    groups: np.ndarray,
    fraction: float,
    rng: np.random.Generator,
) -> np.ndarray:
    """Selects whole domains, stratified by class, so a fraction never splits a domain."""
    index = np.asarray(train_index, dtype=int)
    domain_labels = _domain_labels(groups[index], y[index])
    by_class: dict[int, list[str]] = {0: [], 1: []}
    for domain, target in domain_labels.items():
        by_class[target].append(domain)
    selected: set[str] = set()
    for target, domains in by_class.items():
        pools = sorted(domains)
        take = min(len(pools), max(2, int(round(fraction * len(pools)))))
        if take < len(pools):
            choice = rng.choice(np.asarray(pools, dtype=object), size=take, replace=False)
            selected.update(str(item) for item in choice.tolist())
        else:
            selected.update(pools)
    keep = np.asarray([str(group) in selected for group in groups[index].tolist()])
    return index[keep]


def learning_curve(
    samples: Sequence[dict[str, Any]],
    *,
    group: str = "hybrid",
    model: str = "logistic",
    fractions: Sequence[float] = (0.1, 0.25, 0.5, 0.75, 1.0),
    repeats: int = 20,
    folds: int = 5,
    seed: int = 42,
) -> dict[str, Any]:
    """Train-only learning curve over domain-grouped cross-validation.

    The test split is never scored. Each repeat re-draws the grouped folds; within a
    fold, whole domains are subsampled per class, so a fraction never splits a domain.
    Pooled out-of-fold predictions at fraction 1.0 are the ordinary grouped CV estimate.
    """
    if model not in ("logistic", "hgb"):
        raise ValueError(f"unknown model: {model}")
    data = _design(samples, group)
    if len(set(data.y.tolist())) < 2:
        raise ValueError("learning curve needs both classes")
    fractions = [float(value) for value in fractions]
    if not fractions or any(value <= 0 or value > 1 for value in fractions):
        raise ValueError("fractions must be in (0, 1]")
    from sklearn.model_selection import StratifiedGroupKFold

    class_counts = np.bincount(data.y, minlength=2)
    usable_folds = min(int(folds), data.domains, int(class_counts.min()))
    if usable_folds < 2:
        raise ValueError("not enough domains or minority samples for grouped folds")
    if repeats < 1:
        raise ValueError("repeats must be at least 1")

    curve: dict[str, dict[str, list[float] | list[int]]] = {
        f"{fraction:.2f}": {
            "auroc": [],
            "average_precision": [],
            "n_train_samples": [],
            "n_train_domains": [],
        }
        for fraction in fractions
    }
    for repeat in range(repeats):
        splitter = StratifiedGroupKFold(
            n_splits=usable_folds, shuffle=True, random_state=seed + repeat
        )
        predictions = {fraction: np.full(len(data.y), np.nan) for fraction in fractions}
        for fold_index, (train_index, test_index) in enumerate(
            splitter.split(data.X, data.y, data.groups)
        ):
            if len(test_index) == 0 or len(set(data.y[train_index].tolist())) < 2:
                continue
            for fraction in fractions:
                rng = np.random.default_rng(
                    [seed, repeat, fold_index, int(round(fraction * 10_000))]
                )
                subset = _subsample_domains(
                    np.asarray(train_index), data.y, data.groups, fraction, rng
                )
                if len(set(data.y[subset].tolist())) < 2:
                    continue
                fitted = (
                    _fit_logistic(data.X[subset], data.y[subset], seed)
                    if model == "logistic"
                    else _fit_hgb(data.X[subset], data.y[subset], seed)
                )
                predictions[fraction][test_index] = _predict(fitted, data.X[test_index])
                curve[f"{fraction:.2f}"]["n_train_samples"].append(int(len(subset)))
                curve[f"{fraction:.2f}"]["n_train_domains"].append(
                    len(set(data.groups[subset].tolist()))
                )
        for fraction in fractions:
            mask = ~np.isnan(predictions[fraction])
            if int(mask.sum()) < 10:
                continue
            curve[f"{fraction:.2f}"]["auroc"].append(
                metrics.roc_auc(data.y[mask], predictions[fraction][mask])
            )
            curve[f"{fraction:.2f}"]["average_precision"].append(
                metrics.average_precision(data.y[mask], predictions[fraction][mask])
            )

    def aggregate(values: Sequence[float | None]) -> dict[str, Any]:
        clean = [float(value) for value in values if value is not None]
        if not clean:
            return {"mean": None, "sd": None, "ci": [None, None]}
        array = np.asarray(clean, dtype=float)
        return {
            "mean": round(float(array.mean()), 6),
            "sd": round(float(array.std(ddof=1)) if len(array) > 1 else 0.0, 6),
            "ci": [
                round(float(np.percentile(array, 2.5)), 6),
                round(float(np.percentile(array, 97.5)), 6),
            ],
        }

    points: list[dict[str, Any]] = []
    for fraction in fractions:
        key = f"{fraction:.2f}"
        block = curve[key]
        auroc = aggregate(block["auroc"])
        auprc = aggregate(block["average_precision"])
        points.append(
            {
                "fraction": fraction,
                "repeats_completed": len(block["auroc"]),
                "auroc": auroc,
                "average_precision": auprc,
                "n_train_samples_mean": round(float(np.mean(block["n_train_samples"])), 1)
                if block["n_train_samples"]
                else None,
                "n_train_domains_mean": round(float(np.mean(block["n_train_domains"])), 1)
                if block["n_train_domains"]
                else None,
            }
        )
    full = points[-1]["auroc"]["mean"] if points else None
    half = next(
        (point["auroc"]["mean"] for point in points if abs(point["fraction"] - 0.5) < 1e-9),
        None,
    )
    return {
        "protocol": "train-only domain-grouped cross-validation; the test split is never scored",
        "feature_group": group,
        "model": model,
        "folds": usable_folds,
        "repeats": repeats,
        "seed": seed,
        "samples": len(data),
        "domains": data.domains,
        "points": points,
        "gain_from_half_to_full": round(full - half, 6) if full is not None and half is not None else None,
    }


def _evaluate_predictions(
    y_val: np.ndarray,
    raw_val: np.ndarray,
    y_test: np.ndarray,
    raw_test: np.ndarray,
    test_groups: np.ndarray,
    *,
    bootstrap: int,
    seed: int,
) -> dict[str, Any]:
    calibrator = fit_calibrator(raw_val, y_val)
    calibrated_val = calibrator.apply(raw_val)
    calibrated_test = calibrator.apply(raw_test)
    raw_threshold = metrics.select_threshold(y_val, raw_val)
    threshold = metrics.select_threshold(y_val, calibrated_val)
    result: dict[str, Any] = {
        "calibration": calibrator.to_dict(),
        "threshold_raw": raw_threshold,
        "threshold": threshold,
        "test_raw": metrics.summarise(y_test, raw_test, raw_threshold),
        "test": metrics.summarise(y_test, calibrated_test, threshold),
        "risk_coverage": metrics.risk_coverage(y_test, calibrated_test),
        "reliability": metrics.calibration_table(y_test, calibrated_test)["bins"],
    }
    if bootstrap > 0:
        result["bootstrap"] = metrics.bootstrap_metric_cis(
            y_test, calibrated_test, test_groups, n_boot=bootstrap, seed=seed
        )
    return result


def _top_coefficients(model: Any, names: Sequence[str], limit: int = 20) -> list[dict[str, Any]]:
    coefficients = np.asarray(model.named_steps["clf"].coef_[0], dtype=float)
    order = np.argsort(-np.abs(coefficients))[:limit]
    return [
        {"feature": names[index], "coefficient": round(float(coefficients[index]), 6)}
        for index in order
    ]


def _permutation_importance(
    model: Any,
    X_val: np.ndarray,
    y_val: np.ndarray,
    names: Sequence[str],
    *,
    seed: int,
    limit: int = 15,
) -> list[dict[str, Any]]:
    if len(set(y_val.tolist())) < 2:
        return []
    from sklearn.inspection import permutation_importance

    try:
        with warnings_module.catch_warnings():
            warnings_module.simplefilter("ignore")
            importance = permutation_importance(
                model,
                X_val,
                y_val,
                scoring="roc_auc",
                n_repeats=5,
                random_state=seed,
            )
    except Exception:
        return []
    order = np.argsort(-importance.importances_mean)[:limit]
    return [
        {
            "feature": names[index],
            "importance": round(float(importance.importances_mean[index]), 6),
            "std": round(float(importance.importances_std[index]), 6),
        }
        for index in order
        if float(importance.importances_mean[index]) > 0
    ]


def _save_logistic_artifact(
    model_path: Path,
    model: Any,
    names: Sequence[str],
    group: str,
    result: Mapping[str, Any],
    *,
    dataset_path: Path,
    dataset_manifest: Mapping[str, Any],
    seed: int,
    run_id: str,
) -> Path:
    scaler = model.named_steps["scaler"]
    classifier = model.named_steps["clf"]
    coefficients = np.asarray(classifier.coef_[0], dtype=float)
    scale = np.asarray(scaler.scale_, dtype=float)
    scale = np.where(np.abs(scale) < 1e-12, 1.0, scale)
    means = np.asarray(scaler.mean_, dtype=float)
    raw_coefficients = coefficients / scale
    raw_intercept = float(classifier.intercept_[0]) - float(
        np.sum(coefficients * means / scale)
    )
    payload = {
        "model": "logistic_regression",
        "feature_group": group,
        "feature_names": list(names),
        "coefficients": [round(float(value), 10) for value in raw_coefficients],
        "intercept": round(raw_intercept, 10),
        "calibration": result.get("calibration"),
        "threshold": result.get("threshold"),
        "metrics": result.get("test"),
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "trained_at": _now(),
        "run_id": run_id,
        "seed": seed,
        "dataset": {
            "path": str(dataset_path),
            "sha256": (dataset_manifest.get("files", {}).get("dataset_jsonl") or {}).get("sha256"),
        },
        "standardized_coefficients": {
            name: round(float(value), 8) for name, value in zip(names, coefficients)
        },
    }
    model_path.parent.mkdir(parents=True, exist_ok=True)
    model_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return model_path


def _train_group(
    train: SplitData,
    val: SplitData,
    test: SplitData,
    group: str,
    *,
    seed: int,
    cv_folds: int,
    bootstrap: int,
) -> tuple[dict[str, Any], Any]:
    names = FEATURE_GROUPS[group]
    y_train, y_val, y_test = train.y, val.y, test.y
    if len(set(y_train.tolist())) < 2:
        raise ValueError("training split must contain both classes")
    warnings: list[str] = []
    if len(set(y_val.tolist())) < 2:
        warnings.append("validation split contains one class; threshold/calibration are weak")
    if len(set(y_test.tolist())) < 2:
        warnings.append("test split contains one class; AUROC and AUPRC are not estimable")
    if len(val) < 20 or len(test) < 20:
        warnings.append("validation or test split has fewer than 20 samples")

    rule_val = np.clip(_rule_scores(val.samples), 0.0, 1.0)
    rule_test = np.clip(_rule_scores(test.samples), 0.0, 1.0)
    rule_result = _evaluate_predictions(
        y_val,
        rule_val,
        y_test,
        rule_test,
        test.groups,
        bootstrap=bootstrap,
        seed=seed,
    )
    rule_result["name"] = "rule_engine"
    rule_result["model_label"] = MODEL_LABELS["rule_engine"]
    rule_result["cv"] = None
    rule_result["confidence_risk_coverage"] = metrics.risk_coverage(
        y_test,
        rule_test,
        confidences=_rule_confidences(test.samples),
    )

    logistic = _fit_logistic(train.X, y_train, seed)
    logistic_val = _predict(logistic, val.X)
    logistic_test = _predict(logistic, test.X)
    logistic_result = _evaluate_predictions(
        y_val,
        logistic_val,
        y_test,
        logistic_test,
        test.groups,
        bootstrap=bootstrap,
        seed=seed,
    )
    logistic_result["name"] = "logistic_regression"
    logistic_result["model_label"] = MODEL_LABELS["logistic_regression"]
    logistic_result["cv"] = _grouped_cv(
        "logistic", train.X, y_train, train.groups, seed=seed, folds=cv_folds
    )
    logistic_result["top_coefficients"] = _top_coefficients(logistic, names)

    hgb = _fit_hgb(train.X, y_train, seed)
    hgb_val = _predict(hgb, val.X)
    hgb_test = _predict(hgb, test.X)
    hgb_result = _evaluate_predictions(
        y_val,
        hgb_val,
        y_test,
        hgb_test,
        test.groups,
        bootstrap=bootstrap,
        seed=seed,
    )
    hgb_result["name"] = "hist_gradient_boosting"
    hgb_result["model_label"] = MODEL_LABELS["hist_gradient_boosting"]
    hgb_result["cv"] = _grouped_cv("hgb", train.X, y_train, train.groups, seed=seed, folds=cv_folds)
    hgb_result["permutation_importance"] = _permutation_importance(
        hgb, val.X, y_val, names, seed=seed
    )

    return (
        {
            "feature_group": group,
            "feature_count": len(names),
            "splits": {
                split: {
                    "samples": len(data),
                    "domains": data.domains,
                    "positives": int(data.y.sum()),
                }
                for split, data in (("train", train), ("val", val), ("test", test))
            },
            "models": {
                "rule_engine": rule_result,
                "logistic_regression": logistic_result,
                "hist_gradient_boosting": hgb_result,
            },
            "warnings": warnings,
        },
        logistic,
    )


def _validate_protocol(samples: Sequence[dict[str, Any]]) -> dict[str, SplitData]:
    splits = {split: subset(samples, split) for split in SPLITS}
    for split in ("train", "val", "test"):
        if not splits[split]:
            raise ValueError(
                f"{split} split is empty; rebuild the dataset with more labeled domains"
            )
    domains = {split: {row["domain"] for row in rows} for split, rows in splits.items()}
    for left, right in (("train", "val"), ("train", "test"), ("val", "test")):
        overlap = domains[left] & domains[right]
        if overlap:
            raise ValueError(
                f"{len(overlap)} domain(s) overlap between {left} and {right}; "
                "datasets must be grouped by domain"
            )
    return splits


def _format(value: Any, digits: int = 3) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def _row(label: str, result: Mapping[str, Any], calibrated: bool = True) -> str:
    summary = result["test"] if calibrated else result["test_raw"]
    return "| {label} | {auc} | {ap} | {brier} | {ece} | {f1} | {precision} | {recall} | {threshold} |".format(
        label=label,
        auc=_format(summary.get("roc_auc")),
        ap=_format(summary.get("average_precision")),
        brier=_format(summary.get("brier")),
        ece=_format(summary.get("ece")),
        f1=_format(summary.get("f1")),
        precision=_format(summary.get("precision")),
        recall=_format(summary.get("recall")),
        threshold=_format(summary.get("threshold")),
    )


def _write_report(
    path: Path,
    results: Mapping[str, Any],
    dataset_manifest: Mapping[str, Any],
) -> None:
    lines: list[str] = [
        f"# Website trust assessment research run {results['run_id']}",
        "",
        f"Generated: {results['created_at']}",
        "",
        "## Protocol",
        "",
        "- Models are fitted on the training split only.",
        "- The decision threshold and Platt calibration are selected on validation.",
        "- The test split is evaluated once and never used for fitting or selection.",
        "- All splits are grouped by registrable domain.",
        "- The rule engine is reported both as-is and after Platt calibration.",
        "- Metrics below are computed by `trustlens.research.metrics`.",
        "",
        "## Dataset",
        "",
        f"- Dataset: `{results['dataset']['path']}`",
        f"- SHA-256: `{results['dataset']['sha256']}`",
        f"- Feature schema: v{results['feature_schema_version']}",
        f"- Dataset split seed: {dataset_manifest.get('seed')}",
        f"- Training seed: {results['seed']}",
        "",
        "| Split | Samples | Domains | Benign | Malicious |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for split in SPLITS:
        info = dataset_manifest.get("splits", {}).get(split, {})
        labels = info.get("labels", {})
        lines.append(
            f"| {split} | {info.get('samples', 0)} | {info.get('domains', 0)} | "
            f"{labels.get('benign', 0)} | {labels.get('malicious', 0)} |"
        )
    if dataset_manifest.get("warnings"):
        lines.extend(["", "Dataset warnings:"])
        lines.extend(f"- {warning}" for warning in dataset_manifest["warnings"])

    for group, group_result in results["groups"].items():
        lines.extend(
            [
                "",
                f"## Feature group: `{group}` ({group_result['feature_count']} features)",
                "",
                "| Split | Samples | Domains | Positives |",
                "| --- | ---: | ---: | ---: |",
            ]
        )
        for split, info in group_result["splits"].items():
            lines.append(
                f"| {split} | {info['samples']} | {info['domains']} | {info['positives']} |"
            )
        lines.extend(
            [
                "",
                "### Test results",
                "",
                "| Model | AUROC | AUPRC | Brier | ECE | F1 | Precision | Recall | Threshold |",
                "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
                _row("Rule engine (raw)", group_result["models"]["rule_engine"], False),
                _row("Rule engine + Platt", group_result["models"]["rule_engine"]),
                _row(
                    "Logistic regression + Platt",
                    group_result["models"]["logistic_regression"],
                ),
                _row(
                    "HistGradientBoosting + Platt",
                    group_result["models"]["hist_gradient_boosting"],
                ),
                "",
                "Grouped bootstrap 95% CIs (calibrated test scores):",
                "",
                "| Model | AUROC [95% CI] | AUPRC [95% CI] | Brier [95% CI] |",
                "| --- | --- | --- | --- |",
            ]
        )
        for model_key in ("rule_engine", "logistic_regression", "hist_gradient_boosting"):
            model_result = group_result["models"][model_key]
            boot = model_result.get("bootstrap") or {}

            def interval(name: str) -> str:
                entry = boot.get(name) or {}
                if entry.get("low") is None:
                    return _format(entry.get("point"))
                return (
                    f"{_format(entry.get('point'))} "
                    f"[{_format(entry.get('low'))}, {_format(entry.get('high'))}]"
                )

            lines.append(
                f"| {MODEL_LABELS[model_key]} | {interval('roc_auc')} | "
                f"{interval('average_precision')} | {interval('brier')} |"
            )
        lines.extend(
            [
                "",
                "### Calibration effect on test",
                "",
                "| Model | Brier raw | Brier calibrated | ECE raw | ECE calibrated |",
                "| --- | ---: | ---: | ---: | ---: |",
            ]
        )
        for model_key in ("rule_engine", "logistic_regression", "hist_gradient_boosting"):
            model_result = group_result["models"][model_key]
            raw = model_result["test_raw"]
            calibrated = model_result["test"]
            lines.append(
                f"| {MODEL_LABELS[model_key]} | {_format(raw.get('brier'))} | "
                f"{_format(calibrated.get('brier'))} | {_format(raw.get('ece'))} | "
                f"{_format(calibrated.get('ece'))} |"
            )
        lines.extend(
            [
                "",
                "### Selective prediction (calibrated scores)",
                "",
                "| Model | Coverage | Accuracy | Error rate |",
                "| --- | ---: | ---: | ---: |",
            ]
        )
        for model_key in ("rule_engine", "logistic_regression", "hist_gradient_boosting"):
            for entry in group_result["models"][model_key].get("risk_coverage", []):
                lines.append(
                    f"| {MODEL_LABELS[model_key]} | {entry['coverage_actual']:.0%} | "
                    f"{entry['accuracy']:.3f} | {entry['error_rate']:.3f} |"
                )
        logistic = group_result["models"]["logistic_regression"]
        if logistic.get("top_coefficients"):
            lines.extend(
                [
                    "",
                    "### Logistic coefficients (standardized, largest magnitude)",
                    "",
                    "| Feature | Coefficient |",
                    "| --- | ---: |",
                ]
            )
            for item in logistic["top_coefficients"][:12]:
                lines.append(f"| `{item['feature']}` | {item['coefficient']:+.3f} |")
        hgb = group_result["models"]["hist_gradient_boosting"]
        if hgb.get("permutation_importance"):
            lines.extend(
                [
                    "",
                    "### HistGradientBoosting permutation importance (validation)",
                    "",
                    "| Feature | Mean AUROC drop | Std |",
                    "| --- | ---: | ---: |",
                ]
            )
            for item in hgb["permutation_importance"][:10]:
                lines.append(
                    f"| `{item['feature']}` | {item['importance']:.4f} | {item['std']:.4f} |"
                )
        lines.extend(
            [
                "",
                "### Grouped cross-validation (training split)",
                "",
                "| Model | Folds | AUROC | AUPRC | Brier | ECE |",
                "| --- | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for model_key in ("logistic_regression", "hist_gradient_boosting"):
            cv = group_result["models"][model_key]["cv"] or {}

            def cv_cell(name: str) -> str:
                mean = (cv.get("mean") or {}).get(name)
                std = (cv.get("std") or {}).get(name)
                if mean is None:
                    return "n/a"
                return f"{mean:.3f} ± {std:.3f}" if std is not None else f"{mean:.3f}"

            lines.append(
                f"| {MODEL_LABELS[model_key]} | {cv.get('folds_completed', 0)} | "
                f"{cv_cell('roc_auc')} | {cv_cell('average_precision')} | "
                f"{cv_cell('brier')} | {cv_cell('ece')} |"
            )
        if group_result["warnings"]:
            lines.extend(["", "Training warnings:"])
            lines.extend(f"- {warning}" for warning in group_result["warnings"])

    lines.extend(
        [
            "",
            "## Limitations",
            "",
            "- The dataset is a convenience sample of live sites, not a random sample of the web.",
            "- Labels are human judgments and may contain errors; reported agreement is in the run metadata.",
            "- Suspicious sites are excluded from the main binary task unless a sensitivity run is requested.",
            "- Site content and infrastructure change; results describe the collection window.",
            "- Automated assessment is advisory and cannot guarantee that a site is safe.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def train_run(
    dataset_path: Path,
    out_root: Path,
    *,
    groups: Sequence[str] = ("hybrid",),
    seed: int = 42,
    bootstrap: int = 1000,
    cv_folds: int = 5,
    model_dir: Path | None = None,
    run_name: str | None = None,
) -> dict[str, Any]:
    samples, manifest = load_dataset(dataset_path)
    splits = _validate_protocol(samples)
    if any(group == "all" for group in groups):
        groups = list(FEATURE_GROUPS)
    if not groups:
        groups = ["hybrid"]
    unknown = [group for group in groups if group not in FEATURE_GROUPS]
    if unknown:
        raise ValueError(f"unknown feature group(s): {', '.join(unknown)}")

    run_id = run_name or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = out_root / run_id
    suffix = 1
    base_dir = run_dir
    while run_dir.exists():
        run_dir = base_dir.with_name(f"{base_dir.name}-{suffix}")
        suffix += 1
    run_dir.mkdir(parents=True, exist_ok=False)
    model_dir = model_dir or (run_dir / "models")
    model_dir.mkdir(parents=True, exist_ok=True)

    results: dict[str, Any] = {
        "run_id": run_dir.name,
        "created_at": _now(),
        "seed": seed,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "dataset": {
            "path": str(dataset_path),
            "sha256": (manifest.get("files", {}).get("dataset_jsonl") or {}).get("sha256"),
            "split_seed": manifest.get("seed"),
        },
        "protocol": {
            "fit": "train",
            "threshold": "validation (max F1)",
            "calibration": "validation (Platt)",
            "evaluation": "test (once)",
            "grouping": "registrable domain",
            "cv_folds": cv_folds,
            "bootstrap": bootstrap,
        },
        "groups": {},
    }
    for group in groups:
        train_data = _design(splits["train"], group)
        val_data = _design(splits["val"], group)
        test_data = _design(splits["test"], group)
        group_result, logistic = _train_group(
            train_data,
            val_data,
            test_data,
            group,
            seed=seed,
            cv_folds=cv_folds,
            bootstrap=bootstrap,
        )
        results["groups"][group] = group_result
        logistic_result = group_result["models"]["logistic_regression"]
        artifact_path = model_dir / f"logistic_{group}.json"
        saved = _save_logistic_artifact(
            artifact_path,
            logistic,
            FEATURE_GROUPS[group],
            group,
            logistic_result,
            dataset_path=dataset_path,
            dataset_manifest=manifest,
            seed=seed,
            run_id=run_dir.name,
        )
        group_result["artifact"] = str(saved)

    results = _json_safe(results)
    (run_dir / "run.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    _write_report(run_dir / "report.md", results, manifest)
    results["run_dir"] = str(run_dir)
    return results


def evaluate_artifact(
    model_path: Path,
    dataset_path: Path,
    *,
    split: str = "test",
    bootstrap: int = 1000,
    seed: int = 42,
) -> dict[str, Any]:
    if split not in SPLITS:
        raise ValueError(f"split must be one of {', '.join(SPLITS)}")
    payload = json.loads(model_path.read_text(encoding="utf-8"))
    version = int(payload.get("feature_schema_version") or 0)
    if version != FEATURE_SCHEMA_VERSION:
        raise ValueError(
            f"model feature schema {version} does not match code {FEATURE_SCHEMA_VERSION}"
        )
    names = [str(name) for name in payload["feature_names"]]
    coefficients = np.asarray([float(value) for value in payload["coefficients"]], dtype=float)
    intercept = float(payload["intercept"])
    samples, manifest = load_dataset(dataset_path)
    rows = subset(samples, split)
    if not rows:
        raise ValueError(f"{split} split is empty")
    X = np.asarray(
        [[float(row.get("features", {}).get(name, 0.0)) for name in names] for row in rows],
        dtype=float,
    )
    y = np.asarray([int(row["target"]) for row in rows], dtype=int)
    groups = np.asarray([str(row["domain"]) for row in rows])
    raw = _sigmoid(intercept + X @ coefficients)
    calibration = payload.get("calibration") or {}
    if calibration.get("fitted"):
        transform = calibration.get("input_transform", "logit")
        base = _logit(raw) if transform == "logit" else raw
        scores = _sigmoid(
            float(calibration["slope"]) * base + float(calibration["intercept"])
        )
    else:
        scores = raw
    threshold = float(payload.get("threshold") or 0.5)
    result = {
        "model": str(payload.get("model") or "logistic_regression"),
        "feature_group": str(payload.get("feature_group") or ""),
        "model_path": str(model_path),
        "dataset": {
            "path": str(dataset_path),
            "sha256": (manifest.get("files", {}).get("dataset_jsonl") or {}).get("sha256"),
            "split_seed": manifest.get("seed"),
        },
        "split": split,
        "samples": len(rows),
        "domains": len(set(groups.tolist())),
        "threshold": threshold,
        "metrics": metrics.summarise(y, scores, threshold),
        "risk_coverage": metrics.risk_coverage(y, scores),
    }
    if bootstrap > 0:
        result["bootstrap"] = metrics.bootstrap_metric_cis(
            y, scores, groups, n_boot=bootstrap, seed=seed
        )
    return _json_safe(result)
