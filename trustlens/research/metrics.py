"""Dependency-light evaluation metrics for binary trust classification.

These implementations are small enough to audit and avoid tying the paper's
numbers to a particular library version. Training uses scikit-learn; every
reported metric is computed here.
"""

from __future__ import annotations

import math
from typing import Any, Iterable, Sequence

import numpy as np


def _arrays(y_true: Iterable[Any], y_score: Iterable[Any]) -> tuple[np.ndarray, np.ndarray]:
    y = np.asarray(list(y_true), dtype=int).ravel()
    scores = np.asarray(list(y_score), dtype=float).ravel()
    if y.size != scores.size:
        raise ValueError("y_true and y_score must have the same length")
    if y.size == 0:
        raise ValueError("at least one sample is required")
    if not np.all(np.isfinite(scores)):
        raise ValueError("y_score contains a non-finite value")
    return y, np.clip(scores, 0.0, 1.0)


def roc_auc(y_true: Iterable[Any], y_score: Iterable[Any]) -> float | None:
    y, scores = _arrays(y_true, y_score)
    positives = int(y.sum())
    negatives = int(y.size - positives)
    if positives == 0 or negatives == 0:
        return None
    order = np.argsort(scores, kind="mergesort")
    sorted_scores = scores[order]
    ranks = np.empty(y.size, dtype=float)
    start = 0
    while start < y.size:
        end = start + 1
        while end < y.size and sorted_scores[end] == sorted_scores[start]:
            end += 1
        ranks[order[start:end]] = (start + 1 + end) / 2.0
        start = end
    auc = (ranks[y == 1].sum() - positives * (positives + 1) / 2.0) / (
        positives * negatives
    )
    return round(float(auc), 6)


def average_precision(y_true: Iterable[Any], y_score: Iterable[Any]) -> float | None:
    y, scores = _arrays(y_true, y_score)
    positives = int(y.sum())
    if positives == 0:
        return None
    order = np.argsort(-scores, kind="mergesort")
    ranked = y[order]
    true_positives = np.cumsum(ranked)
    precision = true_positives / np.arange(1, y.size + 1)
    recall = true_positives / positives
    increments = np.diff(np.concatenate(([0.0], recall)))
    return round(float(np.sum(precision * increments)), 6)


def brier_score(y_true: Iterable[Any], y_score: Iterable[Any]) -> float:
    y, scores = _arrays(y_true, y_score)
    return round(float(np.mean((scores - y) ** 2)), 6)


def log_loss(y_true: Iterable[Any], y_score: Iterable[Any]) -> float:
    y, scores = _arrays(y_true, y_score)
    clipped = np.clip(scores, 1e-12, 1.0 - 1e-12)
    value = -np.mean(y * np.log(clipped) + (1 - y) * np.log(1.0 - clipped))
    return round(float(value), 6)


def confusion_matrix(
    y_true: Iterable[Any], y_score: Iterable[Any], threshold: float = 0.5
) -> dict[str, int]:
    y, scores = _arrays(y_true, y_score)
    predicted = scores >= threshold
    actual = y == 1
    return {
        "tp": int(np.sum(predicted & actual)),
        "fp": int(np.sum(predicted & ~actual)),
        "tn": int(np.sum(~predicted & ~actual)),
        "fn": int(np.sum(~predicted & actual)),
    }


def binary_metrics(
    y_true: Iterable[Any], y_score: Iterable[Any], threshold: float = 0.5
) -> dict[str, Any]:
    y, scores = _arrays(y_true, y_score)
    cells = confusion_matrix(y, scores, threshold)
    tp, fp, tn, fn = cells["tp"], cells["fp"], cells["tn"], cells["fn"]
    positives = tp + fn
    negatives = tn + fp
    predicted_positive = tp + fp
    precision = tp / predicted_positive if predicted_positive else 0.0
    recall = tp / positives if positives else 0.0
    specificity = tn / negatives if negatives else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / y.size
    balanced = (recall + specificity) / 2.0 if positives and negatives else None
    denominator = math.sqrt(
        (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    )
    mcc = ((tp * tn) - (fp * fn)) / denominator if denominator else 0.0
    return {
        "n": int(y.size),
        "positives": positives,
        "negatives": negatives,
        "predicted_positive": predicted_positive,
        "accuracy": round(float(accuracy), 6),
        "balanced_accuracy": round(float(balanced), 6) if balanced is not None else None,
        "precision": round(float(precision), 6),
        "recall": round(float(recall), 6),
        "specificity": round(float(specificity), 6),
        "f1": round(float(f1), 6),
        "mcc": round(float(mcc), 6),
        "brier": brier_score(y, scores),
        "log_loss": log_loss(y, scores),
        "mean_score": round(float(np.mean(scores)), 6),
        "threshold": round(float(threshold), 6),
        "confusion": cells,
    }


def calibration_table(
    y_true: Iterable[Any], y_score: Iterable[Any], bins: int = 10
) -> dict[str, Any]:
    y, scores = _arrays(y_true, y_score)
    bins = max(2, int(bins))
    indexes = np.minimum((scores * bins).astype(int), bins - 1)
    table: list[dict[str, Any]] = []
    ece = 0.0
    mce = 0.0
    for index in range(bins):
        mask = indexes == index
        count = int(mask.sum())
        if count == 0:
            continue
        confidence = float(np.mean(scores[mask]))
        accuracy = float(np.mean(y[mask]))
        gap = abs(confidence - accuracy)
        ece += (count / y.size) * gap
        mce = max(mce, gap)
        table.append(
            {
                "lower": round(index / bins, 3),
                "upper": round((index + 1) / bins, 3),
                "count": count,
                "mean_confidence": round(confidence, 6),
                "accuracy": round(accuracy, 6),
                "gap": round(gap, 6),
            }
        )
    return {
        "ece": round(float(ece), 6),
        "mce": round(float(mce), 6),
        "bins": table,
    }


def select_threshold(y_true: Iterable[Any], y_score: Iterable[Any]) -> float:
    """Choose the max-F1 threshold, breaking ties toward the least extreme cutoff."""
    y, scores = _arrays(y_true, y_score)
    candidates = np.unique(np.concatenate(([0.0, 0.5, 1.0], scores)))
    best_threshold = 0.5
    best_f1 = -1.0
    for threshold in candidates:
        cells = confusion_matrix(y, scores, float(threshold))
        tp, fp, fn = cells["tp"], cells["fp"], cells["fn"]
        denominator = 2 * tp + fp + fn
        f1 = (2 * tp / denominator) if denominator else 0.0
        closer = abs(float(threshold) - 0.5) < abs(best_threshold - 0.5)
        if f1 > best_f1 + 1e-12 or (abs(f1 - best_f1) <= 1e-12 and closer):
            best_f1 = f1
            best_threshold = float(threshold)
    return round(best_threshold, 6)


def risk_coverage(
    y_true: Iterable[Any],
    y_score: Iterable[Any],
    *,
    coverages: Sequence[float] = (0.5, 0.8, 1.0),
    confidences: Iterable[Any] | None = None,
) -> list[dict[str, Any]]:
    y, scores = _arrays(y_true, y_score)
    if confidences is None:
        confidence_values = np.maximum(scores, 1.0 - scores)
    else:
        confidence_values = np.asarray(list(confidences), dtype=float).ravel()
        if confidence_values.size != y.size:
            raise ValueError("confidences must have the same length as y_true")
    order = np.argsort(-confidence_values, kind="mergesort")
    rows: list[dict[str, Any]] = []
    for fraction in coverages:
        fraction = max(0.0, min(1.0, float(fraction)))
        count = max(1, min(y.size, int(round(fraction * y.size))))
        indexes = order[:count]
        accuracy = float(np.mean((scores[indexes] >= 0.5) == (y[indexes] == 1)))
        rows.append(
            {
                "coverage_requested": round(float(fraction), 3),
                "coverage_actual": round(count / y.size, 3),
                "n": count,
                "accuracy": round(accuracy, 6),
                "error_rate": round(1.0 - accuracy, 6),
                "mean_score": round(float(np.mean(scores[indexes])), 6),
                "positives": int(np.sum(y[indexes])),
            }
        )
    return rows


def bootstrap_metric_cis(
    y_true: Iterable[Any],
    y_score: Iterable[Any],
    domains: Iterable[str],
    *,
    n_boot: int = 1000,
    seed: int = 42,
) -> dict[str, dict[str, Any]]:
    """Domain-grouped bootstrap confidence intervals for the headline metrics."""
    y, scores = _arrays(y_true, y_score)
    domain_values = np.asarray([str(value) for value in domains])
    if domain_values.size != y.size:
        raise ValueError("domains must have the same length as y_true")
    unique_domains = np.unique(domain_values)
    index_by_domain = {
        domain: np.flatnonzero(domain_values == domain) for domain in unique_domains
    }
    point = {
        "roc_auc": roc_auc(y, scores),
        "average_precision": average_precision(y, scores),
        "brier": brier_score(y, scores),
        "ece": calibration_table(y, scores)["ece"],
    }
    collected: dict[str, list[float]] = {name: [] for name in point}
    rng = np.random.default_rng(seed)
    for _ in range(max(0, int(n_boot))):
        picked = rng.choice(unique_domains, size=unique_domains.size, replace=True)
        indexes = np.concatenate([index_by_domain[domain] for domain in picked])
        sample_y = y[indexes]
        sample_scores = scores[indexes]
        if int(sample_y.sum()) in {0, sample_y.size}:
            continue
        values = {
            "roc_auc": roc_auc(sample_y, sample_scores),
            "average_precision": average_precision(sample_y, sample_scores),
            "brier": brier_score(sample_y, sample_scores),
            "ece": calibration_table(sample_y, sample_scores)["ece"],
        }
        for name, value in values.items():
            if value is not None:
                collected[name].append(float(value))
    result: dict[str, dict[str, Any]] = {}
    for name, value in point.items():
        samples = collected[name]
        entry: dict[str, Any] = {
            "point": value,
            "low": None,
            "high": None,
            "n_valid": len(samples),
        }
        if len(samples) >= 20:
            entry["low"] = round(float(np.percentile(samples, 2.5)), 6)
            entry["high"] = round(float(np.percentile(samples, 97.5)), 6)
        result[name] = entry
    return result


def summarise(
    y_true: Iterable[Any], y_score: Iterable[Any], threshold: float = 0.5
) -> dict[str, Any]:
    y, scores = _arrays(y_true, y_score)
    table = calibration_table(y, scores)
    return {
        "roc_auc": roc_auc(y, scores),
        "average_precision": average_precision(y, scores),
        "brier": brier_score(y, scores),
        "log_loss": log_loss(y, scores),
        "ece": table["ece"],
        "mce": table["mce"],
        **binary_metrics(y, scores, threshold),
    }


def format_metric(value: Any, digits: int = 3) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)
