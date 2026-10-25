"""Optional, data-driven calibration of rule scores.

The rule score is not a probability. When a calibration artefact is produced by
the training pipeline, it maps scores to observed label frequencies. Without
one, calibrated values remain null rather than presenting an uncalibrated score
as a probability.
"""

from __future__ import annotations

import json
import math
from bisect import bisect_left
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Calibrator:
    method: str
    a: float = 1.0
    b: float = 0.0
    x: tuple[float, ...] = field(default_factory=tuple)
    y: tuple[float, ...] = field(default_factory=tuple)
    metrics: dict[str, Any] = field(default_factory=dict)

    def probability(self, score: float) -> float:
        score = max(0.0, min(100.0, float(score)))
        if self.method == "platt":
            value = 1.0 / (1.0 + math.exp(-(self.a * score + self.b)))
            return round(max(0.0, min(1.0, value)), 4)
        if self.method == "isotonic" and self.x and len(self.x) == len(self.y):
            if score <= self.x[0]:
                return round(max(0.0, min(1.0, self.y[0])), 4)
            if score >= self.x[-1]:
                return round(max(0.0, min(1.0, self.y[-1])), 4)
            index = bisect_left(self.x, score)
            left, right = index - 1, index
            span = self.x[right] - self.x[left]
            if span <= 0:
                return round(max(0.0, min(1.0, self.y[left])), 4)
            ratio = (score - self.x[left]) / span
            value = self.y[left] + ratio * (self.y[right] - self.y[left])
            return round(max(0.0, min(1.0, value)), 4)
        return round(max(0.0, min(1.0, score / 100.0)), 4)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Calibrator | None":
        method = str(payload.get("method") or "").lower()
        if method == "platt":
            try:
                return cls(
                    method="platt",
                    a=float(payload["a"]),
                    b=float(payload["b"]),
                    metrics=dict(payload.get("metrics") or {}),
                )
            except (KeyError, TypeError, ValueError):
                return None
        if method == "isotonic":
            try:
                x = tuple(float(value) for value in payload["x"])
                y = tuple(float(value) for value in payload["y"])
            except (KeyError, TypeError, ValueError):
                return None
            if len(x) < 2 or len(x) != len(y) or any(b < a for a, b in zip(x, x[1:])):
                return None
            if any(not 0.0 <= value <= 1.0 for value in y):
                return None
            return cls(
                method="isotonic",
                x=x,
                y=y,
                metrics=dict(payload.get("metrics") or {}),
            )
        return None


def load_calibrator(models_dir: Path) -> Calibrator | None:
    path = models_dir / "calibration.json"
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    return Calibrator.from_dict(payload)
