"""Blinded page-snapshot index for the local labeling form.

The crawler already captures a viewport screenshot per assessment. Joining those images to the
annotator's own sheet lets a site be judged from the captured page instead of opening every domain
live. Only the image is exposed: rule scores, evidence codes, strata, and risk levels never enter this
index, so the blinding of the annotation task is unchanged.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

BLANK_MAX_BYTES = 8192


@dataclass(frozen=True)
class SnapshotRef:
    path: Path
    filename: str
    bytes: int
    sha256: str
    identical_captures: int
    state: str  # ok | duplicate | likely_blank | missing

    def public(self) -> dict[str, Any]:
        return {
            "available": self.state != "missing",
            "state": self.state,
            "bytes": self.bytes,
            "identical_captures": self.identical_captures,
        }


MISSING = SnapshotRef(
    path=Path(""),
    filename="",
    bytes=0,
    sha256="",
    identical_captures=0,
    state="missing",
)


def _file_state(size: int, duplicates: int) -> str:
    # A 1365x1000 viewport PNG of a rendered page is normally a few hundred kilobytes; a few
    # kilobytes means the capture is empty chrome, regardless of whether it repeats.
    if size <= BLANK_MAX_BYTES:
        return "likely_blank"
    if duplicates > 1:
        return "duplicate"
    return "ok"


def _assessment_rows(paths: Iterable[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in paths:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"assessment file not found: {path}")
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict) and "domain" in payload:
                rows.append(payload)
    return rows


def build_snapshot_index(
    assessment_files: Iterable[Path],
    screenshots_dir: Path,
) -> dict[str, SnapshotRef]:
    """Map each assessment's queue URL to its captured screenshot.

    Keys use `final_url or url`, exactly the value written into the annotator sheet, so the join needs
    no re-normalisation and cannot pick up a verdict field.
    """
    screenshots_dir = Path(screenshots_dir)
    captured: dict[str, Path] = {}
    for row in _assessment_rows(assessment_files):
        url = str(row.get("final_url") or row.get("url") or "").strip()
        if not url:
            continue
        filename = str((row.get("meta") or {}).get("screenshot_file") or "").strip()
        if not filename:
            continue
        path = screenshots_dir / Path(filename).name
        if path.exists():
            captured[url] = path

    digests: dict[str, str] = {}
    sizes: dict[str, int] = {}
    for url, path in captured.items():
        if str(path) not in sizes:
            data = path.read_bytes()
            digests[str(path)] = hashlib.sha256(data).hexdigest()
            sizes[str(path)] = len(data)
    counts: dict[str, int] = {}
    for path in captured.values():
        key = str(path)
        counts[key] = counts.get(key, 0) + 1
    by_digest: dict[str, int] = {}
    for key, digest in digests.items():
        by_digest[digest] = by_digest.get(digest, 0) + counts.get(key, 0)

    index: dict[str, SnapshotRef] = {}
    for url, path in captured.items():
        key = str(path)
        duplicates = by_digest.get(digests[key], 1)
        index[url] = SnapshotRef(
            path=path,
            filename=path.name,
            bytes=sizes[key],
            sha256=digests[key],
            identical_captures=duplicates,
            state=_file_state(sizes[key], duplicates),
        )
    return index


def snapshot_stats(
    index: dict[str, SnapshotRef], sheet_urls: Iterable[str]
) -> dict[str, Any]:
    states = {"ok": 0, "duplicate": 0, "likely_blank": 0, "missing": 0}
    for url in sheet_urls:
        state = index.get(str(url), MISSING).state
        states[state] = states.get(state, 0) + 1
    total = sum(states.values())
    return {
        "sites": total,
        "usable_snapshots": states["ok"] + states["duplicate"],
        "suspect_snapshots": states["likely_blank"],
        **states,
    }
