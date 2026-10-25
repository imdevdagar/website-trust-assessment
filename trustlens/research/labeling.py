"""Local blind labeling form for the two human annotators.

The server reads only the annotator's own sheet. It never opens ``key.json``,
so rule scores, strata, and assignments cannot leak into the UI. When a snapshot
index is supplied it also serves the crawler's captured page image for each site,
which lets an annotator judge the page without opening every domain live.
"""

from __future__ import annotations

import json
import math
import os
import secrets
import threading
import uuid
from pathlib import Path
from typing import Any, Mapping

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse, Response
from pydantic import BaseModel

from .annotations import ANNOTATION_FIELDS, LABELS, read_csv_rows, write_csv
from .snapshots import MISSING, SnapshotRef, snapshot_stats

ASSET_DIR = Path(__file__).with_name("label_ui")
CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'none'; "
    "frame-ancestors 'none'"
)
_WRITE_LOCK = threading.Lock()


class AnnotationIn(BaseModel):
    sample_id: str
    label: str
    confidence: float
    notes: str = ""


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _role_label(sheet_path: Path) -> str:
    stem = sheet_path.stem.lower().replace("-", "_")
    if "annotator_a" in stem or stem.endswith("_a"):
        return "A"
    if "annotator_b" in stem or stem.endswith("_b"):
        return "B"
    return "Annotator"


def freeze_record(sheet_path: Path) -> dict[str, Any] | None:
    directory = sheet_path.parent / "frozen"
    if not directory.exists():
        return None
    for record_path in sorted(directory.glob("*.freeze.json")):
        try:
            record = json.loads(record_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if record.get("source_sheet") == sheet_path.name:
            return record
    return None


def _snapshot_for(
    snapshots: Mapping[str, SnapshotRef] | None, url: str
) -> dict[str, Any]:
    if not snapshots:
        return {"available": False, "state": "unavailable"}
    return snapshots.get(str(url or ""), MISSING).public()


def load_sites(
    sheet_path: Path,
    snapshots: Mapping[str, SnapshotRef] | None = None,
) -> list[dict[str, Any]]:
    sites: list[dict[str, Any]] = []
    for row in read_csv_rows(sheet_path):
        url = _clean(row.get("url"))
        label = _clean(row.get("label")).lower()
        if label not in LABELS:
            label = ""
        raw_confidence = _clean(row.get("confidence"))
        try:
            confidence = float(raw_confidence) if raw_confidence else None
        except ValueError:
            confidence = None
        if confidence is not None and not 0.0 <= confidence <= 1.0:
            confidence = None
        sites.append(
            {
                "sample_id": _clean(row.get("sample_id")),
                "url": url,
                "domain": _clean(row.get("domain")),
                "action": _clean(row.get("action")),
                "label": label,
                "confidence": confidence,
                "notes": _clean(row.get("notes")),
                "openable": url.lower().startswith(("http://", "https://")),
                "snapshot": _snapshot_for(snapshots, url),
            }
        )
    return sites


def _progress(sites: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {label: 0 for label in LABELS}
    for site in sites:
        if site["label"] in counts:
            counts[site["label"]] += 1
    labeled = sum(counts.values())
    return {
        "labeled": labeled,
        "total": len(sites),
        "by_label": counts,
        "complete": bool(sites) and labeled == len(sites),
    }


def save_annotation(
    sheet_path: Path,
    *,
    sample_id: str,
    label: str,
    confidence: float,
    notes: str,
) -> dict[str, Any]:
    sample_id = _clean(sample_id)
    label = _clean(label).lower()
    notes = _clean(notes)[:1000]
    if not sample_id:
        raise ValueError("sample_id is required")
    if label not in LABELS:
        raise ValueError(f"label must be one of {', '.join(LABELS)}")
    try:
        confidence = float(confidence)
    except (TypeError, ValueError):
        raise ValueError("confidence must be a number") from None
    if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
        raise ValueError("confidence must be between 0.0 and 1.0")
    if label in {"suspicious", "malicious"} and not notes:
        raise ValueError("notes are required for a suspicious or malicious label")

    with _WRITE_LOCK:
        if freeze_record(sheet_path) is not None:
            raise PermissionError(
                "this sheet is frozen; corrections require a documented protocol amendment"
            )
        rows = read_csv_rows(sheet_path)
        updated: dict[str, Any] | None = None
        for row in rows:
            if _clean(row.get("sample_id")) == sample_id:
                row["label"] = label
                row["confidence"] = f"{confidence:.2f}"
                row["notes"] = notes
                updated = {
                    "sample_id": sample_id,
                    "url": _clean(row.get("url")),
                    "domain": _clean(row.get("domain")),
                    "action": _clean(row.get("action")),
                    "label": label,
                    "confidence": round(confidence, 2),
                    "notes": notes,
                    "openable": _clean(row.get("url")).lower().startswith(
                        ("http://", "https://")
                    ),
                }
                break
        if updated is None:
            raise KeyError(f"unknown sample_id: {sample_id}")

        temp_path = sheet_path.with_name(f".{sheet_path.name}.{uuid.uuid4().hex}.tmp")
        try:
            write_csv(temp_path, ANNOTATION_FIELDS, rows)
            os.replace(temp_path, sheet_path)
        except OSError as exc:
            try:
                temp_path.unlink()
            except OSError:
                pass
            raise PermissionError(
                "could not write the sheet; close it in Excel or another editor and retry"
            ) from exc
        return updated


def _payload(
    sheet_path: Path,
    snapshots: Mapping[str, SnapshotRef] | None = None,
) -> dict[str, Any]:
    sites = load_sites(sheet_path, snapshots)
    record = freeze_record(sheet_path)
    return {
        "sheet": sheet_path.name,
        "round": sheet_path.parent.name,
        "role": _role_label(sheet_path),
        "sites": sites,
        "progress": _progress(sites),
        "snapshots": snapshot_stats(snapshots or {}, (site["url"] for site in sites)),
        "frozen": record is not None,
        "frozen_at": record.get("frozen_at") if record else "",
    }


def _headers() -> dict[str, str]:
    return {
        "Cache-Control": "no-store",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": CSP,
    }


def _asset(name: str) -> str:
    path = ASSET_DIR / name
    if not path.exists():
        raise HTTPException(status_code=500, detail=f"missing UI asset: {name}")
    return path.read_text(encoding="utf-8")


def create_app(
    sheet_path: Path,
    token: str,
    snapshots: Mapping[str, SnapshotRef] | None = None,
) -> FastAPI:
    sheet_path = sheet_path.resolve()
    if not sheet_path.exists():
        raise FileNotFoundError(f"annotation sheet not found: {sheet_path}")
    if not sheet_path.is_file():
        raise ValueError(f"annotation sheet is not a file: {sheet_path}")
    if not token:
        raise ValueError("annotation token must not be empty")

    snapshots = dict(snapshots or {})

    def sheet_url(sample_id: str) -> str:
        """Resolve a sample_id through the annotator's own sheet, so a snapshot is never addressable
        by a URL the annotator was not assigned."""
        sample_id = _clean(sample_id)
        for row in read_csv_rows(sheet_path):
            if _clean(row.get("sample_id")) == sample_id:
                return _clean(row.get("url"))
        raise KeyError(f"unknown sample_id: {sample_id}")

    app = FastAPI(
        title="TrustLens blind annotation",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.sheet_path = sheet_path
    app.state.token = token

    def require_token(
        x_annotation_token: str | None = Header(
            default=None, alias="X-Annotation-Token"
        ),
        token_query: str | None = Query(default=None, alias="token"),
    ) -> None:
        supplied = x_annotation_token or token_query or ""
        if not secrets.compare_digest(supplied, token):
            raise HTTPException(status_code=403, detail="invalid annotation token")

    @app.get("/", response_class=HTMLResponse)
    async def index(token: str = Query(default="")) -> HTMLResponse:
        if not secrets.compare_digest(token, app.state.token):
            raise HTTPException(status_code=403, detail="invalid annotation token")
        html = _asset("label_ui.html").replace("__ANNOTATION_TOKEN__", token)
        return HTMLResponse(html, headers=_headers())

    @app.get("/app.css")
    async def styles() -> Response:
        return Response(
            _asset("label_ui.css"),
            media_type="text/css; charset=utf-8",
            headers=_headers(),
        )

    @app.get("/app.js")
    async def script() -> Response:
        return Response(
            _asset("label_ui.js"),
            media_type="text/javascript; charset=utf-8",
            headers=_headers(),
        )

    @app.get("/api/sites", dependencies=[Depends(require_token)])
    async def sites() -> dict[str, Any]:
        return _payload(sheet_path, snapshots)

    @app.get("/api/snapshot", dependencies=[Depends(require_token)])
    async def snapshot(sample_id: str = Query(alias="sample_id")) -> Response:
        try:
            url = sheet_url(sample_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=exc.args[0]) from exc
        ref = snapshots.get(url)
        if ref is None or ref.state == "missing" or not ref.path.is_file():
            raise HTTPException(status_code=404, detail="no captured snapshot for this site")
        return FileResponse(
            ref.path,
            media_type="image/png",
            headers={
                "Cache-Control": "no-store",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
            },
        )

    @app.post("/api/annotations", dependencies=[Depends(require_token)])
    async def annotate(payload: AnnotationIn) -> dict[str, Any]:
        try:
            updated = save_annotation(
                sheet_path,
                sample_id=payload.sample_id,
                label=payload.label,
                confidence=payload.confidence,
                notes=payload.notes,
            )
        except PermissionError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        updated["snapshot"] = _snapshot_for(snapshots, updated["url"])
        return {
            "ok": True,
            "site": updated,
            "progress": _progress(load_sites(sheet_path, snapshots)),
            "frozen": freeze_record(sheet_path) is not None,
        }

    return app
