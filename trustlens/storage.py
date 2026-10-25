"""SQLite persistence: assessments, labels, domain attributes, and intel cache.

SQLite keeps the prototype deployable on a laptop. Writes are short and each
operation opens its own connection; WAL mode allows the dashboard to read while
the API writes.
"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

from .config import Settings, settings
from .schemas import Assessment

SCHEMA = """
CREATE TABLE IF NOT EXISTS assessments (
    id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    normalized_url TEXT NOT NULL,
    final_url TEXT NOT NULL,
    domain TEXT NOT NULL,
    action TEXT NOT NULL,
    overall_risk REAL NOT NULL,
    overall_level TEXT NOT NULL,
    confidence REAL NOT NULL,
    recommendation TEXT NOT NULL,
    headline TEXT NOT NULL,
    screenshot_url TEXT,
    engine_version TEXT,
    duration_ms INTEGER,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_assessments_domain ON assessments(domain);
CREATE INDEX IF NOT EXISTS idx_assessments_created ON assessments(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_assessments_cache ON assessments(normalized_url, action, created_at DESC);

CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id TEXT NOT NULL,
    verdict TEXT NOT NULL,
    suggested_label TEXT,
    note TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_feedback_assessment ON feedback(assessment_id);

CREATE TABLE IF NOT EXISTS domain_labels (
    domain TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    source TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 1.0,
    note TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS domain_attrs (
    domain TEXT PRIMARY KEY,
    cert_fingerprints TEXT NOT NULL DEFAULT '[]',
    favicon_hashes TEXT NOT NULL DEFAULT '[]',
    analytics_ids TEXT NOT NULL DEFAULT '[]',
    image_hashes TEXT NOT NULL DEFAULT '[]',
    nameservers TEXT NOT NULL DEFAULT '[]',
    registrar TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    times_seen INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS intel_cache (
    key TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    fetched_at REAL NOT NULL
);
"""

_JSON_LIST_FIELDS = ("cert_fingerprints", "favicon_hashes", "analytics_ids", "image_hashes", "nameservers")

_settings_override: Settings | None = None


def configure(cfg: Settings) -> None:
    """Bind storage to the configuration used by the running Assessor."""
    global _settings_override
    _settings_override = cfg


def configured_settings() -> Settings:
    return _settings_override or settings()


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    cfg = configured_settings()
    cfg.db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(cfg.db_path, timeout=15)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db() -> None:
    with connect() as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(SCHEMA)


def _loads(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def save_assessment(assessment: Assessment) -> None:
    payload = assessment.model_dump_json()
    with connect() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO assessments (
                id, url, normalized_url, final_url, domain, action, overall_risk,
                overall_level, confidence, recommendation, headline, screenshot_url,
                engine_version, duration_ms, payload, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                assessment.id,
                assessment.url,
                assessment.normalized_url,
                assessment.final_url,
                assessment.domain,
                assessment.action.value,
                assessment.overall_risk,
                assessment.overall_level.value,
                assessment.confidence,
                assessment.recommendation,
                assessment.headline,
                assessment.screenshot_url,
                str(assessment.meta.get("engine_version", "")),
                int(assessment.meta.get("duration_ms", 0) or 0),
                payload,
                assessment.created_at.isoformat(),
            ),
        )


def get_assessment(assessment_id: str) -> Assessment | None:
    with connect() as conn:
        row = conn.execute("SELECT payload FROM assessments WHERE id = ?", (assessment_id,)).fetchone()
    if not row:
        return None
    return Assessment.model_validate_json(row["payload"])


def get_cached_assessment(normalized_url: str, action: str, ttl_seconds: int) -> Assessment | None:
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=ttl_seconds)).isoformat()
    with connect() as conn:
        row = conn.execute(
            """
            SELECT payload FROM assessments
            WHERE normalized_url = ? AND action = ? AND created_at >= ?
              AND overall_level != 'unknown'
            ORDER BY created_at DESC LIMIT 1
            """,
            (normalized_url, action, cutoff),
        ).fetchone()
    if not row:
        return None
    assessment = Assessment.model_validate_json(row["payload"])
    assessment.cached = True
    return assessment


def list_assessments(
    limit: int = 20,
    offset: int = 0,
    domain: str | None = None,
    level: str | None = None,
) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 100))
    offset = max(0, offset)
    clauses: list[str] = []
    params: list[Any] = []
    if domain:
        clauses.append("domain = ?")
        params.append(domain)
    if level:
        clauses.append("overall_level = ?")
        params.append(level)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with connect() as conn:
        rows = conn.execute(
            f"""
            SELECT id, url, domain, action, overall_risk, overall_level, confidence,
                   headline, created_at, screenshot_url
            FROM assessments {where}
            ORDER BY created_at DESC LIMIT ? OFFSET ?
            """,
            (*params, limit, offset),
        ).fetchall()
    return [dict(row) for row in rows]


def iter_assessments() -> Iterator[Assessment]:
    """Yield every stored assessment for dataset export and research tooling."""
    with connect() as conn:
        rows = conn.execute(
            "SELECT payload FROM assessments ORDER BY created_at, id"
        ).fetchall()
    for row in rows:
        yield Assessment.model_validate_json(row["payload"])


def count_assessments() -> int:
    with connect() as conn:
        return int(conn.execute("SELECT COUNT(*) FROM assessments").fetchone()[0])


def stats() -> dict[str, Any]:
    day_ago = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    with connect() as conn:
        total = conn.execute("SELECT COUNT(*) FROM assessments").fetchone()[0]
        last_24h = conn.execute(
            "SELECT COUNT(*) FROM assessments WHERE created_at >= ?", (day_ago,)
        ).fetchone()[0]
        avg_row = conn.execute(
            "SELECT AVG(overall_risk), AVG(duration_ms) FROM assessments"
        ).fetchone()
        levels = {
            row["overall_level"]: row["count"]
            for row in conn.execute(
                "SELECT overall_level, COUNT(*) AS count FROM assessments GROUP BY overall_level"
            ).fetchall()
        }
        feedback_count = conn.execute("SELECT COUNT(*) FROM feedback").fetchone()[0]
        labeled = conn.execute("SELECT COUNT(*) FROM domain_labels").fetchone()[0]
        malicious = conn.execute(
            "SELECT COUNT(*) FROM domain_labels WHERE label = 'malicious'"
        ).fetchone()[0]
        top_domains = [
            dict(row)
            for row in conn.execute(
                """
                SELECT domain, COUNT(*) AS count, MAX(overall_risk) AS max_risk
                FROM assessments GROUP BY domain ORDER BY count DESC LIMIT 8
                """
            ).fetchall()
        ]
    return {
        "total_assessments": int(total),
        "assessments_24h": int(last_24h),
        "by_level": levels,
        "average_risk": round(float(avg_row[0]), 1) if avg_row[0] is not None else None,
        "average_duration_ms": round(float(avg_row[1]), 1) if avg_row[1] is not None else None,
        "feedback_count": int(feedback_count),
        "labeled_domains": int(labeled),
        "malicious_domains": int(malicious),
        "top_domains": top_domains,
    }


def add_feedback(
    assessment_id: str,
    verdict: str,
    suggested_label: str | None = None,
    note: str = "",
) -> int:
    with connect() as conn:
        cursor = conn.execute(
            """
            INSERT INTO feedback (assessment_id, verdict, suggested_label, note, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (assessment_id, verdict, suggested_label, note[:1000], datetime.now(timezone.utc).isoformat()),
        )
        return int(cursor.lastrowid)


def upsert_domain_label(
    domain: str,
    label: str,
    source: str = "manual",
    confidence: float = 1.0,
    note: str = "",
) -> None:
    domain = domain.strip().lower().rstrip(".")
    if not domain:
        raise ValueError("domain must not be empty")
    label = label.strip().lower()
    if label not in {"benign", "suspicious", "malicious"}:
        raise ValueError("label must be benign, suspicious, or malicious")
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO domain_labels (domain, label, source, confidence, note, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET
                label = excluded.label,
                source = excluded.source,
                confidence = excluded.confidence,
                note = excluded.note,
                updated_at = excluded.updated_at
            """,
            (
                domain,
                label,
                source,
                max(0.0, min(1.0, confidence)),
                note[:1000],
                datetime.now(timezone.utc).isoformat(),
            ),
        )


def get_domain_label(domain: str) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute(
            "SELECT domain, label, source, confidence, note, updated_at FROM domain_labels WHERE domain = ?",
            (domain.strip().lower().rstrip("."),),
        ).fetchone()
    return dict(row) if row else None


def iter_domain_labels() -> list[dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT domain, label, source, confidence, note, updated_at FROM domain_labels"
        ).fetchall()
    return [dict(row) for row in rows]


def count_labels() -> dict[str, int]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT label, COUNT(*) AS count FROM domain_labels GROUP BY label"
        ).fetchall()
    return {row["label"]: int(row["count"]) for row in rows}


def upsert_domain_observation(
    domain: str,
    *,
    cert_fingerprints: Iterable[str] = (),
    favicon_hashes: Iterable[str] = (),
    analytics_ids: Iterable[str] = (),
    image_hashes: Iterable[str] = (),
    nameservers: Iterable[str] = (),
    registrar: str | None = None,
) -> None:
    domain = domain.strip().lower().rstrip(".")
    if not domain:
        return
    now = datetime.now(timezone.utc).isoformat()
    incoming = {
        "cert_fingerprints": [v for v in cert_fingerprints if v],
        "favicon_hashes": [v for v in favicon_hashes if v],
        "analytics_ids": [v for v in analytics_ids if v],
        "image_hashes": [v for v in image_hashes if v],
        "nameservers": [v for v in nameservers if v],
    }
    with connect() as conn:
        row = conn.execute("SELECT * FROM domain_attrs WHERE domain = ?", (domain,)).fetchone()
        if row:
            merged: dict[str, list[str]] = {}
            for field in _JSON_LIST_FIELDS:
                existing = _loads(row[field], [])
                values = list(dict.fromkeys([*existing, *incoming[field]]))
                merged[field] = values[-100:]
            conn.execute(
                """
                UPDATE domain_attrs SET
                    cert_fingerprints = ?, favicon_hashes = ?, analytics_ids = ?,
                    image_hashes = ?, nameservers = ?, registrar = ?, last_seen = ?,
                    times_seen = times_seen + 1
                WHERE domain = ?
                """,
                (
                    json.dumps(merged["cert_fingerprints"]),
                    json.dumps(merged["favicon_hashes"]),
                    json.dumps(merged["analytics_ids"]),
                    json.dumps(merged["image_hashes"]),
                    json.dumps(merged["nameservers"]),
                    registrar or row["registrar"],
                    now,
                    domain,
                ),
            )
        else:
            conn.execute(
                """
                INSERT INTO domain_attrs (
                    domain, cert_fingerprints, favicon_hashes, analytics_ids,
                    image_hashes, nameservers, registrar, first_seen, last_seen, times_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                """,
                (
                    domain,
                    json.dumps(list(dict.fromkeys(incoming["cert_fingerprints"]))),
                    json.dumps(list(dict.fromkeys(incoming["favicon_hashes"]))),
                    json.dumps(list(dict.fromkeys(incoming["analytics_ids"]))),
                    json.dumps(list(dict.fromkeys(incoming["image_hashes"]))),
                    json.dumps(list(dict.fromkeys(incoming["nameservers"]))),
                    registrar,
                    now,
                    now,
                ),
            )


def get_domain_attrs(domain: str) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM domain_attrs WHERE domain = ?", (domain,)).fetchone()
    if not row:
        return None
    result = dict(row)
    for field in _JSON_LIST_FIELDS:
        result[field] = _loads(result[field], [])
    return result


def find_bad_neighbors(
    *,
    cert_fingerprints: Iterable[str] = (),
    favicon_hashes: Iterable[str] = (),
    analytics_ids: Iterable[str] = (),
    image_hashes: Iterable[str] = (),
    exclude_domain: str | None = None,
    limit: int = 5000,
) -> list[dict[str, Any]]:
    """Find labeled-malicious domains sharing infrastructure with this domain."""
    certs = set(cert_fingerprints)
    favicons = set(favicon_hashes)
    analytics = set(analytics_ids)
    images = set(image_hashes)
    if not (certs or favicons or analytics or images):
        return []
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT a.domain, a.cert_fingerprints, a.favicon_hashes, a.analytics_ids,
                   a.image_hashes, l.label, l.confidence, l.source
            FROM domain_attrs a
            JOIN domain_labels l ON l.domain = a.domain
            WHERE l.label = 'malicious'
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    neighbors: list[dict[str, Any]] = []
    for row in rows:
        if exclude_domain and row["domain"] == exclude_domain:
            continue
        matched: list[str] = []
        shared_certs = certs & set(_loads(row["cert_fingerprints"], []))
        shared_favicons = favicons & set(_loads(row["favicon_hashes"], []))
        shared_analytics = analytics & set(_loads(row["analytics_ids"], []))
        shared_images = images & set(_loads(row["image_hashes"], []))
        if shared_certs:
            matched.append("tls_certificate")
        if shared_favicons:
            matched.append("favicon")
        if shared_analytics:
            matched.append("analytics_id")
        if shared_images:
            matched.append("product_image")
        if matched:
            neighbors.append(
                {
                    "domain": row["domain"],
                    "label": row["label"],
                    "confidence": float(row["confidence"]),
                    "source": row["source"],
                    "matched_on": matched,
                    "shared_values": {
                        "tls_certificate": sorted(shared_certs),
                        "favicon": sorted(shared_favicons),
                        "analytics_id": sorted(shared_analytics),
                        "product_image": sorted(shared_images),
                    },
                }
            )
    return neighbors


def cache_get(key: str, ttl_seconds: int) -> Any | None:
    with connect() as conn:
        row = conn.execute(
            "SELECT payload, fetched_at FROM intel_cache WHERE key = ?", (key,)
        ).fetchone()
    if not row or time.time() - float(row["fetched_at"]) > ttl_seconds:
        return None
    return _loads(row["payload"], None)


def cache_set(key: str, payload: Any) -> None:
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO intel_cache (key, payload, fetched_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET payload = excluded.payload, fetched_at = excluded.fetched_at
            """,
            (key, json.dumps(payload, default=str), time.time()),
        )


def cache_delete(key: str) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM intel_cache WHERE key = ?", (key,))


def get_labeled_dataset() -> list[dict[str, Any]]:
    """Assessments joined to domain labels, for training and evaluation scripts."""
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT a.payload, l.label, l.confidence AS label_confidence, l.source
            FROM assessments a
            JOIN domain_labels l ON l.domain = a.domain
            ORDER BY a.created_at DESC
            """
        ).fetchall()
    return [
        {
            "assessment": Assessment.model_validate_json(row["payload"]),
            "label": row["label"],
            "label_confidence": float(row["label_confidence"]),
            "label_source": row["source"],
        }
        for row in rows
    ]


def db_path() -> Path:
    return configured_settings().db_path
