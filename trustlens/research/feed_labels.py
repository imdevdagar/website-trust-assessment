"""Third-party feed verdicts as a label source for the primary evaluation.

The pilot and main batches were labelled by one human annotator. That set is kept as a
validity subset, and the primary ground truth becomes membership of a public abuse feed,
captured at a recorded time. Two properties make this defensible rather than circular:

* The feed is never imported into the local ``domain_labels`` store, so TrustLens cannot score a
  page using the same verdict it is later evaluated against. ``assert_no_label_leakage`` checks
  that assumption against the collected assessments instead of trusting it.
* A feed entry is a statement about a moment in time, so every label carries the retrieval
  timestamp and the crawl must happen inside a bounded window.
"""

from __future__ import annotations

import csv
import dataclasses
import hashlib
import io
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

from .candidates import FEED_DOMAIN_EXCLUSIONS, UnsafeURLError, sanitize_candidate_url

LABEL_SCHEMA_VERSION = 1
LABEL_FIELDS = (
    "domain",
    "label",
    "confidence",
    "source",
    "source_date",
    "retrieved_at",
    "note",
    "url",
)
MALICIOUS_LABEL = "malicious"
DEFAULT_MAX_AGE_DAYS = 7
URLHAUS_FIELDS = (
    "id",
    "dateadded",
    "url",
    "url_status",
    "last_online",
    "threat",
    "tags",
    "urlhaus_link",
    "reporter",
)
POLICY = {
    "label_meaning": "membership of a public abuse feed at retrieval time, not a human trust judgement",
    "feed_never_imported_to_runtime": "the feed must not be loaded into the local domain_labels store",
    "unreachable_pages": "a feed domain that cannot be assessed is dropped, never labelled benign",
    "positive_class_mix": "OpenPhish reports phishing; URLhaus reports malware distribution",
    "leakage_check": "assert_no_label_leakage must pass on every assessment used as a sample",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_when(value: str) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def fetch_feed(url: str, *, name: str) -> tuple[str, dict[str, Any]]:
    """Download a public feed and record the provenance needed to reproduce the label set."""
    import httpx

    response = httpx.get(
        url,
        follow_redirects=True,
        timeout=60.0,
        headers={"User-Agent": "TrustLens/0.1 research labels"},
    )
    response.raise_for_status()
    retrieved_at = datetime.now(timezone.utc)
    return (
        response.content.decode("utf-8-sig", errors="replace"),
        {
            "source": name,
            "url": url,
            "final_url": str(response.url),
            "retrieved_at": retrieved_at.isoformat(timespec="seconds"),
            "source_date": retrieved_at.date().isoformat(),
            "http_date": response.headers.get("date", ""),
            "sha256": hashlib.sha256(response.content).hexdigest(),
            "bytes": len(response.content),
            "fetch_mode": "network",
        },
    )


def read_feed(path: Path, *, name: str, url: str = "") -> tuple[str, dict[str, Any]]:
    """Read a saved feed snapshot so a label set can be rebuilt offline."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"feed snapshot not found: {path}")
    raw = path.read_bytes()
    return (
        raw.decode("utf-8-sig", errors="replace"),
        {
            "source": name,
            "url": url,
            "final_url": url,
            "snapshot_file": str(path),
            "retrieved_at": "",
            "source_date": datetime.now(timezone.utc).date().isoformat(),
            "http_date": "",
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
            "fetch_mode": "local_file",
        },
    )


def urlhaus_urls(text: str) -> list[str]:
    """Pull the URL column out of the headerless URLhaus online CSV export."""
    rows = [
        line
        for line in str(text or "").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not rows:
        return []
    return [
        value
        for row in csv.DictReader(io.StringIO("\n".join(rows)), fieldnames=URLHAUS_FIELDS)
        if (value := str(row.get("url") or "").strip())
    ]


@dataclass(frozen=True)
class FeedSource:
    name: str
    text: str
    retrieved_at: str = ""
    source_date: str = ""
    sha256: str = ""
    url: str = ""
    max_age_days: int = DEFAULT_MAX_AGE_DAYS
    snapshot_file: str = ""


def with_snapshot(source: FeedSource, path: Path) -> FeedSource:
    """Return the source with the saved raw-feed path recorded, so provenance names the bytes used."""
    return dataclasses.replace(source, snapshot_file=str(path))


def _age_state(source: FeedSource, now: datetime) -> tuple[str, float | None]:
    retrieved = _parse_when(source.retrieved_at)
    if retrieved is None:
        return "unknown_age", None
    age_hours = max(0.0, (now - retrieved).total_seconds() / 3600.0)
    state = "fresh" if age_hours <= source.max_age_days * 24 else "stale"
    return state, round(age_hours, 2)


def build_feed_labels(
    sources: Sequence[FeedSource],
    *,
    excluded_domains: Iterable[str] | None = None,
    now: datetime | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Turn one or more feed snapshots into one malicious label per registrable domain.

    Where a domain appears in several feeds the row keeps every source, because the paper needs to
    say which verdict a sample rests on.
    """
    if not sources:
        raise ValueError("at least one feed source is required")
    now = now or datetime.now(timezone.utc)
    excluded = {str(domain).strip().lower() for domain in (excluded_domains or ()) if domain}

    rows: dict[str, dict[str, Any]] = {}
    first_seen: dict[str, dict[str, str]] = {}
    rejections: Counter[str] = Counter()
    per_source: dict[str, dict[str, Any]] = {}

    for source in sources:
        lines = [
            line.strip()
            for line in str(source.text or "").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        age_state, age_hours = _age_state(source, now)
        accepted = 0
        for line in lines:
            try:
                url, domain = sanitize_candidate_url(line)
            except UnsafeURLError as exc:
                rejections[f"{source.name}: {exc}"] += 1
                continue
            if domain in FEED_DOMAIN_EXCLUSIONS:
                rejections[f"{source.name}: shared_or_multitenant_domain"] += 1
                continue
            if domain in excluded:
                rejections[f"{source.name}: excluded_overlap"] += 1
                continue
            accepted += 1
            provenance = f"{source.name}@{source.source_date or 'undated'}"
            first_seen.setdefault(domain, {})[source.name] = provenance
            row = rows.get(domain)
            if row is None:
                rows[domain] = {
                    "domain": domain,
                    "label": MALICIOUS_LABEL,
                    "confidence": "1.00",
                    "source": provenance,
                    "source_date": source.source_date,
                    "retrieved_at": source.retrieved_at,
                    "note": f"feed membership; {age_state}",
                    "url": url,
                }
            elif source.name not in row["source"]:
                row["source"] = f"{row['source']}+{provenance}"
        per_source[source.name] = {
            "url": source.url,
            "sha256": source.sha256,
            "snapshot_file": source.snapshot_file,
            "retrieved_at": source.retrieved_at,
            "source_date": source.source_date,
            "max_age_days": source.max_age_days,
            "age_state": age_state,
            "age_hours": age_hours,
            "lines": len(lines),
            "accepted_entries": accepted,
        }

    ordered = [rows[domain] for domain in sorted(rows)]
    stats = {
        "schema_version": LABEL_SCHEMA_VERSION,
        "created_at": _now(),
        "label": MALICIOUS_LABEL,
        "policy": POLICY,
        "sources": per_source,
        "labeled_domains": len(ordered),
        "multi_feed_domains": sum(1 for row in ordered if "+" in row["source"]),
        "rejections": dict(rejections),
        "rejection_total": sum(rejections.values()),
        # An unknown age (a local snapshot with no retrieval timestamp) is a warning, not a refusal;
        # only a feed provably older than the window blocks the label set.
        "stale_sources": sorted(
            name for name, meta in per_source.items() if meta["age_state"] == "stale"
        ),
    }
    return ordered, stats


def write_labels(rows: Sequence[dict[str, Any]], path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=LABEL_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in LABEL_FIELDS})
    return str(path)


def load_feed_label_domains(path: Path) -> set[str]:
    if not path.exists():
        raise FileNotFoundError(f"feed label file not found: {path}")
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return {
            str(row.get("domain") or "").strip().lower()
            for row in csv.DictReader(handle)
            if str(row.get("domain") or "").strip()
        }


def load_human_label_rows(
    label_files: Sequence[Path],
) -> dict[str, dict[str, Any]]:
    """Read frozen label CSVs into one record per domain, keeping every batch and label seen."""
    rows: dict[str, dict[str, Any]] = {}
    for path in label_files:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"human label file not found: {path}")
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            for record in csv.DictReader(handle):
                domain = str(record.get("domain") or "").strip().lower()
                label = str(record.get("label") or "").strip().lower()
                if not domain or label not in {"benign", "suspicious", "malicious"}:
                    continue
                entry = rows.setdefault(domain, {"labels": [], "batches": []})
                entry["labels"].append(label)
                entry["batches"].append(str(record.get("source") or path.stem))
    return rows


def cross_check_human_labels(
    label_files: Sequence[Path],
    feed_label_file: Path,
) -> dict[str, Any]:
    """Compare the frozen human verdicts with feed membership on the domains both cover.

    A disagreement is a finding about two label sources, not an error to repair: nothing here moves a
    frozen label or removes a feed entry.
    """
    from .annotations import _kappa_values

    humans = load_human_label_rows(label_files)
    feed = load_feed_label_domains(feed_label_file)
    feed_source: dict[str, str] = {}
    with Path(feed_label_file).open("r", encoding="utf-8-sig", newline="") as handle:
        for record in csv.DictReader(handle):
            domain = str(record.get("domain") or "").strip().lower()
            if domain:
                feed_source.setdefault(domain, str(record.get("source") or ""))
    overlap = sorted(set(humans) & feed)

    def human_primary(domain: str) -> str:
        labels = humans[domain]["labels"]
        return "malicious" if "malicious" in labels else labels[-1]

    matrix: dict[str, dict[str, int]] = {
        label: {"in_feed": 0, "not_in_feed": 0} for label in ("benign", "suspicious", "malicious")
    }
    for domain in humans:
        bucket = "in_feed" if domain in feed else "not_in_feed"
        matrix[human_primary(domain)][bucket] += 1

    human_sequence = [human_primary(domain) for domain in overlap]
    feed_sequence = ["malicious"] * len(overlap)
    observed, expected, kappa, _ = _kappa_values(human_sequence, feed_sequence, None)
    human_malicious = [domain for domain in humans if human_primary(domain) == "malicious"]
    still_listed = [domain for domain in human_malicious if domain in feed]
    disagreements = [
        {
            "domain": domain,
            "human_labels": humans[domain]["labels"],
            "batches": humans[domain]["batches"],
            "feed": feed_source.get(domain, ""),
        }
        for domain in overlap
        if human_primary(domain) != "malicious"
    ]
    return {
        "human_domains": len(humans),
        "feed_domains": len(feed),
        "overlap": len(overlap),
        "overlap_domains": overlap,
        "human_label_by_feed_membership": matrix,
        "observed_agreement_on_overlap": observed,
        "expected_agreement_on_overlap": expected,
        "cohens_kappa_on_overlap": kappa,
        # One marginal is constant (every overlapping feed domain is malicious), so kappa is anchored
        # at zero regardless of the human labels and cannot be read as a reliability statistic.
        "cohens_kappa_interpretable": bool(overlap) and len(set(feed_sequence)) > 1
        and len(set(human_sequence)) > 1,
        "human_malicious_still_in_feed": {
            "human_malicious_domains": len(human_malicious),
            "still_listed": len(still_listed),
            "share": round(len(still_listed) / len(human_malicious), 4) if human_malicious else None,
            "meaning": "how much of the human-identified positive class the feeds still carry at "
            "retrieval time; the rest is taken down, repaired, or never reported",
        },
        "human_not_malicious_but_feed_malicious": disagreements,
        "reading": (
            "Feed membership and a human verdict are different statements. The overlap is small "
            "because pilot and main candidates were excluded when the label set was built, so this "
            "table measures source agreement, not label correctness."
        ),
    }


def derive_evaluation_labels(
    assessment_files: Sequence[Path],
    feed_label_file: Path,
    *,
    exclude_domains: Iterable[str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Join collected assessments with feed membership to produce the primary label file.

    A collected domain that is in a feed is `malicious`; one that is not is `benign`, which means
    "absent from both feeds at retrieval time" and nothing stronger. Domains carrying a frozen human
    label are excluded rather than given a derived label, because feed absence would otherwise turn a
    human-confirmed positive into a silent negative.
    """
    from .dataset import load_assessment_files

    rows, _ = load_assessment_files([Path(path) for path in assessment_files])
    feed = load_feed_label_domains(Path(feed_label_file))
    excluded = {str(domain).strip().lower() for domain in (exclude_domains or ()) if domain}
    collected = {str(assessment.domain).strip().lower() for assessment in rows if assessment.domain}

    derived: list[dict[str, Any]] = []
    skipped_human: list[str] = []
    for domain in sorted(collected):
        if domain in excluded:
            skipped_human.append(domain)
            continue
        if domain in feed:
            label, source, confidence = MALICIOUS_LABEL, "feed_membership", "1.00"
        else:
            label, source, confidence = "benign", "absent_from_feeds", "0.80"
        derived.append(
            {
                "domain": domain,
                "label": label,
                "confidence": confidence,
                "source": source,
                "source_date": "",
                "retrieved_at": _now(),
                "note": "derived at dataset time from feed membership and collected assessments",
                "url": "",
            }
        )
    stats = {
        "schema_version": LABEL_SCHEMA_VERSION,
        "created_at": _now(),
        "assessment_files": [str(path) for path in assessment_files],
        "collected_domains": len(collected),
        "derived_rows": len(derived),
        "labels": dict(Counter(row["label"] for row in derived)),
        "excluded_human_labelled_domains": len(skipped_human),
        "excluded_human_labelled_examples": skipped_human[:20],
        "feed_domains_without_an_assessment": len(feed - collected),
        "feed_domains_without_an_assessment_note": (
            "these are dropped, never labelled benign; a feed domain that cannot be assessed is not "
            "evidence of anything"
        ),
        "benign_meaning": "absent from both feeds at retrieval time, not verified trustworthy",
    }
    return derived, stats


def assert_no_label_leakage(
    assessment_files: Sequence[Path],
    label_domains: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Check that no assessment was scored using the verdict it is about to be evaluated against.

    TrustLens can attach ``known_malicious_label`` evidence from the local ``domain_labels`` store,
    which is worth 55 risk points on its own. If the evaluation feed ever reached that store, the
    model would be reading the answer, so this is asserted against the artefacts rather than assumed.
    """
    from .. import storage
    from ..scoring.model import leakage_reasons
    from .dataset import load_assessment_files

    label_domains = {str(domain).strip().lower() for domain in (label_domains or ()) if domain}
    assessments, errors = load_assessment_files(list(assessment_files))
    stored = {
        str(row.get("domain") or "").strip().lower()
        for row in storage.iter_domain_labels()
        if str(row.get("domain") or "").strip()
    }
    leaked: list[dict[str, Any]] = []
    for assessment in assessments:
        reasons = leakage_reasons(assessment)
        in_store = assessment.domain.lower() in stored
        if in_store:
            reasons = [*reasons, "runtime_domain_label_row"]
        if reasons:
            leaked.append({"domain": assessment.domain, "reasons": reasons})
    overlap = sorted({assessment.domain.lower() for assessment in assessments} & stored & label_domains)
    return {
        "assessments": len(assessments),
        "unreadable_rows": len(errors),
        "runtime_label_store_rows": len(stored),
        "leaked_assessments": len(leaked),
        "leaked_examples": leaked[:20],
        "feed_domains_in_runtime_store": overlap,
        "passed": not leaked and not overlap,
    }

