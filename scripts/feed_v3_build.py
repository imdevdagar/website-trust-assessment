"""Build the feed_v3 large-scale evaluation pool from PhishTank, OpenPhish, and Tranco.

User approval recorded 2026-10-26: crawl up to 5,000 usable domains (about 2,500
PhishTank/OpenPhish positives and 2,500 Tranco negatives), using the existing bounded
crawl contract. This script only fetches public metadata and writes manifests; it never
opens a candidate page.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import ipaddress
import json
import time
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence
from urllib.parse import urlsplit, urlunsplit

from website_trust_assessment.research import candidates as cand
from website_trust_assessment.research import feed_labels as fl

ROOT = Path(__file__).resolve().parents[1]
LABEL_DIR = ROOT / "data/labels/feed_v3"
SNAPSHOT_DIR = LABEL_DIR / "snapshots"
POSITIVE_CANDIDATES = ROOT / "data/candidates/feed_v3"
POSITIVE_RESERVE_DIR = POSITIVE_CANDIDATES / "reserve"
POSITIVE_RESERVE_MANIFEST = POSITIVE_RESERVE_DIR / "feed_reserve_manifest.json"
NEGATIVE_CANDIDATES = POSITIVE_CANDIDATES / "negatives"
EXPORT_DIR = ROOT / "data/exports/feed_v3"

PHISHTANK_URL = "https://data.phishtank.com/data/online-valid.csv"
OPENPHISH_URL = "https://openphish.com/feed.txt"
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"

SEED = 42
BATCH_SIZE = 100
TARGET_POSITIVE_USABLE = 2500
POSITIVE_SAMPLE = 3000
POSITIVE_RESERVE_SAMPLE = 1500
NEGATIVES_ESTABLISHED = 1600
NEGATIVES_TAIL = 1400
RESERVE_ESTABLISHED = 400
RESERVE_TAIL = 600
HEAVY_URL_THRESHOLD = 50

FROZEN_HUMAN_LABELS = (
    ROOT / "data/annotations/main/batch_01/frozen/annotator_a_20261020T133255Z.csv",
    ROOT / "data/annotations/pilot/frozen/annotator_a_20261020T101448Z.csv",
    ROOT / "data/annotations/pilot/frozen/annotator_b_20261020T102324Z.csv",
    ROOT / "data/annotations/round2/frozen/annotator_a_v2_20261020T111826Z.csv",
    ROOT / "data/annotations/round2/frozen/annotator_a_20261020T104418Z.csv",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_sha256(path: Path) -> str:
    return _sha256(path.read_bytes())


def _rel(path: Path) -> str:
    try:
        return Path(path).resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def _save_snapshot(name: str, data: bytes) -> dict[str, Any]:
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    digest = _sha256(data)
    suffix = Path(name).suffix or ".bin"
    path = SNAPSHOT_DIR / f"{Path(name).stem}_{digest[:12]}{suffix}"
    path.write_bytes(data)
    return {"path": str(path), "sha256": digest, "bytes": len(data)}


def _fetch(url: str, *, name: str, timeout: float = 180.0) -> tuple[bytes, dict[str, Any]]:
    import httpx

    response = None
    for attempt in range(3):
        try:
            response = httpx.get(
                url,
                follow_redirects=True,
                timeout=timeout,
                headers={"User-Agent": "WebsiteTrustAssessment/0.1 feed_v3 research labels"},
            )
            response.raise_for_status()
            break
        except (httpx.TransportError, httpx.HTTPStatusError):
            if attempt == 2:
                raise
            time.sleep(2 * (attempt + 1))
    assert response is not None
    retrieved_at = datetime.now(timezone.utc)
    data = response.content
    snapshot = _save_snapshot(name, data)
    final = urlsplit(str(response.url))
    meta = {
        "source": name,
        "url": url,
        "final_url": urlunsplit((final.scheme, final.netloc, final.path, "", "")),
        "retrieved_at": retrieved_at.isoformat(timespec="seconds"),
        "source_date": retrieved_at.date().isoformat(),
        "http_date": response.headers.get("date", ""),
        "sha256": _sha256(data),
        "bytes": len(data),
        "snapshot_file": _rel(Path(snapshot["path"])),
        "fetch_mode": "network",
    }
    return data, meta


_SNAPSHOT_META_KEYS = (
    "source",
    "url",
    "final_url",
    "retrieved_at",
    "source_date",
    "http_date",
    "sha256",
    "bytes",
    "snapshot_file",
)


def _replay_snapshot(meta: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    """Reload the exact bytes and provenance of an earlier retrieval."""
    replay = {key: meta[key] for key in _SNAPSHOT_META_KEYS if key in meta}
    replay["fetch_mode"] = "snapshot"
    path = ROOT / str(replay["snapshot_file"])
    data = path.read_bytes()
    if _sha256(data) != replay.get("sha256"):
        raise SystemExit(f"snapshot hash mismatch for {path}")
    return data, replay


def _read_csv_domains(path: Path) -> set[str]:
    if not path.exists():
        return set()
    domains: set[str] = set()
    if path.suffix == ".jsonl":
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            domain = str(record.get("domain") or "").strip().lower()
            if domain:
                domains.add(domain)
        return domains
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            domain = str(row.get("domain") or "").strip().lower()
            if not domain:
                try:
                    _, domain = cand.sanitize_candidate_url(row.get("url", ""))
                except cand.UnsafeURLError:
                    continue
            if domain:
                domains.add(domain)
    return domains


def collect_exclusions() -> tuple[set[str], list[dict[str, Any]]]:
    """Domains already used by earlier rounds, which feed_v3 must not reuse.

    The feed_v3 candidate tree is skipped: on a rebuild its own batches would otherwise
    exclude the very pool being rebuilt.
    """
    sources: list[Path] = [
        ROOT / "data/datasets/feed_v2/dataset.jsonl",
        ROOT / "data/labels/feed/labels.csv",
        *FROZEN_HUMAN_LABELS,
    ]
    own_tree = POSITIVE_CANDIDATES.resolve()
    sources.extend(
        path
        for path in sorted((ROOT / "data/candidates").rglob("*.csv"))
        if own_tree not in path.resolve().parents
    )
    excluded: set[str] = set()
    records: list[dict[str, Any]] = []
    for path in sources:
        if not path.exists():
            continue
        domains = _read_csv_domains(path)
        excluded |= domains
        records.append({"path": _rel(path), "domains": len(domains)})
    return excluded, records


def _parse_phish(
    text: str,
) -> tuple[dict[str, list[str]], Counter[str], int]:
    """Return clean URLs per domain, rejection counts, and the raw row count."""
    rows_seen = 0
    rejections: Counter[str] = Counter()
    per_domain: dict[str, list[str]] = defaultdict(list)
    for line in str(text or "").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        rows_seen += 1
    for url in fl.phishtank_urls(text):
        try:
            clean, domain = cand.sanitize_candidate_url(url)
        except cand.UnsafeURLError as exc:
            rejections[str(exc)] += 1
            continue
        if domain in cand.FEED_DOMAIN_EXCLUSIONS:
            rejections["shared_or_multitenant_domain"] += 1
            continue
        per_domain[domain].append(clean)
    return per_domain, rejections, rows_seen


def _choose_url(urls: Sequence[str]) -> str:
    return min(urls, key=lambda url: _sha256(f"{SEED}:{url}".encode("utf-8")))


def _rank(domain: str, *, namespace: str) -> str:
    return _sha256(f"{namespace}:{SEED}:{domain}".encode("utf-8"))


def build_labels(*, offline: bool = False) -> dict[str, Any]:
    if offline:
        existing = json.loads(
            (LABEL_DIR / "provenance.json").read_text(encoding="utf-8")
        )["sources"]
        phish_raw, phish_meta = _replay_snapshot(existing["phishtank_online_valid"])
        open_raw, open_meta = _replay_snapshot(existing["openphish_public_feed"])
    else:
        phish_raw, phish_meta = _fetch(PHISHTANK_URL, name="phishtank_online_valid.csv")
        open_raw, open_meta = _fetch(OPENPHISH_URL, name="openphish_feed.txt")
    phish_text = phish_raw.decode("utf-8-sig", errors="replace")
    open_text = open_raw.decode("utf-8-sig", errors="replace")

    per_domain, phish_rejections, phish_rows = _parse_phish(phish_text)
    heavy = {
        domain for domain, urls in per_domain.items() if len(urls) >= HEAVY_URL_THRESHOLD
    }
    phish_urls = [
        _choose_url(urls)
        for domain, urls in sorted(per_domain.items())
        if domain not in heavy
    ]

    excluded, exclusion_records = collect_exclusions()
    phish_source = fl.FeedSource(
        name="phishtank_online_valid",
        text="\n".join(phish_urls),
        retrieved_at=phish_meta["retrieved_at"],
        source_date=phish_meta["source_date"],
        sha256=phish_meta["sha256"],
        url=PHISHTANK_URL,
        snapshot_file=phish_meta["snapshot_file"],
    )
    open_source = fl.FeedSource(
        name="openphish_public_feed",
        text=open_text,
        retrieved_at=open_meta["retrieved_at"],
        source_date=open_meta["source_date"],
        sha256=open_meta["sha256"],
        url=OPENPHISH_URL,
        snapshot_file=open_meta["snapshot_file"],
    )

    rows, stats = fl.build_feed_labels(
        [phish_source, open_source],
        excluded_domains=excluded | heavy,
        now=datetime.now(timezone.utc),
    )
    if not rows:
        raise SystemExit("no positive labels were produced")
    stats["policy"] = {
        **stats["policy"],
        "positive_class_mix": (
            "PhishTank online-valid lists URLs PhishTank marks verified and online; "
            "OpenPhish lists phishing URLs. URLhaus is retired for feed_v3."
        ),
    }

    LABEL_DIR.mkdir(parents=True, exist_ok=True)
    labels_path = LABEL_DIR / "labels.csv"
    fl.write_labels(rows, labels_path)

    ranked = sorted(rows, key=lambda row: _rank(row["domain"], namespace="feed_v3-positive"))
    sampled = ranked[:POSITIVE_SAMPLE]
    positives_path = LABEL_DIR / "positives.csv"
    fl.write_labels(sampled, positives_path)
    reserve_sample = ranked[POSITIVE_SAMPLE : POSITIVE_SAMPLE + POSITIVE_RESERVE_SAMPLE]
    positives_reserve_path = LABEL_DIR / "positives_reserve.csv"
    fl.write_labels(reserve_sample, positives_reserve_path)

    provenance = {
        "dataset": "feed_v3",
        "purpose": (
            "large-scale evaluation of the shipped rule engine and learned models; independent "
            "of the feed_v2 domains and the frozen human-label subset"
        ),
        "created_at": _now(),
        "seed": SEED,
        "sources": {
            "phishtank_online_valid": {
                **phish_meta,
                "raw_rows": phish_rows,
                "verified_online_rows": len(fl.phishtank_urls(phish_text)),
                "unique_domains_after_sanitising": len(per_domain),
                "heavy_multi_url_domains_excluded": len(heavy),
                "heavy_url_threshold": HEAVY_URL_THRESHOLD,
                "rejections": dict(phish_rejections),
            },
            "openphish_public_feed": {
                **open_meta,
                "lines": len(open_text.splitlines()),
                "accepted_entries": stats["sources"]["openphish_public_feed"]["accepted_entries"],
            },
        },
        "label_policy": {
            **fl.POLICY,
            "positive_meaning": (
                "verified and online in PhishTank's public online-valid export, or listed by "
                "OpenPhish, at the recorded retrieval time; never a human verdict"
            ),
            "shared_hosts": (
                "multi-tenant, free-hosting and shortener domains are excluded because a "
                "domain-level malicious label would otherwise describe the platform"
            ),
            "heavy_multi_url_rule": (
                f"domains with at least {HEAVY_URL_THRESHOLD} distinct reported URLs are "
                "treated as platforms and excluded"
            ),
        },
        "filters": {
            "excluded_domains_from_prior_work": len(excluded),
            "excluded_domain_sources": exclusion_records,
            "shared_host_library_size": len(cand.FEED_DOMAIN_EXCLUSIONS),
            "heavy_domains_excluded": sorted(heavy),
            "label_rows": len(rows),
        },
        "sampling": {
            "positive_pool": len(rows),
            "positive_sample": len(sampled),
            "positive_reserve": len(reserve_sample),
            "positive_target_usable": TARGET_POSITIVE_USABLE,
            "seed": SEED,
            "selection": "sha256(namespace:seed:domain) ascending",
            "reserve_selection": (
                f"ranks {POSITIVE_SAMPLE + 1}-{POSITIVE_SAMPLE + len(reserve_sample)} of the same "
                "ranking; crawled only if the selected batches fall short of the usable target"
            ),
        },
        "negative_pool": (
            "sampled separately from Tranco top-1M, excluding every domain in the full positive "
            "pool and prior work; see negatives/negative_manifest.json"
        ),
        "gated_crawl_approval": (
            "2026-10-26 user approval for this candidate set; batches remain marked gated and "
            "need --allow-gated"
        ),
        "labels_sha256": _file_sha256(labels_path),
        "positives_sha256": _file_sha256(positives_path),
        "positives_reserve_sha256": _file_sha256(positives_reserve_path),
        "feed_label_stats": stats,
    }
    provenance_path = LABEL_DIR / "provenance.json"
    provenance_path.write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {
        "labels_path": labels_path,
        "positives_path": positives_path,
        "positives_reserve_path": positives_reserve_path,
        "provenance_path": provenance_path,
        "rows": rows,
        "sampled": sampled,
        "reserve_sample": reserve_sample,
        "provenance": provenance,
    }


def _read_tranco_zip(data: bytes) -> tuple[str, str]:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = [name for name in archive.namelist() if name.lower().endswith(".csv")]
        if not names:
            raise SystemExit("Tranco archive did not contain a CSV")
        return archive.read(names[0]).decode("utf-8-sig", errors="replace"), names[0]


def build_negatives(
    positive_domains: Iterable[str], excluded: set[str], *, offline: bool = False
) -> dict[str, Any]:
    if offline:
        existing = json.loads(
            (NEGATIVE_CANDIDATES / "negative_manifest.json").read_text(encoding="utf-8")
        )["tranco"]
        raw, meta = _replay_snapshot(existing)
    else:
        raw, meta = _fetch(TRANCO_URL, name="tranco_top-1m.csv.zip")
    tranco_text, member = _read_tranco_zip(raw)
    rows, parse_stats = cand.parse_tranco_rows(tranco_text)
    exclusion = set(positive_domains) | set(excluded)
    filtered = [row for row in rows if row[1] not in exclusion]

    NEGATIVE_CANDIDATES.mkdir(parents=True, exist_ok=True)
    exclusion_csv = LABEL_DIR / "exclusions.csv"
    with exclusion_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["domain", "url"])
        writer.writeheader()
        for domain in sorted(exclusion):
            writer.writerow({"domain": domain, "url": f"https://{domain}/"})

    candidates = cand.build_tranco_candidates(
        filtered, seed=SEED, source_date=meta["source_date"]
    )
    selected, reserve, stats = cand.select_main_candidates(
        candidates,
        [],
        counts={
            "established": NEGATIVES_ESTABLISHED,
            "tail": NEGATIVES_TAIL,
            "scam_feed": 0,
        },
        reserve_counts={
            "established": RESERVE_ESTABLISHED,
            "tail": RESERVE_TAIL,
            "scam_feed": 0,
        },
    )

    selected_path = NEGATIVE_CANDIDATES / "negatives.csv"
    reserve_path = NEGATIVE_CANDIDATES / "negatives_reserve.csv"
    selected_hash = cand._write_candidates(selected_path, selected)
    reserve_hash = cand._write_candidates(reserve_path, reserve)

    def split(items: Sequence[cand.Candidate], prefix: str) -> list[dict[str, Any]]:
        batches: list[dict[str, Any]] = []
        for number, start in enumerate(range(0, len(items), BATCH_SIZE), start=1):
            chunk = items[start : start + BATCH_SIZE]
            path = NEGATIVE_CANDIDATES / f"{prefix}_{number:02d}.csv"
            digest = cand._write_candidates(path, chunk)
            batches.append(
                {
                    "batch": f"{prefix}_{number:02d}",
                    "path": _rel(path),
                    "sha256": digest,
                    "domains": len(chunk),
                }
            )
        return batches

    batches = split(selected, "neg")
    reserve_batches = split(reserve, "neg_reserve")
    manifest = {
        "schema_version": 1,
        "dataset": "feed_v3",
        "created_at": _now(),
        "seed": SEED,
        "tranco": {
            **meta,
            "member": member,
            "rows_parsed": len(rows),
            "parse_stats": parse_stats,
            "excluded_domains": len(exclusion),
            "rows_after_exclusion": len(filtered),
        },
        "selection": {
            "counts": {"established": NEGATIVES_ESTABLISHED, "tail": NEGATIVES_TAIL},
            "reserve": {"established": RESERVE_ESTABLISHED, "tail": RESERVE_TAIL},
            "stats": stats,
        },
        "negative_meaning": (
            "absent from PhishTank online-valid and OpenPhish at retrieval, sampled from the "
            "Tranco top-1M sampling frame; not verified clean"
        ),
        "files": {
            "selected": _rel(selected_path),
            "selected_sha256": selected_hash,
            "reserve": _rel(reserve_path),
            "reserve_sha256": reserve_hash,
        },
        "batches": batches,
        "reserve_batches": reserve_batches,
    }
    (NEGATIVE_CANDIDATES / "negative_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {
        "manifest": manifest,
        "selected": selected,
        "reserve": reserve,
        "exclusion_csv": exclusion_csv,
    }


def _normalise_feed_manifest(
    manifest: dict[str, Any], *, labels_path: Path, manifest_path: Path
) -> dict[str, Any]:
    manifest["labels_file"] = _rel(labels_path)
    for batch in manifest["batches"]:
        batch["file"] = _rel(Path(batch["file"]))
    manifest["approval"] = (
        "scoped approval recorded 2026-10-26 in collection_approval.json; every batch is "
        "gated and the batch command still requires --allow-gated"
    )
    manifest["approval_record"] = _rel(POSITIVE_CANDIDATES / "collection_approval.json")
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def build_positive_candidates(
    positives_path: Path, reserve_path: Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    if POSITIVE_CANDIDATES.exists():
        for path in POSITIVE_CANDIDATES.glob("feed_batch_*.csv"):
            path.unlink()
    if POSITIVE_RESERVE_DIR.exists():
        for path in POSITIVE_RESERVE_DIR.glob("feed_reserve_*.csv"):
            path.unlink()
    manifest = cand.build_feed_candidates(
        labels_path=positives_path,
        out_dir=POSITIVE_CANDIDATES,
        seed=SEED,
        batch_size=BATCH_SIZE,
        batch_prefix="feed_batch",
    )
    _normalise_feed_manifest(
        manifest,
        labels_path=positives_path,
        manifest_path=POSITIVE_CANDIDATES / "feed_manifest.json",
    )
    reserve_manifest = cand.build_feed_candidates(
        labels_path=reserve_path,
        out_dir=POSITIVE_RESERVE_DIR,
        seed=SEED,
        batch_size=BATCH_SIZE,
        batch_prefix="feed_reserve",
    )
    _normalise_feed_manifest(
        reserve_manifest,
        labels_path=reserve_path,
        manifest_path=POSITIVE_RESERVE_MANIFEST,
    )
    return manifest, reserve_manifest


def write_approval(
    *,
    positive_manifest: dict[str, Any],
    positive_reserve_manifest: dict[str, Any],
    negative_manifest: dict[str, Any],
    provenance: dict[str, Any],
) -> Path:
    approval = {
        "record_id": "feed_v3_gated_collection",
        "approved_at": "2026-10-26",
        "approved_by": "project owner (explicit user approval)",
        "scope": (
            "5,000 usable domains: about 2,500 PhishTank/OpenPhish positives and 2,500 Tranco "
            "negatives, plus positive and negative reserves; batches of at most 100"
        ),
        "constraints": [
            "bounded assessments only; no file downloads",
            "existing SSRF/public-IP validation stays enabled",
            "positive batches remain gated and require --allow-gated",
            "no new candidates may be added without fresh approval",
        ],
        "positive_batches": len(positive_manifest["batches"]),
        "positive_reserve_batches": len(positive_reserve_manifest["batches"]),
        "negative_batches": len(negative_manifest["batches"]),
        "negative_reserve_batches": len(negative_manifest.get("reserve_batches", [])),
        "positive_manifest_sha256": _file_sha256(POSITIVE_CANDIDATES / "feed_manifest.json"),
        "positive_reserve_manifest_sha256": _file_sha256(POSITIVE_RESERVE_MANIFEST),
        "negative_manifest_sha256": _file_sha256(
            NEGATIVE_CANDIDATES / "negative_manifest.json"
        ),
        "label_provenance_sha256": _file_sha256(LABEL_DIR / "provenance.json"),
        "expires_when": "the approved candidate batches and their reserves are exhausted",
        "source_retrieval": {
            name: source["retrieved_at"]
            for name, source in provenance["sources"].items()
        },
    }
    path = POSITIVE_CANDIDATES / "collection_approval.json"
    path.write_text(json.dumps(approval, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _read_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _collect_batches(
    entries: Sequence[dict[str, Any]],
    *,
    label: str,
    failures: list[dict[str, str]],
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for entry in entries:
        raw = str(entry.get("file") or entry.get("path") or "")
        path = Path(raw)
        if not path.is_absolute():
            path = ROOT / path
        name = str(entry.get("batch", raw))
        if not path.exists():
            failures.append(
                {"check": f"{label}_batch_present", "detail": f"{name}: missing {raw}"}
            )
            continue
        digest = _file_sha256(path)
        if digest != entry.get("sha256"):
            failures.append(
                {
                    "check": f"{label}_batch_hash",
                    "detail": f"{name}: {digest} != {entry.get('sha256')}",
                }
            )
        batch_rows = _read_rows(path)
        expected = entry.get("candidates", entry.get("domains"))
        if expected is not None and len(batch_rows) != expected:
            failures.append(
                {
                    "check": f"{label}_batch_rows",
                    "detail": f"{name}: {len(batch_rows)} rows != {expected}",
                }
            )
        domains = {row.get("domain", "") for row in batch_rows}
        if entry.get("domains") is not None and len(domains) != entry["domains"]:
            failures.append(
                {
                    "check": f"{label}_batch_domains",
                    "detail": f"{name}: {len(domains)} domains != {entry['domains']}",
                }
            )
        rows.extend(batch_rows)
    return rows


def _check_candidate_rows(
    rows: Sequence[dict[str, str]],
    *,
    label: str,
    gate: str,
    sources: set[str],
    failures: list[dict[str, str]],
) -> set[str]:
    counts: Counter[str] = Counter()
    for row in rows:
        domain = str(row.get("domain") or "")
        counts[domain] += 1
        raw = str(row.get("url") or "").strip()
        try:
            clean, resolved = cand.sanitize_candidate_url(raw)
        except cand.UnsafeURLError as exc:
            failures.append(
                {"check": f"{label}_url_safe", "detail": f"{domain or raw!r}: {exc}"}
            )
            continue
        if clean != raw:
            failures.append(
                {"check": f"{label}_url_canonical", "detail": f"{raw!r} -> {clean!r}"}
            )
        if resolved != domain:
            failures.append(
                {
                    "check": f"{label}_domain_match",
                    "detail": f"{raw!r}: {resolved!r} != {domain!r}",
                }
            )
        host = urlsplit(clean).hostname or ""
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            failures.append(
                {"check": f"{label}_no_ip_literal", "detail": f"{raw!r}"}
            )
        if str(row.get("collection_gate") or "") != gate:
            failures.append(
                {
                    "check": f"{label}_gate",
                    "detail": f"{domain}: {row.get('collection_gate')!r}",
                }
            )
        row_sources = {
            part.split("@")[0]
            for part in str(row.get("source") or "").split("+")
            if part
        }
        if not row_sources <= sources:
            failures.append(
                {
                    "check": f"{label}_source",
                    "detail": f"{domain}: {sorted(row_sources)}",
                }
            )
    duplicates = sorted(domain for domain, count in counts.items() if count > 1)
    if duplicates:
        failures.append(
            {
                "check": f"{label}_duplicate_domains",
                "detail": f"{len(duplicates)} duplicates, e.g. {duplicates[:5]}",
            }
        )
    return set(counts)


def _expect(
    failures: list[dict[str, str]],
    ok: bool,
    check: str,
    detail: str,
) -> None:
    if not ok:
        failures.append({"check": check, "detail": detail})


def verify() -> dict[str, Any]:
    """Re-check every manifest hash, count, overlap and URL before collection."""
    failures: list[dict[str, str]] = []
    provenance = json.loads((LABEL_DIR / "provenance.json").read_text(encoding="utf-8"))
    positive_manifest = json.loads(
        (POSITIVE_CANDIDATES / "feed_manifest.json").read_text(encoding="utf-8")
    )
    positive_reserve_manifest = json.loads(
        POSITIVE_RESERVE_MANIFEST.read_text(encoding="utf-8")
    )
    negative_manifest = json.loads(
        (NEGATIVE_CANDIDATES / "negative_manifest.json").read_text(encoding="utf-8")
    )

    labels_path = LABEL_DIR / "labels.csv"
    positives_path = LABEL_DIR / "positives.csv"
    positives_reserve_path = LABEL_DIR / "positives_reserve.csv"
    labels_hash = _file_sha256(labels_path)
    positives_hash = _file_sha256(positives_path)
    positives_reserve_hash = _file_sha256(positives_reserve_path)
    _expect(
        failures,
        labels_hash == provenance.get("labels_sha256"),
        "labels_hash_provenance",
        f"{labels_hash} != {provenance.get('labels_sha256')}",
    )
    _expect(
        failures,
        positives_hash == provenance.get("positives_sha256"),
        "positives_hash_provenance",
        f"{positives_hash} != {provenance.get('positives_sha256')}",
    )
    _expect(
        failures,
        positives_reserve_hash == provenance.get("positives_reserve_sha256"),
        "positives_reserve_hash_provenance",
        f"{positives_reserve_hash} != {provenance.get('positives_reserve_sha256')}",
    )
    _expect(
        failures,
        positives_hash == positive_manifest.get("labels_sha256"),
        "positives_hash_manifest",
        f"{positives_hash} != {positive_manifest.get('labels_sha256')}",
    )
    _expect(
        failures,
        positives_reserve_hash == positive_reserve_manifest.get("labels_sha256"),
        "positives_reserve_hash_manifest",
        f"{positives_reserve_hash} != {positive_reserve_manifest.get('labels_sha256')}",
    )

    label_rows = _read_rows(labels_path)
    label_domains = {row["domain"] for row in label_rows}
    _expect(
        failures,
        len(label_domains) == len(label_rows),
        "label_domain_unique",
        f"{len(label_rows)} rows, {len(label_domains)} domains",
    )
    _expect(
        failures,
        all(row.get("label", "").strip().lower() == "malicious" for row in label_rows),
        "label_values",
        "every feed_v3 label must be malicious",
    )
    positive_selected = {row["domain"] for row in _read_rows(positives_path)}

    positive_rows = _collect_batches(
        positive_manifest.get("batches", []), label="positive", failures=failures
    )
    positive_reserve_rows = _collect_batches(
        positive_reserve_manifest.get("batches", []),
        label="positive_reserve",
        failures=failures,
    )
    negative_rows = _collect_batches(
        negative_manifest.get("batches", []), label="negative", failures=failures
    )
    reserve_rows = _collect_batches(
        negative_manifest.get("reserve_batches", []), label="reserve", failures=failures
    )
    positives = _check_candidate_rows(
        positive_rows,
        label="positive",
        gate=cand.GATED_COLLECTION,
        sources={"phishtank_online_valid", "openphish_public_feed"},
        failures=failures,
    )
    positive_reserves = _check_candidate_rows(
        positive_reserve_rows,
        label="positive_reserve",
        gate=cand.GATED_COLLECTION,
        sources={"phishtank_online_valid", "openphish_public_feed"},
        failures=failures,
    )
    negatives = _check_candidate_rows(
        negative_rows,
        label="negative",
        gate=cand.STANDARD_COLLECTION,
        sources={"tranco_top_1m"},
        failures=failures,
    )
    reserves = _check_candidate_rows(
        reserve_rows,
        label="reserve",
        gate=cand.STANDARD_COLLECTION,
        sources={"tranco_top_1m"},
        failures=failures,
    )

    _expect(
        failures,
        len(positive_rows) == positive_manifest.get("candidates"),
        "positive_total",
        f"{len(positive_rows)} rows != {positive_manifest.get('candidates')}",
    )
    _expect(
        failures,
        len(positives) == positive_manifest.get("domains"),
        "positive_domain_total",
        f"{len(positives)} domains != {positive_manifest.get('domains')}",
    )
    _expect(
        failures,
        len(positive_reserve_rows) == positive_reserve_manifest.get("candidates"),
        "positive_reserve_total",
        f"{len(positive_reserve_rows)} rows != {positive_reserve_manifest.get('candidates')}",
    )
    _expect(
        failures,
        len(positive_reserves) == positive_reserve_manifest.get("domains"),
        "positive_reserve_domain_total",
        f"{len(positive_reserves)} domains != {positive_reserve_manifest.get('domains')}",
    )
    _expect(
        failures,
        positive_selected <= label_domains,
        "positive_pool_in_labels",
        f"{len(positive_selected - label_domains)} positive_sample domains absent from labels.csv",
    )
    missing = sorted(positives - label_domains)
    _expect(
        failures,
        not missing,
        "positive_domain_labelled",
        f"{len(missing)} positive domains absent from labels.csv, e.g. {missing[:5]}",
    )
    missing = sorted(positive_reserves - label_domains)
    _expect(
        failures,
        not missing,
        "positive_reserve_domain_labelled",
        f"{len(missing)} positive reserve domains absent from labels.csv, e.g. {missing[:5]}",
    )
    overlap = positives & positive_reserves
    _expect(
        failures,
        not overlap,
        "positive_positive_reserve_overlap",
        f"{len(overlap)} domains, e.g. {sorted(overlap)[:5]}",
    )

    heavy = set(provenance.get("filters", {}).get("heavy_domains_excluded", []))
    prior, prior_records = collect_exclusions()

    for name, group in (
        ("positive", positives),
        ("positive_reserve", positive_reserves),
        ("negative", negatives),
        ("reserve", reserves),
    ):
        overlap = group & heavy
        _expect(
            failures,
            not overlap,
            f"{name}_heavy_overlap",
            f"{len(overlap)} shared-host/heavy domains, e.g. {sorted(overlap)[:5]}",
        )
        overlap = group & prior
        _expect(
            failures,
            not overlap,
            f"{name}_prior_work_overlap",
            f"{len(overlap)} prior-work domains, e.g. {sorted(overlap)[:5]}",
        )

    for name, group in (("negative", negatives), ("reserve", reserves)):
        overlap = group & label_domains
        _expect(
            failures,
            not overlap,
            f"{name}_positive_pool_overlap",
            f"{len(overlap)} domains, e.g. {sorted(overlap)[:5]}",
        )

    for name_a, group_a, name_b, group_b in (
        ("positive", positives, "negative", negatives),
        ("positive", positives, "reserve", reserves),
        ("positive_reserve", positive_reserves, "negative", negatives),
        ("positive_reserve", positive_reserves, "reserve", reserves),
        ("negative", negatives, "reserve", reserves),
    ):
        overlap = group_a & group_b
        _expect(
            failures,
            not overlap,
            f"{name_a}_{name_b}_overlap",
            f"{len(overlap)} domains, e.g. {sorted(overlap)[:5]}",
        )

    files = negative_manifest.get("files", {})
    selected_path = ROOT / files.get("selected", "")
    reserve_path = ROOT / files.get("reserve", "")
    if selected_path.exists():
        _expect(
            failures,
            _file_sha256(selected_path) == files.get("selected_sha256"),
            "negative_file_hash",
            str(selected_path),
        )
        _expect(
            failures,
            {row["domain"] for row in _read_rows(selected_path)} == negatives,
            "negative_file_domains",
            str(selected_path),
        )
    else:
        failures.append({"check": "negative_file_present", "detail": str(selected_path)})
    if reserve_path.exists():
        _expect(
            failures,
            _file_sha256(reserve_path) == files.get("reserve_sha256"),
            "reserve_file_hash",
            str(reserve_path),
        )
        _expect(
            failures,
            {row["domain"] for row in _read_rows(reserve_path)} == reserves,
            "reserve_file_domains",
            str(reserve_path),
        )
    else:
        failures.append({"check": "reserve_file_present", "detail": str(reserve_path)})

    approval_path = POSITIVE_CANDIDATES / "collection_approval.json"
    if approval_path.exists():
        approval = json.loads(approval_path.read_text(encoding="utf-8"))
        _expect(
            failures,
            approval.get("approved_at") == "2026-10-26",
            "approval_date",
            str(approval.get("approved_at")),
        )
        _expect(
            failures,
            approval.get("positive_batches") == len(positive_manifest.get("batches", [])),
            "approval_positive_batches",
            str(approval.get("positive_batches")),
        )
        _expect(
            failures,
            approval.get("positive_reserve_batches")
            == len(positive_reserve_manifest.get("batches", [])),
            "approval_positive_reserve_batches",
            str(approval.get("positive_reserve_batches")),
        )
        _expect(
            failures,
            approval.get("negative_batches") == len(negative_manifest.get("batches", [])),
            "approval_negative_batches",
            str(approval.get("negative_batches")),
        )
        _expect(
            failures,
            approval.get("negative_reserve_batches")
            == len(negative_manifest.get("reserve_batches", [])),
            "approval_negative_reserve_batches",
            str(approval.get("negative_reserve_batches")),
        )
        _expect(
            failures,
            approval.get("positive_manifest_sha256")
            == _file_sha256(POSITIVE_CANDIDATES / "feed_manifest.json"),
            "approval_positive_manifest_hash",
            "feed_manifest.json changed after approval",
        )
        _expect(
            failures,
            approval.get("positive_reserve_manifest_sha256")
            == _file_sha256(POSITIVE_RESERVE_MANIFEST),
            "approval_positive_reserve_manifest_hash",
            "feed_reserve_manifest.json changed after approval",
        )
        _expect(
            failures,
            approval.get("negative_manifest_sha256")
            == _file_sha256(NEGATIVE_CANDIDATES / "negative_manifest.json"),
            "approval_negative_manifest_hash",
            "negative_manifest.json changed after approval",
        )
        _expect(
            failures,
            approval.get("label_provenance_sha256")
            == _file_sha256(LABEL_DIR / "provenance.json"),
            "approval_provenance_hash",
            "provenance.json changed after approval",
        )
    else:
        failures.append({"check": "approval_present", "detail": str(approval_path)})

    report = {
        "ok": not failures,
        "checked_at": _now(),
        "failures": failures,
        "stats": {
            "label_rows": len(label_rows),
            "positive_candidates": len(positive_rows),
            "positive_domains": len(positives),
            "positive_batches": len(positive_manifest.get("batches", [])),
            "positive_reserve_candidates": len(positive_reserve_rows),
            "positive_reserve_domains": len(positive_reserves),
            "positive_reserve_batches": len(positive_reserve_manifest.get("batches", [])),
            "negative_candidates": len(negative_rows),
            "negative_domains": len(negatives),
            "negative_batches": len(negative_manifest.get("batches", [])),
            "reserve_candidates": len(reserve_rows),
            "reserve_domains": len(reserves),
            "reserve_batches": len(negative_manifest.get("reserve_batches", [])),
            "prior_work_domains": len(prior),
            "heavy_domains_excluded": len(heavy),
        },
        "overlaps": {
            "positive_negative": len(positives & negatives),
            "positive_reserve": len(positives & reserves),
            "positive_positive_reserve": len(positives & positive_reserves),
            "positive_reserve_negative": len(positive_reserves & negatives),
            "positive_reserve_reserve": len(positive_reserves & reserves),
            "negative_reserve": len(negatives & reserves),
            "negative_positive_pool": len(negatives & label_domains),
            "reserve_positive_pool": len(reserves & label_domains),
        },
        "prior_work_sources": prior_records,
    }
    (LABEL_DIR / "validation.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--verify",
        action="store_true",
        help="re-check existing manifests, hashes, overlaps and URLs without fetching anything",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="rebuild from the recorded snapshots instead of fetching the feeds again",
    )
    args = parser.parse_args(argv)
    if args.verify:
        report = verify()
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["ok"] else 1

    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    built = build_labels(offline=args.offline)
    excluded, _ = collect_exclusions()
    negatives = build_negatives(
        [row["domain"] for row in built["rows"]], excluded, offline=args.offline
    )
    positive_manifest, positive_reserve_manifest = build_positive_candidates(
        built["positives_path"], built["positives_reserve_path"]
    )
    approval_path = write_approval(
        positive_manifest=positive_manifest,
        positive_reserve_manifest=positive_reserve_manifest,
        negative_manifest=negatives["manifest"],
        provenance=built["provenance"],
    )
    report = verify()
    print(
        json.dumps(
            {
                "labels": str(built["labels_path"].relative_to(ROOT)),
                "label_domains": len(built["rows"]),
                "positive_candidates": positive_manifest["candidates"],
                "positive_batches": len(positive_manifest["batches"]),
                "positive_reserve_candidates": positive_reserve_manifest["candidates"],
                "positive_reserve_batches": len(positive_reserve_manifest["batches"]),
                "negative_candidates": len(negatives["selected"]),
                "negative_batches": len(negatives["manifest"]["batches"]),
                "negative_reserve_candidates": len(negatives["reserve"]),
                "negative_reserve_batches": len(negatives["manifest"]["reserve_batches"]),
                "approval": str(approval_path.relative_to(ROOT)),
                "verification_ok": report["ok"],
                "verification_failures": len(report["failures"]),
            },
            indent=2,
        )
    )
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
