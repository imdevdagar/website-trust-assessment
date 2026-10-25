"""Build the gated Round 2 mixed-calibration candidate manifest.

Only URL metadata is handled here. Candidate pages are never fetched. Feed
candidates retain their public URL (query and fragment removed) but are marked
for explicit confirmation before any assessment is collected.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit, urlunsplit

from ..security import EXTRACTOR, UnsafeURLError, check_url_structure

ROUND2_STRATA = ("scam_feed", "ambiguous", "benign_control")
CURATED_STRATA = ("ambiguous", "benign_control")
DEFAULT_COUNTS = {"scam_feed": 20, "ambiguous": 8, "benign_control": 8}
DEFAULT_RESERVE = {"scam_feed": 20, "ambiguous": 4, "benign_control": 4}
GATED_COLLECTION = "malicious_page_requires_explicit_confirmation"
STANDARD_COLLECTION = "standard_annotation_safety_rules"
FEED_SOURCE = "openphish_public_feed"
MAIN_STRATA = ("established", "tail", "scam_feed")
MAIN_DEFAULT_COUNTS = {"established": 260, "tail": 100, "scam_feed": 140}
MAIN_DEFAULT_RESERVE = {"established": 80, "tail": 30, "scam_feed": 50}
MAIN_BANDS = {"established": (1, 50000), "tail": (50001, 1000000)}
MAIN_FEED_NOTE = (
    "Public feed candidate, not a label. Feed metadata only; verify the live page "
    "before labelling. Query string and fragment were removed."
)
MAIN_BINARY_EXTENSIONS = frozenset(
    {
        ".7z", ".apk", ".avi", ".bat", ".bin", ".cmd", ".css", ".deb", ".dll",
        ".dmg", ".doc", ".docm", ".exe", ".gif", ".gz", ".img", ".iso", ".jar",
        ".jpeg", ".jpg", ".js", ".m4a", ".mov", ".mp3", ".mp4", ".msi", ".pdf",
        ".pkg", ".png", ".ps1", ".rar", ".rpm", ".scr", ".sh", ".svg", ".tar",
        ".tgz", ".ttf", ".vbs", ".webp", ".woff", ".woff2", ".xls", ".xlsm",
        ".zip",
    }
)
CANDIDATE_FIELDS = (
    "candidate_id",
    "url",
    "domain",
    "stratum",
    "candidate_family",
    "source",
    "source_date",
    "collection_gate",
    "verification_required",
    "notes",
)
FEED_NOTE = (
    "Public feed candidate, not a label. Feed metadata only; verify the live page "
    "before labelling. Query string and fragment were removed."
)

# The sampling unit is the registrable domain. A feed hit on a free host,
# shortener, CDN, or major shared platform would attach a malicious label to the
# platform rather than to the page owner, so these are excluded from discovery.
FEED_DOMAIN_EXCLUSIONS = frozenset(
    {
        "000webhostapp.com",
        "akamai.net",
        "akamaized.net",
        "amazonaws.com",
        "appspot.com",
        "azure.com",
        "azurewebsites.net",
        "beacons.ai",
        "bio.link",
        "bit.ly",
        "bitly.com",
        "blogger.com",
        "blogspot.com",
        "bolt.host",
        "box.com",
        "business.site",
        "byet.host",
        "cargo.site",
        "carrd.co",
        "cloudapp.net",
        "cloudflare.com",
        "cloudfront.net",
        "craftum.io",
        "cutt.ly",
        "cyclic.app",
        "ddns.net",
        "deno.dev",
        "discord.com",
        "docs.google.com",
        "dropbox.com",
        "duckdns.org",
        "dynu.net",
        "epizy.com",
        "facebook.com",
        "fastly.net",
        "firebaseapp.com",
        "flazio.online",
        "fly.dev",
        "forms.gle",
        "framer.app",
        "framer.website",
        "ghost.io",
        "github.com",
        "github.io",
        "gitlab.com",
        "gitlab.io",
        "glitch.me",
        "godaddy.com",
        "godaddysites.com",
        "google.com",
        "goo.gl",
        "herokuapp.com",
        "hopto.org",
        "infinityfreeapp.com",
        "instagram.com",
        "is-a.dev",
        "is.gd",
        "jimdosite.com",
        "koyeb.app",
        "laravel.cloud",
        "linkedin.com",
        "linktr.ee",
        "lovable.app",
        "maglit.me",
        "medium.com",
        "microsoft.com",
        "myshopify.com",
        "mystrikingly.com",
        "netlify.app",
        "ngrok.app",
        "ngrok.io",
        "no-ip.com",
        "no-ip.org",
        "notion.site",
        "now.sh",
        "office.com",
        "onamaeweb.jp",
        "onedrive.live.com",
        "onrender.com",
        "ow.ly",
        "pages.dev",
        "paypal.com",
        "r2.dev",
        "railway.app",
        "rb.gy",
        "rebrand.ly",
        "reddit.com",
        "redirecionar.com",
        "replit.app",
        "repl.co",
        "rf.gd",
        "sharepoint.com",
        "shopify.com",
        "shorturl.at",
        "sites.google.com",
        "snip.ly",
        "spoo.me",
        "spotify.com",
        "square.site",
        "squarespace.com",
        "strikingly.com",
        "stripe.com",
        "substack.com",
        "surge.sh",
        "t.co",
        "t.me",
        "telegram.org",
        "tiktok.com",
        "tinyurl.com",
        "trafficmanager.net",
        "twitter.com",
        "typedream.app",
        "vercel.app",
        "web.app",
        "webflow.com",
        "webflow.io",
        "weebly.com",
        "weeblysite.com",
        "webnode.page",
        "wikipedia.org",
        "wix.com",
        "wixsite.com",
        "wordpress.com",
        "wordpress.org",
        "workers.dev",
        "wp.com",
        "x.com",
        "yahoo.com",
        "youtube.com",
        "zapto.org",
    }
)
EMAIL_IN_PATH = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)


@dataclass(frozen=True)
class Candidate:
    candidate_id: str
    url: str
    domain: str
    stratum: str
    candidate_family: str
    source: str
    source_date: str
    notes: str
    collection_gate: str
    verification_required: str
    rank: str = field(repr=False, compare=False)

    def row(self) -> dict[str, str]:
        return {name: getattr(self, name) for name in CANDIDATE_FIELDS}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _candidate_id(seed: int, domain: str, prefix: str = "r2") -> str:
    digest = hashlib.sha256(f"{seed}:{domain}".encode("utf-8")).hexdigest()
    return f"{prefix}_{digest[:10]}"


def _selection_rank(seed: int, stratum: str, domain: str) -> str:
    return hashlib.sha256(f"{seed}:{stratum}:{domain}".encode("utf-8")).hexdigest()


def _url_rank(seed: int, domain: str, url: str) -> str:
    return hashlib.sha256(f"{seed}:url:{domain}:{url}".encode("utf-8")).hexdigest()


def sanitize_candidate_url(raw: str) -> tuple[str, str]:
    """Return a query-free http(s) URL and its registrable domain.

    Raises UnsafeURLError for credentials, non-standard ports, internal/IP
    hosts, unknown suffixes, or paths containing an email address.
    """
    value = str(raw or "").strip()
    if not value:
        raise UnsafeURLError("empty URL")
    try:
        parsed = urlsplit(value)
    except ValueError:
        raise UnsafeURLError("URL could not be parsed") from None
    if parsed.scheme.lower() not in {"http", "https"}:
        raise UnsafeURLError("only http:// and https:// URLs are accepted")
    clean = urlunsplit(
        (parsed.scheme.lower(), parsed.netloc, parsed.path or "/", "", "")
    )
    parts = check_url_structure(clean)
    if parts.is_ip:
        raise UnsafeURLError("IP-literal candidates are outside the domain sample")
    if "." not in parts.registrable_domain:
        raise UnsafeURLError("URL has no registrable domain")
    if not EXTRACTOR(parts.host).suffix:
        raise UnsafeURLError("host has no public suffix in the bundled PSL")
    if EMAIL_IN_PATH.search(parts.path):
        raise UnsafeURLError("path appears to contain an email address")
    return parts.url, parts.registrable_domain


def load_pilot_domains(path: Path) -> set[str]:
    if not path.exists():
        raise FileNotFoundError(f"pilot candidate file not found: {path}")
    domains: set[str] = set()
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            try:
                _, domain = sanitize_candidate_url(row.get("url", ""))
            except UnsafeURLError:
                continue
            domains.add(domain)
    return domains


def _make_candidate(
    *,
    seed: int,
    url: str,
    domain: str,
    stratum: str,
    candidate_family: str,
    source: str,
    source_date: str,
    notes: str,
    collection_gate: str,
    verification_required: str,
    candidate_prefix: str = "r2",
) -> Candidate:
    return Candidate(
        candidate_id=_candidate_id(seed, domain, candidate_prefix),
        url=url,
        domain=domain,
        stratum=stratum,
        candidate_family=candidate_family,
        source=source,
        source_date=source_date,
        notes=notes,
        collection_gate=collection_gate,
        verification_required=verification_required,
        rank=_selection_rank(seed, stratum, domain),
    )


def load_curated_candidates(
    path: Path,
    *,
    seed: int,
) -> tuple[list[Candidate], dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"curated candidate file not found: {path}")
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = [dict(row) for row in csv.DictReader(handle)]
    accepted: list[Candidate] = []
    seen: set[str] = set()
    skipped: Counter[str] = Counter()
    for index, row in enumerate(rows, start=2):
        stratum = str(row.get("stratum") or "").strip().lower()
        if stratum not in CURATED_STRATA:
            raise ValueError(
                f"{path}:{index}: stratum must be one of {CURATED_STRATA}, got {stratum!r}"
            )
        if str(row.get("label") or row.get("target") or "").strip():
            raise ValueError(f"{path}:{index}: candidate sources must not contain labels")
        try:
            url, domain = sanitize_candidate_url(row.get("url", ""))
        except UnsafeURLError as exc:
            raise ValueError(f"{path}:{index}: {exc}") from None
        if domain in seen:
            skipped["duplicate_domain"] += 1
            continue
        notes = str(row.get("notes") or "").strip()
        if not notes:
            raise ValueError(f"{path}:{index}: notes are required")
        source_date = str(row.get("source_date") or "").strip()
        if not source_date:
            raise ValueError(f"{path}:{index}: source_date is required")
        accepted.append(
            _make_candidate(
                seed=seed,
                url=url,
                domain=domain,
                stratum=stratum,
                candidate_family=str(row.get("candidate_family") or "unclassified").strip(),
                source=str(row.get("source") or "manual_curated").strip(),
                source_date=source_date,
                notes=notes,
                collection_gate=STANDARD_COLLECTION,
                verification_required="false",
            )
        )
        seen.add(domain)
    stats = {
        "path": str(path),
        "sha256": _sha256_file(path),
        "rows": len(rows),
        "accepted": len(accepted),
        "skipped": dict(skipped),
    }
    return accepted, stats


def _likely_html_path(url: str) -> bool:
    path = urlsplit(url).path.lower()
    if not path or path == "/" or path.endswith("/"):
        return True
    segment = path.rsplit("/", 1)[-1]
    if "." not in segment:
        return True
    extension = "." + segment.rsplit(".", 1)[-1]
    return extension not in MAIN_BINARY_EXTENSIONS


def parse_feed_candidates(
    text: str,
    *,
    seed: int,
    source_date: str,
    excluded_domains: set[str] | None = None,
    source: str = FEED_SOURCE,
    candidate_family: str = "unclassified_feed",
    candidate_prefix: str = "r2",
    html_only: bool = False,
    notes: str = FEED_NOTE,
) -> tuple[list[Candidate], dict[str, Any]]:
    excluded_domains = set(excluded_domains or ())
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    rejected: Counter[str] = Counter()
    by_domain: dict[str, Candidate] = {}
    for line in lines:
        if line.startswith("#"):
            rejected["comment"] += 1
            continue
        try:
            url, domain = sanitize_candidate_url(line)
        except UnsafeURLError as exc:
            reason = str(exc)
            if "email" in reason:
                rejected["email_in_path"] += 1
            elif "IP-literal" in reason:
                rejected["ip_literal"] += 1
            elif "public suffix" in reason:
                rejected["no_public_suffix"] += 1
            elif "Non-standard ports" in reason:
                rejected["nonstandard_port"] += 1
            else:
                rejected["unsafe_or_malformed"] += 1
            continue
        if domain in FEED_DOMAIN_EXCLUSIONS:
            rejected["shared_or_multitenant_domain"] += 1
            continue
        if domain in excluded_domains:
            rejected["excluded_overlap"] += 1
            continue
        if html_only and not _likely_html_path(url):
            rejected["non_html_download_path"] += 1
            continue
        candidate = _make_candidate(
            seed=seed,
            url=url,
            domain=domain,
            stratum="scam_feed",
            candidate_family=candidate_family,
            source=source,
            source_date=source_date,
            notes=notes,
            collection_gate=GATED_COLLECTION,
            verification_required="true",
            candidate_prefix=candidate_prefix,
        )
        existing = by_domain.get(domain)
        if existing is None or _url_rank(seed, domain, url) < _url_rank(
            seed, domain, existing.url
        ):
            by_domain[domain] = candidate
    stats = {
        "lines": len(lines),
        "unique_usable_domains": len(by_domain),
        "rejected": dict(rejected),
    }
    return list(by_domain.values()), stats


def select_round2_candidates(
    curated: Sequence[Candidate],
    feed: Sequence[Candidate],
    *,
    counts: dict[str, int] | None = None,
    reserve_counts: dict[str, int] | None = None,
) -> tuple[list[Candidate], list[Candidate], dict[str, Any]]:
    counts = {**DEFAULT_COUNTS, **(counts or {})}
    reserve_counts = {**DEFAULT_RESERVE, **(reserve_counts or {})}
    for stratum in ROUND2_STRATA:
        if counts.get(stratum, 0) < 0 or reserve_counts.get(stratum, 0) < 0:
            raise ValueError("candidate counts and reserve counts must be non-negative")
    selected: dict[str, list[Candidate]] = {name: [] for name in ROUND2_STRATA}
    reserve: dict[str, list[Candidate]] = {name: [] for name in ROUND2_STRATA}
    seen: set[str] = {candidate.domain for candidate in curated}
    curated_by_stratum = {
        stratum: sorted(
            (candidate for candidate in curated if candidate.stratum == stratum),
            key=lambda candidate: candidate.rank,
        )
        for stratum in CURATED_STRATA
    }
    for stratum in CURATED_STRATA:
        for candidate in curated_by_stratum[stratum]:
            if len(selected[stratum]) < counts[stratum]:
                selected[stratum].append(candidate)
            elif len(reserve[stratum]) < reserve_counts[stratum]:
                reserve[stratum].append(candidate)
    for candidate in sorted(feed, key=lambda item: item.rank):
        if candidate.domain in seen:
            continue
        seen.add(candidate.domain)
        if len(selected["scam_feed"]) < counts["scam_feed"]:
            selected["scam_feed"].append(candidate)
        elif len(reserve["scam_feed"]) < reserve_counts["scam_feed"]:
            reserve["scam_feed"].append(candidate)
    shortfalls = {
        stratum: {
            "requested": counts[stratum],
            "available": len(selected[stratum]),
        }
        for stratum in ROUND2_STRATA
        if len(selected[stratum]) < counts[stratum]
    }
    if shortfalls:
        raise ValueError(
            "not enough distinct candidates after safety and overlap filters: "
            + json.dumps(shortfalls, sort_keys=True)
        )
    selected_rows = [
        candidate
        for stratum in ROUND2_STRATA
        for candidate in sorted(selected[stratum], key=lambda item: item.domain)
    ]
    reserve_rows = [
        candidate
        for stratum in ROUND2_STRATA
        for candidate in sorted(reserve[stratum], key=lambda item: item.domain)
    ]
    stats = {
        "selected": {name: len(items) for name, items in selected.items()},
        "reserve": {name: len(items) for name, items in reserve.items()},
        "feed_domains_matching_curated": sum(
            1 for candidate in feed if candidate.domain in {item.domain for item in curated}
        ),
    }
    return selected_rows, reserve_rows, stats


def load_candidate_domains(path: Path) -> set[str]:
    """Return registrable domains from a candidate CSV, ignoring unsafe rows."""
    if not path.exists():
        raise FileNotFoundError(f"candidate file not found: {path}")
    domains: set[str] = set()
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            try:
                _, domain = sanitize_candidate_url(row.get("url", ""))
            except UnsafeURLError:
                continue
            domains.add(domain)
    return domains


def parse_tranco_rows(text: str) -> tuple[list[tuple[int, str, str]], dict[str, Any]]:
    """Parse a Tranco ``rank,domain`` CSV snapshot without fetching any site."""
    lines = [line for line in text.splitlines() if line.strip()]
    rejected: Counter[str] = Counter()
    seen: set[str] = set()
    rows: list[tuple[int, str, str]] = []
    for row in csv.reader(io.StringIO(text)):
        if not row:
            continue
        rank_raw = row[0].strip().lstrip("\ufeff")
        domain_raw = row[1].strip() if len(row) > 1 else ""
        if rank_raw.lower() == "rank":
            rejected["header"] += 1
            continue
        try:
            rank = int(rank_raw)
        except ValueError:
            rejected["malformed_rank"] += 1
            continue
        if not 1 <= rank <= 1_000_000:
            rejected["rank_out_of_range"] += 1
            continue
        if not domain_raw:
            rejected["missing_domain"] += 1
            continue
        try:
            url, domain = sanitize_candidate_url(f"http://{domain_raw}/")
        except UnsafeURLError as exc:
            reason = str(exc)
            if "IP-literal" in reason:
                rejected["ip_literal"] += 1
            elif "public suffix" in reason:
                rejected["no_public_suffix"] += 1
            elif "Non-standard ports" in reason:
                rejected["nonstandard_port"] += 1
            else:
                rejected["unsafe_or_malformed"] += 1
            continue
        if domain in seen:
            rejected["duplicate_domain"] += 1
            continue
        seen.add(domain)
        rows.append((rank, domain, url))
    rows.sort()
    stats = {
        "lines": len(lines),
        "unique_domains": len(rows),
        "rejected": dict(rejected),
        "rank_min": rows[0][0] if rows else None,
        "rank_max": rows[-1][0] if rows else None,
    }
    return rows, stats


def build_tranco_candidates(
    rows: Sequence[tuple[int, str, str]],
    *,
    seed: int,
    source_date: str,
) -> dict[str, list[Candidate]]:
    grouped: dict[str, list[Candidate]] = {name: [] for name in ("established", "tail")}
    for rank, domain, url in rows:
        if rank <= MAIN_BANDS["established"][1]:
            stratum = "established"
        elif rank <= MAIN_BANDS["tail"][1]:
            stratum = "tail"
        else:
            continue
        low, high = MAIN_BANDS[stratum]
        grouped[stratum].append(
            _make_candidate(
                seed=seed,
                url=url,
                domain=domain,
                stratum=stratum,
                candidate_family=f"tranco_rank_{low}_{high}",
                source="tranco_top_1m",
                source_date=source_date,
                notes=(
                    f"Tranco top-1M rank band {low}-{high}. Ranking is a sampling frame, "
                    "not a feature or a label."
                ),
                collection_gate=STANDARD_COLLECTION,
                verification_required="false",
                candidate_prefix="m",
            )
        )
    return grouped


def select_main_candidates(
    tranco: Mapping[str, Sequence[Candidate]],
    feed: Sequence[Candidate],
    *,
    counts: dict[str, int] | None = None,
    reserve_counts: dict[str, int] | None = None,
) -> tuple[list[Candidate], list[Candidate], dict[str, Any]]:
    counts = {**MAIN_DEFAULT_COUNTS, **(counts or {})}
    reserve_counts = {**MAIN_DEFAULT_RESERVE, **(reserve_counts or {})}
    for stratum in MAIN_STRATA:
        if counts.get(stratum, 0) < 0 or reserve_counts.get(stratum, 0) < 0:
            raise ValueError("candidate counts and reserve counts must be non-negative")
    selected: dict[str, list[Candidate]] = {name: [] for name in MAIN_STRATA}
    reserve: dict[str, list[Candidate]] = {name: [] for name in MAIN_STRATA}
    seen: set[str] = set()

    for stratum in ("established", "tail"):
        for candidate in sorted(tranco.get(stratum, ()), key=lambda item: item.rank):
            if candidate.domain in seen:
                continue
            if len(selected[stratum]) < counts[stratum]:
                selected[stratum].append(candidate)
                seen.add(candidate.domain)
            elif len(reserve[stratum]) < reserve_counts[stratum]:
                reserve[stratum].append(candidate)
                seen.add(candidate.domain)

    for candidate in sorted(feed, key=lambda item: item.rank):
        if candidate.domain in seen:
            continue
        if len(selected["scam_feed"]) < counts["scam_feed"]:
            selected["scam_feed"].append(candidate)
            seen.add(candidate.domain)
        elif len(reserve["scam_feed"]) < reserve_counts["scam_feed"]:
            reserve["scam_feed"].append(candidate)
            seen.add(candidate.domain)

    shortfalls = {
        stratum: {
            "requested": counts[stratum],
            "available": len(selected[stratum]),
        }
        for stratum in MAIN_STRATA
        if len(selected[stratum]) < counts[stratum]
    }
    if shortfalls:
        raise ValueError(
            "not enough distinct candidates after safety and overlap filters: "
            + json.dumps(shortfalls, sort_keys=True)
        )
    selected_rows = [
        candidate
        for stratum in MAIN_STRATA
        for candidate in sorted(selected[stratum], key=lambda item: item.domain)
    ]
    reserve_rows = [
        candidate
        for stratum in MAIN_STRATA
        for candidate in sorted(reserve[stratum], key=lambda item: item.domain)
    ]
    stats = {
        "selected": {name: len(items) for name, items in selected.items()},
        "reserve": {name: len(items) for name, items in reserve.items()},
        "feed_domains_matching_tranco": sum(
            1
            for candidate in feed
            if candidate.domain
            in {item.domain for items in tranco.values() for item in items}
        ),
    }
    return selected_rows, reserve_rows, stats


def build_main_manifest(
    *,
    tranco_text: str,
    tranco_meta: dict[str, Any],
    feeds: Sequence[dict[str, Any]],
    exclusion_paths: Sequence[Path],
    out_dir: Path,
    seed: int = 42,
    counts: dict[str, int] | None = None,
    reserve_counts: dict[str, int] | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """Build the main Tranco + public-feed manifest without opening a page."""
    counts = {**MAIN_DEFAULT_COUNTS, **(counts or {})}
    reserve_counts = {**MAIN_DEFAULT_RESERVE, **(reserve_counts or {})}
    source_date = str(
        tranco_meta.get("source_date") or datetime.now(timezone.utc).date().isoformat()
    )

    exclusion_domains: set[str] = set()
    exclusion_records: list[dict[str, Any]] = []
    for path in exclusion_paths:
        domains = load_candidate_domains(path)
        exclusion_domains |= domains
        exclusion_records.append(
            {
                "path": str(path),
                "sha256": _sha256_file(path),
                "domains": len(domains),
            }
        )

    raw_rows, tranco_stats = parse_tranco_rows(tranco_text)
    rows = [row for row in raw_rows if row[1] not in exclusion_domains]
    tranco_stats["excluded_overlap_domains"] = len(raw_rows) - len(rows)
    tranco_candidates = build_tranco_candidates(rows, seed=seed, source_date=source_date)

    tranco_selected, tranco_reserve, _ = select_main_candidates(
        tranco_candidates,
        [],
        counts={"established": counts["established"], "tail": counts["tail"], "scam_feed": 0},
        reserve_counts={
            "established": reserve_counts["established"],
            "tail": reserve_counts["tail"],
            "scam_feed": 0,
        },
    )
    feed_excluded = exclusion_domains | {
        candidate.domain for candidate in (*tranco_selected, *tranco_reserve)
    }

    combined_feed: dict[str, Candidate] = {}
    feed_records: list[dict[str, Any]] = []
    duplicates_across_feeds = 0
    for descriptor in feeds:
        feed_text = str(descriptor.get("text") or "")
        meta = dict(descriptor.get("meta") or {})
        feed_candidates, feed_stats = parse_feed_candidates(
            feed_text,
            seed=seed,
            source_date=str(meta.get("source_date") or source_date),
            excluded_domains=feed_excluded,
            source=str(descriptor.get("source") or meta.get("source") or FEED_SOURCE),
            candidate_family=str(
                descriptor.get("candidate_family") or "unclassified_feed"
            ),
            candidate_prefix="m",
            html_only=bool(descriptor.get("html_only", False)),
            notes=str(descriptor.get("notes") or MAIN_FEED_NOTE),
        )
        for candidate in feed_candidates:
            existing = combined_feed.get(candidate.domain)
            if existing is None:
                combined_feed[candidate.domain] = candidate
            else:
                duplicates_across_feeds += 1
                if _url_rank(seed, candidate.domain, candidate.url) < _url_rank(
                    seed, candidate.domain, existing.url
                ):
                    combined_feed[candidate.domain] = candidate
        feed_records.append(
            {
                "source": str(descriptor.get("source") or meta.get("source") or FEED_SOURCE),
                "candidate_family": str(
                    descriptor.get("candidate_family") or "unclassified_feed"
                ),
                "html_only": bool(descriptor.get("html_only", False)),
                "meta": meta,
                **feed_stats,
            }
        )
    feed_candidates = list(combined_feed.values())

    selected, reserve, selection_stats = select_main_candidates(
        tranco_candidates,
        feed_candidates,
        counts=counts,
        reserve_counts=reserve_counts,
    )
    targets = {
        "selected": out_dir / "main.csv",
        "reserve": out_dir / "main_reserve.csv",
        "manifest": out_dir / "main_manifest.json",
    }
    if not force:
        existing = [str(path) for path in targets.values() if path.exists()]
        if existing:
            raise FileExistsError(
                "main candidate artifacts already exist; pass --force to replace: "
                + ", ".join(existing)
            )
    selected_hash = _write_candidates(targets["selected"], selected)
    reserve_hash = _write_candidates(targets["reserve"], reserve)

    protocol_path = Path("docs/main-dataset-protocol.md")
    protocol = (
        {"path": str(protocol_path), "sha256": _sha256_file(protocol_path)}
        if protocol_path.exists()
        else None
    )
    manifest = {
        "schema_version": 1,
        "dataset": "main",
        "name": "main-collection",
        "created_at": _now(),
        "seed": seed,
        "unit": "registrable_domain",
        "policy": protocol,
        "selection": {name: counts[name] for name in MAIN_STRATA},
        "reserve": {name: reserve_counts[name] for name in MAIN_STRATA},
        "selected": selection_stats["selected"],
        "reserve": selection_stats["reserve"],
        "domains_total": len(selected),
        "domains": sorted({candidate.domain for candidate in selected}),
        "strata": {
            "established": (
                "Tranco rank 1-50,000. The rank band is a sampling frame, not a label."
            ),
            "tail": (
                "Tranco rank 50,001-1,000,000. The rank band is a sampling frame, not a label."
            ),
            "scam_feed": (
                "OpenPhish and URLhaus public-feed candidates. Membership is candidate "
                "discovery, not a label; all rows are gated."
            ),
        },
        "tranco": {
            **tranco_meta,
            **tranco_stats,
            "bands": {name: list(band) for name, band in MAIN_BANDS.items()},
            "after_exclusion": len(rows),
            "selected": selection_stats["selected"]["established"]
            + selection_stats["selected"]["tail"],
            "reserve": selection_stats["reserve"]["established"]
            + selection_stats["reserve"]["tail"],
        },
        "feeds": feed_records,
        "feed_duplicates_across_sources": duplicates_across_feeds,
        "feed_domains_matching_tranco": selection_stats["feed_domains_matching_tranco"],
        "exclusions": exclusion_records,
        "safety": {
            "candidate_pages_fetched": False,
            "feed_metadata_only": True,
            "gated_stratum": "scam_feed",
            "gated_selected": selection_stats["selected"]["scam_feed"],
            "gate_value": GATED_COLLECTION,
            "explicit_confirmation_required": True,
            "note": (
                "Building this manifest did not open any candidate page. Collection of "
                "scam_feed rows is blocked by the batch safety gate until the team "
                "explicitly confirms the main collection and passes --allow-gated."
            ),
        },
        "outputs": {
            "selected": {
                "path": str(targets["selected"]),
                "sha256": selected_hash,
                "rows": len(selected),
            },
            "reserve": {
                "path": str(targets["reserve"]),
                "sha256": reserve_hash,
                "rows": len(reserve),
            },
        },
    }
    targets["manifest"].write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )
    return manifest


def _write_candidates(path: Path, candidates: Sequence[Candidate]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CANDIDATE_FIELDS)
        writer.writeheader()
        for candidate in candidates:
            writer.writerow(candidate.row())
    return _sha256_file(path)


FEED_LABELED_FAMILY = "feed_labeled_malicious"
FEED_LABELED_NOTE = (
    "Label is public-feed membership at retrieval time, not a human verdict. Collected for scoring; "
    "no annotator inspects the page. Query string and fragment were removed."
)
MAX_FEED_BATCH = 100


def build_feed_candidates(
    *,
    labels_path: Path,
    out_dir: Path,
    seed: int,
    batch_size: int = MAX_FEED_BATCH,
) -> dict[str, Any]:
    """Write gated crawl batches for feed-labeled domains from the label CSV alone.

    Nothing here opens a page: the rows are assembled from label metadata, and every one is marked
    gated so the batch command refuses to collect it without explicit confirmation.
    """
    if not labels_path.exists():
        raise FileNotFoundError(f"feed label file not found: {labels_path}")
    if batch_size < 1 or batch_size > MAX_FEED_BATCH:
        raise ValueError(f"batch size must be between 1 and {MAX_FEED_BATCH}")
    with labels_path.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = [dict(row) for row in csv.DictReader(handle)]

    candidates: list[Candidate] = []
    download_only = 0
    for row in rows:
        label = str(row.get("label") or "").strip().lower()
        if label != "malicious":
            continue
        try:
            url, domain = sanitize_candidate_url(str(row.get("url") or ""))
        except UnsafeURLError:
            continue
        # The collection contract excludes raw file downloads, and many feed entries point straight at
        # a payload, so the crawl target falls back to the domain root when the path is not HTML.
        if not _likely_html_path(url):
            download_only += 1
            url = f"https://{domain}/"
        candidates.append(
            _make_candidate(
                seed=seed,
                url=url,
                domain=domain,
                stratum="scam_feed",
                candidate_family=FEED_LABELED_FAMILY,
                source=str(row.get("source") or "").split("@")[0],
                source_date=str(row.get("source_date") or ""),
                notes=FEED_LABELED_NOTE,
                collection_gate=GATED_COLLECTION,
                verification_required="false",
                candidate_prefix="feed",
            )
        )

    candidates.sort(key=lambda item: (item.rank, item.domain))
    batches = [
        candidates[index : index + batch_size]
        for index in range(0, len(candidates), batch_size)
    ]
    out_dir.mkdir(parents=True, exist_ok=True)
    batch_files: list[dict[str, Any]] = []
    for number, batch in enumerate(batches, start=1):
        path = out_dir / f"feed_batch_{number:02d}.csv"
        digest = _write_candidates(path, batch)
        batch_files.append(
            {
                "batch": number,
                "file": str(path),
                "sha256": digest,
                "candidates": len(batch),
                "domains": len({item.domain for item in batch}),
            }
        )

    manifest = {
        "schema_version": 1,
        "created_at": _now(),
        "seed": seed,
        "labels_file": str(labels_path),
        "labels_sha256": _sha256_file(labels_path),
        "batch_size": batch_size,
        "candidates": len(candidates),
        "domains": len({item.domain for item in candidates}),
        "payload_urls_replaced_by_domain_root": download_only,
        "collection_gate": GATED_COLLECTION,
        "approval": "not approved; each batch needs fresh explicit confirmation before collection",
        "batches": batch_files,
    }
    (out_dir / "feed_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def build_round2_manifest(
    *,
    feed_text: str,
    feed_meta: dict[str, Any],
    curated_path: Path,
    pilot_path: Path,
    out_dir: Path,
    seed: int = 11,
    counts: dict[str, int] | None = None,
    reserve_counts: dict[str, int] | None = None,
    force: bool = False,
) -> dict[str, Any]:
    counts = {**DEFAULT_COUNTS, **(counts or {})}
    reserve_counts = {**DEFAULT_RESERVE, **(reserve_counts or {})}
    pilot_domains = load_pilot_domains(pilot_path)
    curated, curated_stats = load_curated_candidates(curated_path, seed=seed)
    curated_domains_before = {candidate.domain for candidate in curated}
    curated_after_pilot = [
        candidate for candidate in curated if candidate.domain not in pilot_domains
    ]
    curated_stats["excluded_round1"] = len(curated) - len(curated_after_pilot)
    curated = curated_after_pilot
    feed_candidates, feed_stats = parse_feed_candidates(
        feed_text,
        seed=seed,
        source_date=str(feed_meta.get("source_date") or ""),
        excluded_domains=pilot_domains,
    )
    selected, reserve, selection_stats = select_round2_candidates(
        curated,
        feed_candidates,
        counts=counts,
        reserve_counts=reserve_counts,
    )
    targets = {
        "pilot": out_dir / "round2.csv",
        "reserve": out_dir / "round2_reserve.csv",
        "manifest": out_dir / "round2_manifest.json",
    }
    if not force:
        existing = [str(path) for path in targets.values() if path.exists()]
        if existing:
            raise FileExistsError(
                "Round 2 candidate artifacts already exist; pass --force to replace: "
                + ", ".join(existing)
            )
    pilot_hash = _write_candidates(targets["pilot"], selected)
    reserve_hash = _write_candidates(targets["reserve"], reserve)
    manifest = {
        "schema_version": 1,
        "round": "round2",
        "name": "mixed-calibration",
        "created_at": _now(),
        "seed": seed,
        "unit": "registrable_domain",
        "selection": {name: counts[name] for name in ROUND2_STRATA},
        "selected": selection_stats["selected"],
        "reserve": selection_stats["reserve"],
        "domains_total": len(selected),
        "domains": sorted({candidate.domain for candidate in selected}),
        "strata": {
            "scam_feed": (
                "Public feed candidates. Membership is candidate discovery, not a label; "
                "all rows are gated."
            ),
            "ambiguous": (
                "Boundary cases: login-only, legacy, small-business, and placeholder pages."
            ),
            "benign_control": (
                "Established organisations selected to exercise the benign boundary. "
                "The stratum name is a sampling frame, not a preassigned label."
            ),
        },
        "feed": {
            **feed_meta,
            **feed_stats,
        },
        "curated_source": {
            **curated_stats,
            "domains_matching_round1": len(curated_domains_before & pilot_domains),
        },
        "pilot_source": {
            "path": str(pilot_path),
            "sha256": _sha256_file(pilot_path),
            "domains_excluded": len(pilot_domains),
        },
        "safety": {
            "candidate_pages_fetched": False,
            "feed_metadata_only": True,
            "gated_stratum": "scam_feed",
            "gated_selected": selection_stats["selected"]["scam_feed"],
            "gate_value": GATED_COLLECTION,
            "explicit_confirmation_required": True,
            "note": (
                "Building this manifest did not open any candidate page. Collection of "
                "scam_feed rows is blocked by the batch safety gate until the team "
                "explicitly confirms and passes --allow-gated."
            ),
        },
        "outputs": {
            "pilot": {
                "path": str(targets["pilot"]),
                "sha256": pilot_hash,
                "rows": len(selected),
            },
            "reserve": {
                "path": str(targets["reserve"]),
                "sha256": reserve_hash,
                "rows": len(reserve),
            },
        },
    }
    targets["manifest"].write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )
    return manifest


def load_manifest(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))
