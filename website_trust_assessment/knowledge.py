"""Static knowledge used by evidence extractors: brands, trackers, TLDs, patterns."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from .config import load_json_data
from .security import EXTRACTOR, UnsafeURLError, normalize_url, registrable_domain

DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9-]{1,63}$")


@dataclass(frozen=True)
class Brand:
    name: str
    domains: tuple[str, ...]
    aliases: tuple[str, ...]


@dataclass(frozen=True)
class TrackerDef:
    name: str
    pattern: str
    category: str


@dataclass(frozen=True)
class DarkPatternDef:
    code: str
    category: str
    title: str
    description: str
    regexes: tuple[re.Pattern[str], ...]
    severity: str
    risk_points: float
    confidence: float
    tags: tuple[str, ...]


@lru_cache(maxsize=1)
def brands() -> tuple[Brand, ...]:
    data = load_json_data("brands.json")
    result = []
    for item in data.get("brands", []):
        domains = tuple(str(d).strip().lower().rstrip(".") for d in item.get("domains", []) if d)
        aliases = {str(a).strip().lower() for a in item.get("aliases", []) if a}
        aliases.add(str(item.get("name", "")).strip().lower())
        aliases.discard("")
        result.append(Brand(str(item.get("name", "")), domains, tuple(sorted(aliases))))
    return tuple(result)


@lru_cache(maxsize=1)
def _official_domains() -> tuple[str, ...]:
    domains: set[str] = set()
    for brand in brands():
        domains.update(brand.domains)
    return tuple(sorted(domains))


@lru_cache(maxsize=1)
def _brand_domain_map() -> dict[str, Brand]:
    mapping: dict[str, Brand] = {}
    for brand in brands():
        for domain in brand.domains:
            mapping.setdefault(domain, brand)
    return mapping


@lru_cache(maxsize=1)
def _alias_patterns() -> tuple[tuple[re.Pattern[str], Brand, str], ...]:
    patterns: list[tuple[re.Pattern[str], Brand, str]] = []
    for brand in brands():
        for alias in brand.aliases:
            if len(alias) < 4:
                continue
            if not re.fullmatch(r"[a-z0-9][a-z0-9 .+-]*", alias):
                continue
            pattern = re.compile(rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])", re.IGNORECASE)
            patterns.append((pattern, brand, alias))
    return tuple(patterns)


def is_official_domain(domain_or_host: str) -> bool:
    host = domain_or_host.strip().lower().rstrip(".")
    if not host:
        return False
    for official in _official_domains():
        if host == official or host.endswith("." + official):
            return True
    return False


def matching_brand_for_host(host: str) -> Brand | None:
    host = host.strip().lower().rstrip(".")
    for official, brand in _brand_domain_map().items():
        if host == official or host.endswith("." + official):
            return brand
    return None


def brands_in_text(text: str, *, min_alias_length: int = 4, limit: int = 3) -> list[Brand]:
    if not text:
        return []
    lowered = text.lower()
    found: list[tuple[int, Brand]] = []
    seen: set[str] = set()
    for pattern, brand, alias in _alias_patterns():
        if len(alias) < min_alias_length:
            continue
        if brand.name in seen:
            continue
        if pattern.search(lowered):
            found.append((len(alias), brand))
            seen.add(brand.name)
    found.sort(key=lambda item: item[0], reverse=True)
    return [brand for _, brand in found[:limit]]


def domain_core(host: str) -> str:
    host = host.strip().lower().rstrip(".")
    try:
        extracted = EXTRACTOR(host)
        return (extracted.domain or host).lower()
    except Exception:
        return host.split(".")[0]


def domain_suffix(host: str) -> str:
    try:
        return EXTRACTOR(host).suffix.lower()
    except Exception:
        return host.rsplit(".", 1)[-1].lower() if "." in host else ""


def host_prefix(host: str) -> str:
    host = host.strip().lower().rstrip(".")
    domain = registrable_domain(host)
    if host.endswith("." + domain):
        return host[: -(len(domain) + 1)]
    if host == domain:
        return ""
    return ""


def levenshtein(a: str, b: str, max_distance: int = 2) -> int:
    if a == b:
        return 0
    if abs(len(a) - len(b)) > max_distance:
        return max_distance + 1
    if len(a) > len(b):
        a, b = b, a
    previous = list(range(len(a) + 1))
    for row, char_b in enumerate(b, start=1):
        current = [row]
        best = row
        for col, char_a in enumerate(a, start=1):
            cost = 0 if char_a == char_b else 1
            value = min(previous[col] + 1, current[col - 1] + 1, previous[col - 1] + cost)
            current.append(value)
            best = min(best, value)
        if best > max_distance:
            return max_distance + 1
        previous = current
    return previous[-1]


def homoglyph_fold(value: str) -> str:
    table = str.maketrans(
        {
            "0": "o",
            "1": "l",
            "3": "e",
            "4": "a",
            "5": "s",
            "7": "t",
            "$": "s",
            "@": "a",
        }
    )
    folded = value.lower().translate(table)
    return folded.replace("rn", "m").replace("vv", "w").replace("cl", "d")


def decode_punycode_host(host: str) -> str:
    pieces = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                pieces.append(label.encode("ascii").decode("idna"))
            except Exception:
                pieces.append(label)
        else:
            pieces.append(label)
    return ".".join(pieces)


@lru_cache(maxsize=1)
def tracker_defs() -> tuple[tuple[TrackerDef, ...], dict[str, dict[str, Any]]]:
    data = load_json_data("trackers.json")
    defs = tuple(
        TrackerDef(
            name=str(item["name"]),
            pattern=str(item["pattern"]).lower(),
            category=str(item["category"]),
        )
        for item in data.get("trackers", [])
    )
    return defs, dict(data.get("category_weights", {}))


def match_trackers(urls: list[str], page_host: str) -> list[dict[str, Any]]:
    """Return one best tracker match per URL, de-duplicated by name."""
    defs, _ = tracker_defs()
    site_domain = registrable_domain(page_host) if page_host else ""
    matches: dict[str, dict[str, Any]] = {}
    for url in urls:
        lowered = url.lower()
        best: TrackerDef | None = None
        for definition in defs:
            if definition.pattern in lowered:
                if best is None or len(definition.pattern) > len(best.pattern):
                    best = definition
        if not best:
            continue
        host = lowered.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        third_party = bool(site_domain and registrable_domain(host) != site_domain)
        key = best.name
        existing = matches.get(key)
        if existing:
            existing["count"] += 1
            existing["third_party"] = existing["third_party"] or third_party
        else:
            matches[key] = {
                "name": best.name,
                "category": best.category,
                "host": host,
                "third_party": third_party,
                "count": 1,
            }
    return list(matches.values())


@lru_cache(maxsize=1)
def payment_processor_domains() -> tuple[str, ...]:
    data = load_json_data("payment_processors.json")
    return tuple(
        str(domain).lower()
        for processor in data.get("processors", [])
        for domain in processor.get("domains", [])
    )


def is_trusted_checkout(host: str) -> bool:
    host = host.strip().lower().rstrip(".")
    if not host:
        return False
    return any(host == domain or host.endswith("." + domain) for domain in payment_processor_domains())


@lru_cache(maxsize=1)
def tld_data() -> dict[str, Any]:
    return load_json_data("tlds.json")


def is_suspicious_tld(host: str) -> bool:
    suffix = domain_suffix(host)
    if not suffix:
        return False
    data = tld_data()
    suspicious = set(data.get("suspicious_tlds", []))
    return suffix in suspicious or suffix.rsplit(".", 1)[-1] in suspicious


def is_free_subdomain(host: str) -> str | None:
    host = host.lower().rstrip(".")
    for provider in tld_data().get("free_subdomain_providers", []):
        if host == provider or host.endswith("." + provider):
            return provider
    return None


def is_url_shortener(host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(host == item or host.endswith("." + item) for item in tld_data().get("url_shorteners", []))


def is_file_host(host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(host == item or host.endswith("." + item) for item in tld_data().get("file_hosts", []))


@lru_cache(maxsize=1)
def dark_pattern_defs() -> tuple[DarkPatternDef, ...]:
    data = load_json_data("dark_patterns.json")
    result = []
    for item in data.get("patterns", []):
        compiled = tuple(
            re.compile(pattern, re.IGNORECASE) for pattern in item.get("patterns", [])
        )
        result.append(
            DarkPatternDef(
                code=str(item["code"]),
                category=str(item["category"]),
                title=str(item["title"]),
                description=str(item["description"]),
                regexes=compiled,
                severity=str(item["severity"]),
                risk_points=float(item["risk_points"]),
                confidence=float(item["confidence"]),
                tags=tuple(item.get("tags", [])),
            )
        )
    return tuple(result)


def safe_host(url: str) -> str:
    try:
        return normalize_url(url).split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
    except (UnsafeURLError, IndexError):
        return ""


def tracking_cookie(name: str) -> bool:
    lowered = name.lower()
    known = (
        "_ga",
        "_gid",
        "_gat",
        "_gcl",
        "_fbp",
        "_fbc",
        "fbp",
        "fr",
        "ide",
        "nid",
        "anid",
        "dsid",
        "_pin_unauth",
        "_tt_enable_cookie",
        "_ttp",
        "_hj",
        "_clck",
        "_clsk",
        "_uetsid",
        "_uetvid",
        "ajs_",
        "mp_",
        "amplitude_",
        "intercom-",
        "optimizely",
        "vwo_",
    )
    return any(lowered == item or lowered.startswith(item) for item in known)
