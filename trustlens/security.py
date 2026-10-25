"""URL normalisation and SSRF protection.

The system fetches untrusted URLs. Every network hop (initial request, redirects,
subresources, policy fetches) must pass these checks. DNS rebinding remains a
residual risk because resolution and connection are separate operations; the
server is intended to run locally behind an operator who supplies URLs. See
docs/THREAT_MODEL.md.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit, urlunsplit

import tldextract

from .schemas import utc_now

_PSL_FILE = Path(__file__).resolve().parent / "data" / "public_suffix_list.dat"
EXTRACTOR = tldextract.TLDExtract(
    cache_dir=None,
    suffix_list_urls=(_PSL_FILE.as_uri(),),
    fallback_to_snapshot=True,
)

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443}
BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata",
    "metadata.google.internal",
    "instance-data",
    "metadata.azure.internal",
}
BLOCKED_HOST_SUFFIXES = (".local", ".internal", ".lan", ".home", ".corp", ".localhost")
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
PUNYCODE_LABEL = re.compile(r"(^|\.)xn--", re.IGNORECASE)
IP_LITERAL = re.compile(r"^[\d.]+$|^\[?[0-9a-f:]+\]?$", re.IGNORECASE)


class UnsafeURLError(ValueError):
    """The URL cannot be fetched safely (or is not a normal web URL)."""


@dataclass(frozen=True)
class URLParts:
    url: str
    scheme: str
    host: str
    port: int
    path: str
    registrable_domain: str
    is_ip: bool
    is_punycode: bool


def _idna(host: str) -> str:
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        raise UnsafeURLError("Hostname is not valid IDNA") from None


def normalize_url(raw: str) -> str:
    """Canonical http(s) URL or raise UnsafeURLError.

    Fragments are dropped, default ports removed, the host lower-cased and
    IDNA-encoded, and userinfo rejected.
    """
    if not isinstance(raw, str):
        raise UnsafeURLError("URL must be a string")
    raw = raw.strip()
    if not raw or len(raw) > 2048:
        raise UnsafeURLError("URL is empty or too long")
    if CONTROL_CHARS.search(raw) or any(ch.isspace() for ch in raw):
        raise UnsafeURLError("URL contains whitespace or control characters")
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parts = urlsplit(raw)
    except ValueError:
        raise UnsafeURLError("URL could not be parsed") from None
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UnsafeURLError("Only http:// and https:// URLs are supported")
    if parts.username or parts.password:
        raise UnsafeURLError("URLs with embedded credentials are not allowed")
    if not parts.hostname:
        raise UnsafeURLError("URL has no hostname")
    host = parts.hostname.rstrip(".")
    host = _idna(host.lower())
    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError:
        raise UnsafeURLError("URL has an invalid port") from None
    if port not in ALLOWED_PORTS:
        raise UnsafeURLError("Non-standard ports are not crawled")
    host_for_netloc = f"[{host}]" if ":" in host else host
    netloc = (
        host_for_netloc
        if port == (443 if scheme == "https" else 80)
        else f"{host_for_netloc}:{port}"
    )
    path = parts.path or "/"
    normalized = urlunsplit((scheme, netloc, path, parts.query, ""))
    if len(normalized) > 2048:
        raise UnsafeURLError("URL is too long")
    return normalized


def url_parts(raw: str) -> URLParts:
    normalized = normalize_url(raw)
    parts = urlsplit(normalized)
    host = (parts.hostname or "").lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    extracted = EXTRACTOR(host)
    registrable = extracted.top_domain_under_public_suffix or extracted.domain or host
    return URLParts(
        url=normalized,
        scheme=parts.scheme,
        host=host,
        port=parts.port or (443 if parts.scheme == "https" else 80),
        path=(parts.path or "/") + (f"?{parts.query}" if parts.query else ""),
        registrable_domain=registrable.lower(),
        is_ip=is_ip,
        is_punycode=bool(PUNYCODE_LABEL.search(host)),
    )


def host_from_url(raw: str) -> str:
    try:
        return url_parts(raw).host
    except UnsafeURLError:
        return ""


def domain_from_url(raw: str) -> str:
    try:
        return url_parts(raw).registrable_domain
    except UnsafeURLError:
        return ""


def is_same_site(url_a: str, url_b: str) -> bool:
    domain_a, domain_b = domain_from_url(url_a), domain_from_url(url_b)
    return bool(domain_a and domain_a == domain_b)


def registrable_domain(host: str) -> str:
    host = host.lower().rstrip(".")
    extracted = EXTRACTOR(host)
    return (extracted.top_domain_under_public_suffix or extracted.domain or host).lower()


def is_public_ip(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address.strip("[]"))
    except ValueError:
        return False
    return bool(ip.is_global and not ip.is_multicast and not ip.is_reserved)


def _is_blocked_hostname(host: str) -> bool:
    host = host.lower().rstrip(".")
    if host in BLOCKED_HOSTNAMES:
        return True
    return any(host.endswith(suffix) for suffix in BLOCKED_HOST_SUFFIXES)


def check_url_structure(raw: str) -> URLParts:
    parts = url_parts(raw)
    if _is_blocked_hostname(parts.host):
        raise UnsafeURLError("Local and internal hostnames are not crawled")
    if parts.is_ip and not is_public_ip(parts.host):
        raise UnsafeURLError("Private, loopback, link-local, and reserved IPs are not crawled")
    return parts


async def resolve_public(host: str, port: int = 443) -> list[str]:
    """Resolve a hostname and require every address to be globally routable."""
    if _is_blocked_hostname(host):
        raise UnsafeURLError("Local and internal hostnames are not crawled")
    try:
        ipaddress.ip_address(host)
        addresses = [host]
    except ValueError:
        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: socket.getaddrinfo(host, port, type=socket.SOCK_STREAM),
                ),
                timeout=5.0,
            )
        except (socket.gaierror, TimeoutError, OSError):
            raise UnsafeURLError(f"Could not resolve hostname: {host}") from None
        addresses = sorted({info[4][0] for info in infos})
    if not addresses:
        raise UnsafeURLError(f"Could not resolve hostname: {host}")
    for address in addresses:
        if not is_public_ip(address):
            raise UnsafeURLError("Hostname resolves to a non-public address")
    return addresses


async def validate_public_url(raw: str) -> URLParts:
    parts = check_url_structure(raw)
    await resolve_public(parts.host, parts.port)
    return parts


_resolve_cache: dict[str, tuple[float, list[str]]] = {}
_RESOLVE_TTL = 60.0


def resolve_public_sync(host: str, port: int = 443) -> list[str]:
    """Blocking resolver with a small TTL cache for the Playwright route guard."""
    now = time.monotonic()
    cached = _resolve_cache.get(host)
    if cached and now - cached[0] < _RESOLVE_TTL:
        return cached[1]
    if _is_blocked_hostname(host):
        raise UnsafeURLError("Local and internal hostnames are not crawled")
    try:
        ipaddress.ip_address(host)
        addresses = [host]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except (socket.gaierror, OSError):
            raise UnsafeURLError(f"Could not resolve hostname: {host}") from None
        addresses = sorted({info[4][0] for info in infos})
    if not addresses:
        raise UnsafeURLError(f"Could not resolve hostname: {host}")
    for address in addresses:
        if not is_public_ip(address):
            raise UnsafeURLError("Hostname resolves to a non-public address")
    _resolve_cache[host] = (now, addresses)
    return addresses


def check_request_url_sync(raw: str) -> tuple[str, str]:
    """Validate a browser subrequest. Returns (host, scheme) or raises."""
    try:
        parts = urlsplit(raw)
    except ValueError:
        raise UnsafeURLError("Malformed subrequest URL") from None
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise UnsafeURLError("Blocked non-HTTP subrequest")
    if parts.username or parts.password:
        raise UnsafeURLError("Blocked subrequest with credentials")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise UnsafeURLError("Subrequest has no host")
    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError:
        raise UnsafeURLError("Subrequest has an invalid port")
    if port not in ALLOWED_PORTS:
        raise UnsafeURLError("Blocked non-standard port")
    try:
        resolve_public_sync(host, port)
    except UnsafeURLError:
        raise
    return host, scheme


def sanitize_text(text: str, max_chars: int = 5000) -> str:
    """Strip control characters and collapse whitespace. No HTML is preserved."""
    if not text:
        return ""
    cleaned = CONTROL_CHARS.sub(" ", text)
    cleaned = re.sub(r"[ \t\r\f\v]+", " ", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip()[:max_chars]


def origin(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def path_and_query(url: str) -> str:
    parts = urlsplit(url)
    return (parts.path or "/") + (f"?{parts.query}" if parts.query else "")


def normalize_domain_list(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        domain = value.strip().lower().rstrip(".")
        if not domain or domain in seen:
            continue
        if not re.fullmatch(r"[a-z0-9.*_-]+", domain):
            continue
        seen.add(domain)
        result.append(domain)
    return result


def utc_iso() -> str:
    return utc_now().isoformat()
