"""Infrastructure evidence: favicon and image hashes, analytics IDs, and labels.

The graph is intentionally local. Domains become linked only through values
observed by the system or imported labels; shared hosting and copied images can
create legitimate overlaps, so overlaps are surfaced with an explicit caveat
rather than treated as proof.
"""

from __future__ import annotations

import asyncio
import io
import re
from typing import Any
from urllib.parse import urlsplit

from PIL import Image

from .. import storage
from ..crawler import fetch_bytes
from ..schemas import Dimension, Evidence, Severity
from ..security import origin
from .base import ScanContext, truncate

ANALYTICS_SPECS: tuple[tuple[str, re.Pattern[str], int], ...] = (
    (
        "google",
        re.compile(r"\b(?:G-[A-Z0-9]{6,14}|UA-\d{4,10}-\d{1,4}|AW-\d{6,12}|DC-\d{4,8}|GTM-[A-Z0-9]{4,10})\b"),
        0,
    ),
    ("facebook", re.compile(r"fbq\s*\(\s*['\"]init['\"]\s*,\s*['\"](\d{8,20})", re.IGNORECASE), 1),
    ("tiktok", re.compile(r"ttq\.load\s*\(\s*['\"]([A-Z0-9]{10,30})", re.IGNORECASE), 1),
    ("linkedin", re.compile(r"_linkedin_partner_id\s*=\s*['\"](\d{3,12})", re.IGNORECASE), 1),
    ("hotjar", re.compile(r"(?:hjid\s*[:=]\s*|['\"]hjid['\"]\s*:\s*)(\d{4,12})", re.IGNORECASE), 1),
    (
        "clarity",
        re.compile(r"(?:clarity\s*\(\s*['\"]|['\"]clarity['\"]\s*,\s*['\"])([a-z0-9]{6,20})", re.IGNORECASE),
        1,
    ),
    ("hubspot", re.compile(r"portalId\s*:\s*['\"]?(\d{4,12})", re.IGNORECASE), 1),
    ("segment", re.compile(r"analytics\.load\s*\(\s*['\"]([A-Za-z0-9]{10,40})", re.IGNORECASE), 1),
    ("mixpanel", re.compile(r"mixpanel\.init\s*\(\s*['\"]([A-Fa-f0-9]{16,40})", re.IGNORECASE), 1),
    (
        "amplitude",
        re.compile(r"amplitude[^;]{0,300}?api_key\s*[:=]\s*['\"]([A-Fa-f0-9]{20,50})", re.IGNORECASE),
        1,
    ),
    ("pinterest", re.compile(r"pintrk\s*\(\s*['\"]load['\"]\s*,\s*['\"](\d{6,20})", re.IGNORECASE), 1),
    ("twitter", re.compile(r"twq\s*\(\s*['\"]config['\"]\s*,\s*['\"]([a-z0-9]{4,12})", re.IGNORECASE), 1),
    (
        "snapchat",
        re.compile(r"snaptr\s*\(\s*['\"]init['\"]\s*,\s*['\"]([A-Fa-f0-9-]{10,40})", re.IGNORECASE),
        1,
    ),
    ("yandex", re.compile(r"ym\s*\(\s*(\d{6,12})"), 1),
    (
        "matomo",
        re.compile(r"_paq\.push\s*\[\s*['\"]setSiteId['\"]\s*,\s*['\"](\d{1,10})", re.IGNORECASE),
        1,
    ),
    ("heap", re.compile(r"heap\.load\s*\(\s*['\"](\d{4,20})", re.IGNORECASE), 1),
)

MATCH_WEIGHTS = {
    "tls_certificate": 11.0,
    "favicon": 14.0,
    "analytics_id": 12.0,
    "product_image": 8.0,
}
_IMAGE_SKIP_RE = re.compile(
    r"logo|icon|avatar|sprite|pixel|tracker|badge|spacer|placeholder|spinner|"
    r"loading|banner|payment|1x1|transparent",
    re.IGNORECASE,
)
_PRODUCT_HINT_RE = re.compile(
    r"product|item|shop|deal|offer|gallery|photo|upload|catalog",
    re.IGNORECASE,
)
_IMAGE_EXT_SKIP = (".svg", ".gif", ".ico")


def _analytics_ids(ctx: ScanContext) -> list[str]:
    haystack = "\n".join(
        [
            ctx.page.html,
            "\n".join(ctx.page.inline_scripts),
        ]
    )
    if not haystack:
        return []
    found: list[str] = []
    seen: set[str] = set()
    for prefix, pattern, group in ANALYTICS_SPECS:
        count = 0
        for match in pattern.finditer(haystack):
            value = match.group(group).strip()
            if not value:
                continue
            identifier = f"{prefix}:{value}"
            if identifier.lower() in seen:
                continue
            seen.add(identifier.lower())
            found.append(identifier)
            count += 1
            if count >= 5:
                break
        if len(found) >= 20:
            break
    return found[:20]


def _flatten(image: Image.Image) -> Image.Image:
    if image.mode in {"RGBA", "LA"} or "transparency" in image.info:
        rgba = image.convert("RGBA")
        background = Image.new("RGB", rgba.size, (255, 255, 255))
        background.paste(rgba, mask=rgba.getchannel("A"))
        return background
    return image.convert("RGB")


def _dhash(gray: Image.Image) -> str:
    resampling = getattr(Image, "Resampling", Image).LANCZOS
    small = gray.resize((9, 8), resampling)
    pixels = list(small.getdata())
    value = 0
    for row in range(8):
        offset = row * 9
        for column in range(8):
            value = (value << 1) | (1 if pixels[offset + column] > pixels[offset + column + 1] else 0)
    return f"{value:016x}"


def _hash_image_bytes(content: bytes) -> str | None:
    try:
        with Image.open(io.BytesIO(content)) as image:
            if image.width < 8 or image.height < 8:
                return None
            if image.width * image.height > 30_000_000:
                return None
            image.load()
            rgb = _flatten(image)
    except Exception:
        return None
    try:
        gray = rgb.convert("L")
        low, high = gray.getextrema()
        if high - low < 20:
            return None
        digest = _dhash(gray)
        if digest in {"0000000000000000", "ffffffffffffffff"}:
            return None
        return digest
    except Exception:
        return None


async def _fetch_hash(url: str) -> str | None:
    try:
        result = await fetch_bytes(
            url,
            max_bytes=400_000,
            timeout=5.0,
            accept="image/avif,image/webp,image/png,image/jpeg,image/*;q=0.8,*/*;q=0.3",
        )
    except Exception:
        return None
    if result.error or not (200 <= result.status < 300) or len(result.content) < 32:
        return None
    if "text/html" in result.content_type.lower():
        return None
    return await asyncio.to_thread(_hash_image_bytes, result.content)


async def _hash_urls(urls: list[str]) -> list[str]:
    unique = list(dict.fromkeys(url for url in urls if url))
    if not unique:
        return []
    tasks = [asyncio.create_task(_fetch_hash(url)) for url in unique]
    try:
        results = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=18.0)
    except TimeoutError:
        for task in tasks:
            task.cancel()
        return []
    return [result for result in results if isinstance(result, str)][:4]


def _favicon_urls(ctx: ScanContext) -> list[str]:
    urls = [
        url
        for url in ctx.page.favicon_urls[:2]
        if url.startswith(("http://", "https://"))
    ]
    if not urls:
        try:
            urls.append(origin(ctx.final_url).rstrip("/") + "/favicon.ico")
        except Exception:
            pass
    return list(dict.fromkeys(urls))[:3]


def _image_urls(ctx: ScanContext) -> list[str]:
    favicons = set(ctx.page.favicon_urls)
    ranked: list[tuple[int, int, str]] = []
    for image in ctx.page.images:
        src = image.src
        if not src.startswith(("http://", "https://")) or src in favicons:
            continue
        if not image.visible:
            continue
        joined = f"{src} {image.alt}"
        if _IMAGE_SKIP_RE.search(joined):
            continue
        if urlsplit(src).path.lower().endswith(_IMAGE_EXT_SKIP):
            continue
        if image.width and image.height and min(image.width, image.height) < 90:
            continue
        area = max(0, image.width) * max(0, image.height)
        hint = 1 if _PRODUCT_HINT_RE.search(joined) else 0
        ranked.append((hint, area, src))
    ranked.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return [item[2] for item in ranked[:3]]


def _neighbor_evidence(ctx: ScanContext, neighbors: list[dict[str, Any]]) -> Evidence | None:
    if not neighbors:
        return None
    matched_types = sorted(
        {
            str(kind)
            for neighbor in neighbors
            for kind in neighbor.get("matched_on", [])
        }
    )
    base = sum(MATCH_WEIGHTS.get(kind, 4.0) for kind in matched_types)
    if len(neighbors) >= 2:
        base += 4.0
    if len(neighbors) >= 3:
        base += 2.0
    if "product_image" in matched_types and not ctx.has_payment_form:
        base -= 3.0
    risk = min(32.0, max(6.0, base))
    confidence = min(
        0.8,
        0.55 + 0.06 * len(matched_types) + 0.04 * min(len(neighbors), 3),
    )
    domains = ", ".join(str(neighbor["domain"]) for neighbor in neighbors[:4])
    caveat = (
        "Shared certificates, hosting, copied branding, and reused public images can create legitimate "
        "overlaps, so this is supporting evidence rather than proof of common ownership."
        if "tls_certificate" in matched_types or "product_image" in matched_types
        else "Infrastructure identifiers can be copied, so treat the overlap as a lead, not proof."
    )
    detail = (
        f"This domain shares {', '.join(kind.replace('_', ' ') for kind in matched_types)} with "
        f"{len(neighbors)} domain(s) that are labeled malicious in the local intelligence store: {domains}. "
        f"{caveat}"
    )
    return ctx.evidence(
        dimension=Dimension.SECURITY,
        code="malicious_infrastructure_overlap",
        title="Infrastructure overlaps with domains labeled malicious",
        detail=detail,
        severity=Severity.HIGH if risk >= 22 else Severity.MEDIUM,
        risk_points=risk,
        confidence=confidence,
        source="infrastructure_graph",
        provenance={
            "neighbors": [
                {
                    "domain": str(neighbor["domain"]),
                    "matched_on": neighbor.get("matched_on", []),
                    "label_confidence": neighbor.get("confidence"),
                    "label_source": neighbor.get("source"),
                }
                for neighbor in neighbors[:5]
            ],
            "matched_types": matched_types,
            "neighbor_count": len(neighbors),
        },
        tags=["infrastructure", "graph", "known_bad_neighbor"],
    )


async def extract(ctx: ScanContext) -> list[Evidence]:
    evidence: list[Evidence] = []
    domain = ctx.final_domain
    if not domain:
        return evidence

    favicons, images = await asyncio.gather(
        _hash_urls(_favicon_urls(ctx)),
        _hash_urls(_image_urls(ctx)),
    )
    analytics_ids = _analytics_ids(ctx)
    tls = ctx.intel.tls or {}
    cert_fingerprints = (
        [str(tls.get("fingerprint_sha256"))]
        if tls.get("ok") and tls.get("fingerprint_sha256")
        else []
    )
    nameservers = [str(item) for item in (ctx.intel.dns.get("ns") or [])][:10]
    registrar = str(ctx.intel.rdap.get("registrar") or "") or None

    try:
        label = storage.get_domain_label(domain)
    except Exception as exc:
        label = None
        ctx.errors["domain_labels"] = f"lookup_failed: {type(exc).__name__}"

    try:
        neighbors = storage.find_bad_neighbors(
            cert_fingerprints=cert_fingerprints,
            favicon_hashes=favicons,
            analytics_ids=analytics_ids,
            image_hashes=images,
            exclude_domain=domain,
        )
    except Exception as exc:
        neighbors = []
        ctx.errors["infrastructure_graph"] = f"lookup_failed: {type(exc).__name__}"

    try:
        if favicons or images or analytics_ids or cert_fingerprints or nameservers or registrar:
            storage.upsert_domain_observation(
                domain,
                cert_fingerprints=cert_fingerprints,
                favicon_hashes=favicons,
                analytics_ids=analytics_ids,
                image_hashes=images,
                nameservers=nameservers,
                registrar=registrar,
            )
        ctx.add_source("infrastructure_graph", True)
    except Exception as exc:
        ctx.errors["infrastructure_graph_store"] = f"store_failed: {type(exc).__name__}"
        ctx.add_source("infrastructure_graph", False)

    if label:
        label_name = str(label.get("label") or "").lower()
        label_confidence = float(label.get("confidence") or 1.0)
        source = truncate(str(label.get("source") or "manual"), 80)
        if label_name == "malicious":
            evidence.append(
                ctx.evidence(
                    dimension=Dimension.SECURITY,
                    code="known_malicious_label",
                    title="Domain is present in the local malicious-label store",
                    detail=f"The domain is labeled malicious by '{source}' with confidence "
                    f"{label_confidence:.2f}. This label comes from a locally imported blocklist or "
                    "annotation set; it is not a live reputation lookup. Treat the site as unsafe unless "
                    "the label is independently verified.",
                    severity=Severity.CRITICAL,
                    risk_points=55.0,
                    confidence=max(0.6, label_confidence),
                    source="domain_labels",
                    provenance={
                        "label": label_name,
                        "label_source": source,
                        "label_confidence": label_confidence,
                        "updated_at": label.get("updated_at"),
                    },
                    tags=["known_label", "blocklist", "label"],
                )
            )
        elif label_name == "suspicious":
            evidence.append(
                ctx.evidence(
                    dimension=Dimension.SECURITY,
                    code="known_suspicious_label",
                    title="Domain is present in the local suspicious-label store",
                    detail=f"The domain is labeled suspicious by '{source}' with confidence "
                    f"{label_confidence:.2f}. This is a local label, not a live reputation service.",
                    severity=Severity.HIGH,
                    risk_points=28.0,
                    confidence=max(0.55, label_confidence),
                    source="domain_labels",
                    provenance={
                        "label": label_name,
                        "label_source": source,
                        "label_confidence": label_confidence,
                    },
                    tags=["known_label", "label"],
                )
            )

    neighbor_evidence = _neighbor_evidence(ctx, neighbors)
    if neighbor_evidence:
        evidence.append(neighbor_evidence)

    matches = sorted(
        {
            str(kind)
            for neighbor in neighbors
            for kind in neighbor.get("matched_on", [])
        }
    )
    ctx.notes["infrastructure"] = {
        "cert_fingerprint": bool(cert_fingerprints),
        "favicon_hashes": len(favicons),
        "image_hashes": len(images),
        "analytics_ids": analytics_ids[:10],
        "nameservers": nameservers[:5],
        "registrar": registrar,
        "neighbor_count": len(neighbors),
        "matched_on": matches,
        "known_label": str(label.get("label")) if label else None,
    }
    return evidence
