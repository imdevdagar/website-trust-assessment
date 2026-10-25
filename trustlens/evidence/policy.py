"""Privacy-policy presence and clause analysis.

The policy is fetched separately from the main page, through the same SSRF
guard as every other request. Only aggregate features and short clause
snippets are retained; the policy body itself is never stored.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

from ..crawler import fetch_text
from ..schemas import Dimension, Evidence, Severity
from ..security import registrable_domain, sanitize_text
from .base import ScanContext, truncate

PRIVACY_LINK_RE = re.compile(
    r"privacy|data[-\s]?protection|datenschutz|privacybeleid|goprivacy",
    re.IGNORECASE,
)
POLICY_CONTEXT_RE = re.compile(
    r"\b(privacy|personal (?:data|information)|we (?:collect|process|share)|data protection)\b",
    re.IGNORECASE,
)
NEGATION_RE = re.compile(r"\b(do not|don't|never|no|without)\b[^.]{0,30}$", re.IGNORECASE)

CLAUSE_SPECS: tuple[dict[str, Any], ...] = (
    {
        "code": "privacy_third_party_sharing",
        "title": "Policy allows sharing data with third parties",
        "pattern": re.compile(
            r"(?:share|disclose|provide|transfer)[^.]{0,140}"
            r"(?:third[-\s]?part(?:y|ies)|affiliat(?:e|es)|partners?|advertis\w*|"
            r"data brokers?|service providers?)",
            re.IGNORECASE,
        ),
        "risk": 7.0,
        "severity": Severity.MEDIUM,
        "detail": "The privacy policy describes disclosure of personal data to third parties. "
        "This is common for analytics, payments, and cloud hosting, but it widens the data-sharing surface.",
        "tags": ["privacy", "third_party", "policy_clause"],
    },
    {
        "code": "privacy_data_sale",
        "title": "Policy language around selling personal data",
        "pattern": re.compile(
            r"\b(?:sell|sale|rent)\b[^.]{0,100}\b(?:personal|user|customer|your)\s+"
            r"(?:data|information|details)\b",
            re.IGNORECASE,
        ),
        "risk": 8.0,
        "severity": Severity.MEDIUM,
        "detail": "The privacy policy contains language about selling or renting personal data. "
        "Check the scope and any opt-out rights before providing information.",
        "negate": True,
        "tags": ["privacy", "data_sale", "policy_clause"],
    },
    {
        "code": "privacy_arbitration",
        "title": "Policy includes an arbitration or class-action waiver",
        "pattern": re.compile(
            r"binding arbitration|class[-\s]?action waiver|"
            r"waive[^.]{0,60}(?:jury trial|class action)",
            re.IGNORECASE,
        ),
        "risk": 6.0,
        "severity": Severity.MEDIUM,
        "detail": "The policy appears to require arbitration or waive class-action rights. "
        "This affects how disputes can be pursued; it is not a security signal by itself.",
        "tags": ["privacy", "terms", "policy_clause"],
    },
    {
        "code": "privacy_vague_retention",
        "title": "Vague data-retention language",
        "pattern": re.compile(
            r"(?:retain|keep|store)[^.]{0,100}"
            r"(?:as long as (?:necessary|needed)|at our discretion|indefinitely|"
            r"reasonable (?:period|time))",
            re.IGNORECASE,
        ),
        "risk": 4.0,
        "severity": Severity.LOW,
        "detail": "Retention is described in vague terms. Open-ended retention makes it harder for visitors "
        "to understand how long their data is kept.",
        "tags": ["privacy", "retention", "policy_clause"],
    },
    {
        "code": "privacy_tracking_disclosure",
        "title": "Policy discloses advertising or tracking cookies",
        "pattern": re.compile(
            r"(?:cookies?|pixels?|beacons?)[^.]{0,120}(?:advertis\w*|marketing|track\w*|target\w*)|"
            r"(?:advertis\w*|marketing)[^.]{0,120}(?:cookies?|tracking)",
            re.IGNORECASE,
        ),
        "risk": 3.0,
        "severity": Severity.LOW,
        "detail": "The policy acknowledges advertising, tracking, or profiling cookies. "
        "Disclosure is preferable to silence, but the practice still involves third-party observation.",
        "tags": ["privacy", "tracking", "policy_clause"],
    },
    {
        "code": "privacy_international_transfer",
        "title": "Data may be transferred internationally",
        "pattern": re.compile(
            r"(?:transfer|store|process)[^.]{0,100}"
            r"(?:outside|international|third countr|united states|european union)",
            re.IGNORECASE,
        ),
        "risk": 3.0,
        "severity": Severity.LOW,
        "detail": "The policy mentions transferring data across borders. The legal protections that apply "
        "may differ from those in the visitor's jurisdiction.",
        "tags": ["privacy", "transfer", "policy_clause"],
    },
    {
        "code": "privacy_law_enforcement",
        "title": "Broad disclosure to authorities",
        "pattern": re.compile(
            r"(?:law enforcement|legal process|government (?:request|authorit))",
            re.IGNORECASE,
        ),
        "risk": 3.0,
        "severity": Severity.LOW,
        "detail": "The policy describes disclosure in response to legal or government requests. "
        "This is standard in many policies; the scope and notice commitments matter.",
        "tags": ["privacy", "disclosure", "policy_clause"],
    },
    {
        "code": "privacy_sensitive_data",
        "title": "Policy references sensitive data categories",
        "pattern": re.compile(
            r"(?:biometric|precise (?:geo)?location|health (?:data|information)|"
            r"racial|ethnic|religious|political opinion)",
            re.IGNORECASE,
        ),
        "risk": 4.0,
        "severity": Severity.LOW,
        "detail": "The policy references sensitive data categories. Handling of this data carries higher "
        "privacy risk and usually requires stronger safeguards.",
        "tags": ["privacy", "sensitive_data", "policy_clause"],
    },
)

RIGHTS_RE = re.compile(
    r"(?:opt[-\s]?out|right to (?:access|delete|correct|port)|withdraw (?:your )?consent|"
    r"data protection officer|\bdpo\b|subject access request)",
    re.IGNORECASE,
)
DO_NOT_SELL_RE = re.compile(
    r"(?:do not|don't|never)\s+(?:sell|share)\b[^.]{0,80}\b(?:personal|your|my)\b",
    re.IGNORECASE,
)


def _policy_candidates(ctx: ScanContext) -> list[dict[str, Any]]:
    seen: set[str] = set()
    candidates: list[dict[str, Any]] = []
    for link in ctx.page.links:
        href = str(link.get("href") or "")
        text = str(link.get("text") or "")
        if not PRIVACY_LINK_RE.search(f"{href} {text}"):
            continue
        if urlsplit(href).scheme not in {"http", "https"}:
            continue
        if href.lower().split("?", 1)[0].endswith((".pdf", ".doc", ".docx")):
            continue
        if href in seen:
            continue
        seen.add(href)
        candidates.append(link)

    def rank(link: dict[str, Any]) -> tuple[int, int]:
        host = (urlsplit(str(link.get("href") or "")).hostname or "").lower()
        same_site = 0 if registrable_domain(host) == ctx.final_domain else 1
        explicit = 0 if "privacy" in str(link.get("href") or "").lower() else 1
        return same_site, explicit

    candidates.sort(key=rank)
    return candidates[: max(1, ctx.settings.max_policy_fetch)]


async def _load_policy(url: str) -> tuple[str, dict[str, Any]] | None:
    result, html = await fetch_text(url, max_bytes=900_000, timeout=8.0)
    if result.error or not (200 <= result.status < 400):
        return None
    if "html" not in result.content_type.lower() and "text" not in result.content_type.lower():
        return None
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        return None
    for tag in soup(["script", "style", "noscript", "svg", "form", "iframe"]):
        tag.decompose()
    title = sanitize_text(soup.title.get_text(" ", strip=True), 200) if soup.title else ""
    text = sanitize_text(soup.get_text(" ", strip=True), 600_000)
    words = re.findall(r"[A-Za-z']{2,}", text)
    if len(words) < 100:
        return None
    if len(POLICY_CONTEXT_RE.findall(text)) < 2:
        return None
    meta = {
        "url": result.final_url,
        "title": title,
        "words": len(words),
        "text": text,
    }
    return text, meta


def _clause_snippet(text: str, match: re.Match[str], limit: int = 190) -> str:
    start = max(0, match.start() - 70)
    end = min(len(text), match.end() + 90)
    return truncate(text[start:end], limit)


def _find_clause(text: str, spec: dict[str, Any]) -> str:
    for match in spec["pattern"].finditer(text):
        if spec.get("negate"):
            prefix = text[max(0, match.start() - 50) : match.start()]
            if NEGATION_RE.search(prefix):
                continue
        return _clause_snippet(text, match)
    return ""


def _policy_evidence(ctx: ScanContext, text: str, meta: dict[str, Any]) -> list[Evidence]:
    evidence: list[Evidence] = []
    external = registrable_domain(urlsplit(meta["url"]).hostname or "") != ctx.final_domain
    evidence.append(
        ctx.evidence(
            dimension=Dimension.PRIVACY,
            code="privacy_policy_accessible",
            title="Privacy policy is accessible",
            detail=f"A readable privacy policy was found ({meta['words']} words) at {meta['url']}. "
            "An accessible policy is a transparency positive, but its promises are not verified against "
            "the site's actual behavior.",
            severity=Severity.INFO,
            trust_points=2.5,
            confidence=0.8,
            source="policy",
            provenance={
                "policy_url": meta["url"],
                "title": meta["title"],
                "word_count": meta["words"],
                "external_host": external,
            },
            tags=["privacy", "transparency", "policy_present"],
        )
    )
    if meta["words"] < 250:
        evidence.append(
            ctx.evidence(
                dimension=Dimension.PRIVACY,
                code="privacy_policy_thin",
                title="Privacy policy is unusually short",
                detail=f"The policy is only about {meta['words']} words. Short notices can be legitimate, "
                "but they often omit retention, sharing, and user-rights details.",
                severity=Severity.LOW,
                risk_points=4.0,
                confidence=0.55,
                source="policy",
                provenance={"word_count": meta["words"], "policy_url": meta["url"]},
                tags=["privacy", "transparency", "policy_quality"],
            )
        )

    seen_codes: set[str] = set()
    for spec in CLAUSE_SPECS:
        snippet = _find_clause(text, spec)
        if not snippet:
            continue
        seen_codes.add(spec["code"])
        evidence.append(
            ctx.evidence(
                dimension=Dimension.PRIVACY,
                code=spec["code"],
                title=spec["title"],
                detail=f"{spec['detail']} Policy text: \"{snippet}\"",
                severity=spec["severity"],
                risk_points=spec["risk"],
                confidence=0.7,
                source="policy",
                provenance={
                    "snippet": snippet,
                    "policy_url": meta["url"],
                },
                tags=list(spec["tags"]),
            )
        )

    rights = list(dict.fromkeys(match.group(0).lower() for match in RIGHTS_RE.finditer(text)))
    do_not_sell = bool(DO_NOT_SELL_RE.search(text))
    if rights or do_not_sell:
        parts = []
        if do_not_sell:
            parts.append("the policy states that personal data is not sold")
        if rights:
            parts.append("visitor rights or opt-out mechanisms are described")
        evidence.append(
            ctx.evidence(
                dimension=Dimension.PRIVACY,
                code="privacy_rights_described",
                title="Visitor privacy rights are described",
                detail="The policy includes " + " and ".join(parts) + ". This is a transparency positive; "
                "exercising these rights may still require effort.",
                severity=Severity.INFO,
                trust_points=2.0 if do_not_sell else 1.0,
                confidence=0.65,
                source="policy",
                provenance={
                    "rights_terms": rights[:8],
                    "do_not_sell": do_not_sell,
                    "policy_url": meta["url"],
                },
                tags=["privacy", "rights", "transparency"],
            )
        )
    ctx.notes["privacy_policy"] = {
        "url": meta["url"],
        "word_count": meta["words"],
        "external_host": external,
        "clauses": sorted(seen_codes),
        "rights_described": bool(rights),
        "do_not_sell": do_not_sell,
    }
    return evidence


async def extract(ctx: ScanContext) -> list[Evidence]:
    evidence: list[Evidence] = []
    candidates = _policy_candidates(ctx)
    if not candidates:
        ctx.add_source("privacy_policy", False)
        ctx.add_missing("No privacy-policy link was found on the main page")
        collects_data = bool(ctx.forms) or ctx.has_payment_form or ctx.has_password_form
        evidence.append(
            ctx.evidence(
                dimension=Dimension.PRIVACY,
                code="privacy_policy_missing",
                title="No privacy-policy link found",
                detail="No link to a privacy policy was visible on the main page. "
                + (
                    "The page contains a form that can collect visitor data, so the absence of a notice "
                    "is a meaningful transparency gap."
                    if collects_data
                    else "This is a low-severity transparency gap for an informational page."
                ),
                severity=Severity.LOW if collects_data else Severity.INFO,
                risk_points=5.0 if collects_data else 2.0,
                confidence=0.6,
                source="page",
                provenance={
                    "links_scanned": len(ctx.page.links),
                    "form_count": len(ctx.forms),
                    "transactional": ctx.has_payment_form,
                },
                tags=["privacy", "transparency", "policy_missing"],
            )
        )
        return evidence

    tasks = [asyncio.create_task(_load_policy(str(link["href"]))) for link in candidates]
    try:
        results = await asyncio.wait_for(
            asyncio.gather(*tasks, return_exceptions=True),
            timeout=16.0,
        )
    except TimeoutError:
        for task in tasks:
            task.cancel()
        results = []
        ctx.add_missing("Privacy-policy retrieval timed out")

    loaded: tuple[str, dict[str, Any]] | None = None
    for result in results:
        if isinstance(result, Exception) or not result:
            continue
        loaded = result
        break

    if loaded is None:
        ctx.add_source("privacy_policy", False)
        ctx.add_missing("A privacy-policy link was present but its content could not be retrieved")
        evidence.append(
            ctx.evidence(
                dimension=Dimension.PRIVACY,
                code="privacy_policy_unavailable",
                title="Privacy-policy link could not be verified",
                detail="The page links to a privacy policy, but it could not be loaded as readable HTML. "
                "The link may be broken, require JavaScript, or point to a document format.",
                severity=Severity.LOW,
                risk_points=3.0,
                confidence=0.5,
                source="policy",
                provenance={"candidates": [str(link.get("href"))[:250] for link in candidates]},
                tags=["privacy", "transparency", "policy_unavailable"],
            )
        )
        return evidence

    ctx.add_source("privacy_policy", True)
    text, meta = loaded
    evidence.extend(_policy_evidence(ctx, text, meta))
    return evidence
