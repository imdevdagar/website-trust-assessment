"""Shared context and evidence-construction helpers for extractors."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

from ..config import Settings
from ..schemas import Dimension, Evidence, Severity
from ..security import URLParts, url_parts

if TYPE_CHECKING:
    from ..crawler import CrawlData


@dataclass
class DomainIntel:
    domain: str = ""
    rdap: dict[str, Any] = field(default_factory=dict)
    dns: dict[str, Any] = field(default_factory=dict)
    tls: dict[str, Any] | None = None
    rdap_ok: bool = False
    dns_ok: bool = False
    tls_ok: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def age_days(self) -> int | None:
        value = self.rdap.get("age_days")
        return int(value) if isinstance(value, (int, float)) else None


@dataclass
class ScanContext:
    url: str
    parts: URLParts
    page: "CrawlData"
    settings: Settings
    intel: DomainIntel = field(default_factory=DomainIntel)
    sources: dict[str, bool] = field(default_factory=dict)
    missing_evidence: list[str] = field(default_factory=list)
    notes: dict[str, Any] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def final_url(self) -> str:
        return self.page.final_url or self.url

    @property
    def final_domain(self) -> str:
        return self.page.domain or self.parts.registrable_domain

    @property
    def final_host(self) -> str:
        try:
            return url_parts(self.final_url).host
        except Exception:
            return self.parts.host

    @property
    def final_parts(self) -> URLParts:
        try:
            return url_parts(self.final_url)
        except Exception:
            return self.parts

    @property
    def text(self) -> str:
        return self.page.text

    @property
    def forms(self):
        return self.page.forms

    @property
    def has_password_form(self) -> bool:
        return self.page.has_credential_form

    @property
    def has_payment_form(self) -> bool:
        return self.page.has_payment_form

    @property
    def page_available(self) -> bool:
        return bool(self.page.html or self.page.visible_text) and not self.page.error

    def add_missing(self, message: str) -> None:
        if message not in self.missing_evidence:
            self.missing_evidence.append(message)

    def add_source(self, name: str, available: bool) -> None:
        self.sources[name] = bool(available)

    def evidence(
        self,
        *,
        dimension: Dimension,
        code: str,
        title: str,
        detail: str,
        severity: Severity,
        risk_points: float = 0.0,
        trust_points: float = 0.0,
        confidence: float = 0.8,
        source: str = "page",
        provenance: dict[str, Any] | None = None,
        tags: list[str] | None = None,
    ) -> Evidence:
        return Evidence(
            dimension=dimension,
            code=code,
            title=title,
            detail=detail,
            severity=severity,
            risk_points=max(0.0, risk_points),
            trust_points=max(0.0, trust_points),
            confidence=max(0.0, min(1.0, confidence)),
            source=source,
            provenance=provenance or {},
            tags=tags or [],
        )


def truncate(value: str, limit: int = 200) -> str:
    value = re.sub(r"\s+", " ", value or "").strip()
    if len(value) <= limit:
        return value
    return value[: limit - 1].rstrip() + "…"


def phrase_hit(text: str, pattern: re.Pattern[str], context: int = 70) -> str:
    match = pattern.search(text or "")
    if not match:
        return ""
    start = max(0, match.start() - context)
    end = min(len(text), match.end() + context)
    return truncate(text[start:end], 180)


def find_link(page: "CrawlData", pattern: re.Pattern[str]) -> list[dict[str, Any]]:
    results = []
    for link in page.links:
        haystack = f"{link.get('href', '')} {link.get('text', '')}"
        if pattern.search(haystack):
            results.append(link)
    return results


def form_field_blob(ctx: ScanContext) -> str:
    parts: list[str] = []
    for form in ctx.forms:
        for field in form.fields:
            parts.append(f"{field.name} {field.placeholder} {field.autocomplete} {field.label}")
    return " ".join(parts)


def form_text_blob(ctx: ScanContext) -> str:
    return " ".join(form.text for form in ctx.forms)


EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})\b", re.IGNORECASE)
PHONE_RE = re.compile(r"(?:\+\d{1,3}[\s.-]?)?(?:\(?\d{2,5}\)?[\s.-]?){2,4}\d{3,5}")
TRUST_LINK_RES = {
    "privacy": re.compile(r"privacy|data[-\s]?protection", re.IGNORECASE),
    "terms": re.compile(r"\bterms\b|tos\b|conditions|legal", re.IGNORECASE),
    "contact": re.compile(r"contact|support|help|customer[-\s]?care", re.IGNORECASE),
    "about": re.compile(r"\babout\b|our[-\s]?story|company", re.IGNORECASE),
    "returns": re.compile(r"refund|return|cancellation", re.IGNORECASE),
}


def trust_links(page: "CrawlData") -> dict[str, bool]:
    found = {name: False for name in TRUST_LINK_RES}
    for link in page.links:
        haystack = f"{link.get('href', '')} {link.get('text', '')}"
        for name, pattern in TRUST_LINK_RES.items():
            if not found[name] and pattern.search(haystack):
                found[name] = True
                break
    return found


def page_emails(page: "CrawlData") -> list[str]:
    return list(dict.fromkeys(match.group(0) for match in EMAIL_RE.finditer(page.visible_text)))[:5]


def free_email_domains() -> set[str]:
    return {
        "gmail.com",
        "googlemail.com",
        "yahoo.com",
        "yahoo.co.in",
        "outlook.com",
        "hotmail.com",
        "live.com",
        "protonmail.com",
        "proton.me",
        "aol.com",
        "mail.ru",
        "yandex.com",
        "zoho.com",
        "gmx.com",
        "icloud.com",
    }


SENSITIVE_FIELD_RE = re.compile(
    r"aadhaar|social[-\s]?security|\bssn\b|passport|national[-\s]?id|"
    r"\bpan\b|pan[-\s]?(number|no|card)|tax[-\s]?id|"
    r"bank[-\s]?account|account[-\s]?(number|no)|routing[-\s]?number|"
    r"\bifsc\b|\biban\b|swift[-\s]?(code|bic)|"
    r"medical|health|patient|diagnosis|prescription|biometric|fingerprint|"
    r"insurance|policy[-\s]?number",
    re.IGNORECASE,
)
ORDINARY_PII_RE = re.compile(
    r"full[-\s]?name|first[-\s]?name|last[-\s]?name|your[-\s]?name|"
    r"\bemail\b|e-?mail|phone|mobile|whatsapp|"
    r"address|street|zip|postal|city|state|country|"
    r"date[-\s]?of[-\s]?birth|\bdob\b|birthday|gender|age\b",
    re.IGNORECASE,
)
CREDENTIAL_FIELD_RE = re.compile(
    r"password|passwd|passcode|pin\b|otp|one[-\s]?time|two[-\s]?factor|2fa|mfa|"
    r"username|user[-\s]?id|login|sign[-\s]?in",
    re.IGNORECASE,
)
CARD_FIELD_RE = re.compile(
    r"card[-\s]?(number|no|holder|name)|cc[-\s]?number|credit[-\s]?card|debit[-\s]?card|"
    r"cvv|cvc|security[-\s]?code|expiry|expiration|exp[-\s]?date",
    re.IGNORECASE,
)


def has_sensitive_fields(ctx: ScanContext) -> bool:
    return bool(SENSITIVE_FIELD_RE.search(form_field_blob(ctx)))


def has_ordinary_pii_fields(ctx: ScanContext) -> bool:
    return bool(ORDINARY_PII_RE.search(form_field_blob(ctx)))


def has_credential_fields(ctx: ScanContext) -> bool:
    return any(form.has_password for form in ctx.forms) or bool(
        CREDENTIAL_FIELD_RE.search(form_field_blob(ctx))
    )


def page_lower(ctx: ScanContext) -> str:
    return ctx.text.lower()
