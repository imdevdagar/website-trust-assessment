"""HTTP response-header and transport hygiene evidence."""

from __future__ import annotations

from urllib.parse import urlsplit

from ..knowledge import registrable_domain
from ..schemas import Dimension, Evidence, Severity
from .base import ScanContext, truncate

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


def extract(ctx: ScanContext) -> list[Evidence]:
    evidence: list[Evidence] = []
    headers = {str(k).lower(): str(v) for k, v in ctx.page.headers.items()}
    final_scheme = ctx.final_parts.scheme
    ctx.add_source("headers", bool(headers))
    if not headers:
        ctx.add_missing("HTTP response headers could not be captured")
        return evidence

    if final_scheme == "https":
        missing = []
        if not headers.get("strict-transport-security"):
            missing.append("Strict-Transport-Security (HSTS)")
        if not headers.get("content-security-policy"):
            missing.append("Content-Security-Policy")
        if not headers.get("x-frame-options") and "frame-ancestors" not in headers.get(
            "content-security-policy", ""
        ):
            missing.append("clickjacking protection (X-Frame-Options / frame-ancestors)")
        if not headers.get("x-content-type-options"):
            missing.append("X-Content-Type-Options")
        if not headers.get("referrer-policy"):
            missing.append("Referrer-Policy")
        if not headers.get("permissions-policy"):
            missing.append("Permissions-Policy")
        if len(missing) >= 4:
            evidence.append(
                ctx.evidence(
                    dimension=Dimension.SECURITY,
                    code="weak_security_headers",
                    title="Several browser hardening headers are missing",
                    detail="The response omits " + ", ".join(missing[:6]) + ". These headers reduce impact of "
                    "content injection, clickjacking, and referrer leakage. Their absence is common and does not "
                    "prove malicious intent.",
                    severity=Severity.LOW,
                    risk_points=min(8.0, 1.5 * len(missing)),
                    confidence=0.6,
                    source="headers",
                    provenance={"missing": missing, "server": truncate(headers.get("server", ""), 80)},
                    tags=["headers", "hygiene", "weak_signal"],
                )
            )
        elif not missing:
            evidence.append(
                ctx.evidence(
                    dimension=Dimension.SECURITY,
                    code="strong_security_headers",
                    title="Common browser hardening headers are present",
                    detail="The response sets HSTS, CSP, clickjacking protection, nosniff, referrer, and permissions "
                    "policies. This shows security engineering practice, not business legitimacy.",
                    severity=Severity.INFO,
                    risk_points=0.0,
                    trust_points=2.0,
                    confidence=0.7,
                    source="headers",
                    provenance={"headers": sorted(SECURITY_HEADERS)},
                    tags=["headers", "hygiene", "weak_trust"],
                )
            )

    server_header = headers.get("server", "")
    if server_header and any(char.isdigit() for char in server_header) and "/" in server_header:
        ctx.notes["server_header"] = truncate(server_header, 100)

    if final_scheme == "https":
        insecure_cookies = [
            cookie for cookie in ctx.page.cookies if not cookie.get("secure") and not cookie.get("session")
        ]
        if ctx.page.engine == "playwright" and len(insecure_cookies) >= 3:
            evidence.append(
                ctx.evidence(
                    dimension=Dimension.SECURITY,
                    code="insecure_cookie_flags",
                    title="Persistent cookies without the Secure flag",
                    detail=f"{len(insecure_cookies)} persistent cookie(s) are not marked Secure on an HTTPS page. "
                    "They could be sent over an unencrypted connection if one is ever used.",
                    severity=Severity.LOW,
                    risk_points=3.0,
                    confidence=0.5,
                    source="headers",
                    provenance={"cookie_names": [c.get("name", "") for c in insecure_cookies[:8]]},
                    tags=["cookies", "hygiene"],
                )
            )

        mixed_hosts: set[str] = set()
        for url in ctx.page.network_urls:
            if url.startswith("http://"):
                host = urlsplit(url).hostname or ""
                if host:
                    mixed_hosts.add(host.lower())
        if mixed_hosts:
            evidence.append(
                ctx.evidence(
                    dimension=Dimension.SECURITY,
                    code="mixed_content",
                    title="HTTPS page references plain-HTTP resources",
                    detail="The page loads resources over HTTP while being served over HTTPS. Modern browsers block "
                    "much mixed content, but any allowed request is exposed to tampering. Hosts observed: "
                    + ", ".join(sorted(mixed_hosts)[:5])
                    + ".",
                    severity=Severity.MEDIUM,
                    risk_points=7.0,
                    confidence=0.65,
                    source="headers",
                    provenance={"hosts": sorted(mixed_hosts)[:8]},
                    tags=["mixed_content", "transport"],
                )
            )

    if ctx.page.status and ctx.page.status in {401, 403, 429}:
        ctx.add_missing(
            f"The site returned HTTP {ctx.page.status}; visible content may be an access-control page rather than the real site"
        )

    third_party_cookie_domains = {
        str(cookie.get("domain", "")).lstrip(".").lower()
        for cookie in ctx.page.cookies
        if cookie.get("domain") and registrable_domain(str(cookie.get("domain", "")).lstrip(".")) != ctx.final_domain
    }
    if len(third_party_cookie_domains) >= 3:
        evidence.append(
            ctx.evidence(
                dimension=Dimension.PRIVACY,
                code="third_party_cookies",
                title="Multiple third-party cookie domains",
                detail=f"Cookies were set for {len(third_party_cookie_domains)} domains other than the site itself, "
                "which enables cross-site tracking and profiling.",
                severity=Severity.LOW,
                risk_points=4.0,
                confidence=0.6,
                source="headers",
                provenance={"cookie_domains": sorted(third_party_cookie_domains)[:8]},
                tags=["cookies", "tracking"],
            )
        )

    if ctx.page.redirect_chain and len(ctx.page.redirect_chain) >= 3:
        evidence.append(
            ctx.evidence(
                dimension=Dimension.IDENTITY,
                code="long_redirect_chain",
                title="Long redirect chain",
                detail=f"The URL passed through {len(ctx.page.redirect_chain)} locations before settling. Long chains "
                "can obscure the final destination; check the address bar after loading.",
                severity=Severity.LOW,
                risk_points=3.0,
                confidence=0.5,
                source="headers",
                provenance={"hops": len(ctx.page.redirect_chain)},
                tags=["redirect"],
            )
        )

    return evidence
