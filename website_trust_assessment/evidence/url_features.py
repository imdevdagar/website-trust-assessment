"""URL-structure evidence: domain impersonation, obfuscation, transport scheme."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

from ..knowledge import (
    brands,
    decode_punycode_host,
    domain_core,
    homoglyph_fold,
    host_prefix,
    is_file_host,
    is_free_subdomain,
    is_official_domain,
    is_suspicious_tld,
    is_url_shortener,
    levenshtein,
    matching_brand_for_host,
)
from ..schemas import Dimension, Evidence, Severity
from ..security import host_from_url
from .base import ScanContext, truncate

RISKY_URL_TOKENS = re.compile(
    r"kyc|verif|login|sign[-\s]?in|secure|account|update|wallet|airdrop|claim|"
    r"prize|gift|bonus|unlock|recover|seed|winner|support",
    re.IGNORECASE,
)
SECRET_QUERY_PARAMS = re.compile(
    r"token|session|password|passwd|otp|seed|private[_-]?key|api[_-]?key|secret|auth",
    re.IGNORECASE,
)
REDIRECT_PARAMS = re.compile(r"redirect|return|next|continue|url|target|dest", re.IGNORECASE)


def _brand_impersonation(host: str) -> tuple[str, str, float, float] | None:
    """Detect brand-like labels. Returns (code, detail, risk, confidence)."""
    if not host or is_official_domain(host):
        return None
    labels = [label for label in host.split(".") if label]
    registrable = domain_core(host)
    prefix = host_prefix(host).split(".")
    best: tuple[str, str, float, float] | None = None

    for item in brands():
        official_cores = {domain_core(domain) for domain in item.domains}
        for core in official_cores:
            if len(core) < 4:
                continue
            # 1. brand token used as a subdomain, e.g. paypal.com.evil.tk
            if core in prefix:
                candidate = (
                    "brand_subdomain_impersonation",
                    f"The hostname places '{core}' before the actual registered domain '{registrable}'.",
                    38.0,
                    0.85,
                )
                if best is None or candidate[2] > best[2]:
                    best = candidate
            # 2. brand plus an action token, e.g. paypal-secure-login.tk
            tokens = [token for label in labels for token in re.split(r"[-_]", label)]
            has_action = any(RISKY_URL_TOKENS.search(token) for token in tokens if token != core)
            if (core in tokens or any(core in label for label in labels if label != core)) and has_action:
                candidate = (
                    "brand_action_domain",
                    f"The domain combines the brand token '{core}' with account or verification wording.",
                    32.0,
                    0.75,
                )
                if best is None or candidate[2] > best[2]:
                    best = candidate
            # 3. lookalikes and typosquats in any label
            for label in [*labels, registrable]:
                if label == core:
                    continue
                folded = homoglyph_fold(label)
                if folded == core:
                    candidate = (
                        "typosquatting_domain",
                        f"The label '{label}' is visually confusable with the brand '{core}'.",
                        38.0,
                        0.85,
                    )
                    if best is None or candidate[2] > best[2]:
                        best = candidate
                elif len(core) >= 5 and abs(len(label) - len(core)) <= 2:
                    distance = levenshtein(folded, core, max_distance=2)
                    threshold = 1 if len(core) < 10 else 2
                    if 0 < distance <= threshold:
                        candidate = (
                            "typosquatting_domain",
                            f"The label '{label}' is {distance} edit(s) away from the brand '{core}'.",
                            34.0,
                            0.75,
                        )
                        if best is None or candidate[2] > best[2]:
                            best = candidate
    return best


def _query_signals(url: str) -> list[tuple[str, Dimension, str, str, float, float]]:
    signals: list[tuple[str, Dimension, str, str, float, float]] = []
    try:
        query = urlsplit(url).query
    except ValueError:
        return signals
    try:
        pairs = parse_qsl(query, keep_blank_values=True, max_num_fields=60)
    except ValueError:
        return signals
    sensitive_names = sorted({name for name, _ in pairs if SECRET_QUERY_PARAMS.search(name)})
    if sensitive_names:
        signals.append(
            (
                "secret_in_url",
                Dimension.PRIVACY,
                "Credential-like parameter in the URL",
                "URLs are stored in browser history, logs, and referrer headers. "
                f"Parameter names observed: {', '.join(sensitive_names[:5])}.",
                8.0,
                0.65,
            )
        )
    redirect_hosts: list[str] = []
    for name, value in pairs:
        if REDIRECT_PARAMS.search(name) and ("http://" in value.lower() or "https://" in value.lower() or "%3a%2f%2f" in value.lower()):
            host = host_from_url(value)
            if not host and "%3a%2f%2f" in value.lower():
                from urllib.parse import unquote

                host = host_from_url(unquote(value))
            if host:
                redirect_hosts.append(host)
    if redirect_hosts:
        signals.append(
            (
                "embedded_redirect",
                Dimension.IDENTITY,
                "External destination embedded in the URL",
                f"A query parameter contains another destination host ({', '.join(sorted(set(redirect_hosts))[:3])}). "
                "Confirm the final destination before signing in or paying.",
                5.0,
                0.55,
            )
        )
    return signals


def extract(ctx: ScanContext) -> list[Evidence]:
    evidence: list[Evidence] = []
    ctx.add_source("url", True)
    final = ctx.final_parts
    initial = ctx.parts
    final_host = final.host
    official = is_official_domain(final_host)
    host_labels = final_host.split(".")
    scheme = final.scheme

    if scheme == "http":
        evidence.append(
            ctx.evidence(
                dimension=Dimension.SECURITY,
                code="unencrypted_http",
                title="Page is served without HTTPS",
                detail="The final page uses plain HTTP. Credentials, cookies, and page content can be "
                "read or modified in transit. This is a transport risk, not proof of fraud.",
                severity=Severity.HIGH,
                risk_points=22.0,
                confidence=0.95,
                source="url",
                provenance={"scheme": scheme, "host": final_host},
                tags=["transport", "encryption"],
            )
        )

    if final.is_ip:
        evidence.append(
            ctx.evidence(
                dimension=Dimension.SECURITY,
                code="ip_literal_host",
                title="Site is addressed by raw IP",
                detail="The site is reached by an IP address rather than a domain name. This hides "
                "registrant identity, breaks normal certificate expectations, and is common in "
                "throwaway phishing infrastructure.",
                severity=Severity.HIGH,
                risk_points=24.0,
                confidence=0.9,
                source="url",
                provenance={"host": final_host},
                tags=["url_structure"],
            )
        )

    if final.is_punycode:
        decoded = decode_punycode_host(final_host)
        evidence.append(
            ctx.evidence(
                dimension=Dimension.IDENTITY,
                code="punycode_host",
                title="Internationalized (punycode) hostname",
                detail=f"The hostname '{final_host}' decodes to '{decoded}'. Punycode is legitimate for "
                "international domains but is also used to imitate familiar Latin-script brands.",
                severity=Severity.MEDIUM,
                risk_points=12.0,
                confidence=0.6,
                source="url",
                provenance={"host": final_host, "decoded": decoded},
                tags=["url_structure", "homograph"],
            )
        )

    if not official:
        impersonation = _brand_impersonation(final_host)
        if impersonation:
            code, detail, risk, confidence = impersonation
            evidence.append(
                ctx.evidence(
                    dimension=Dimension.IDENTITY,
                    code=code,
                    title="Domain resembles a brand it does not own",
                    detail=detail,
                    severity=Severity.HIGH if risk >= 30 else Severity.MEDIUM,
                    risk_points=risk,
                    confidence=confidence,
                    source="url",
                    provenance={"host": final_host, "brand_domains_checked": "local brand list"},
                    tags=["impersonation", "domain"],
                )
            )
        elif final_host != final.registrable_domain:
            identity_hint = f"{domain_core(final_host)}.{final.registrable_domain.split('.')[-1]}"
            evidence.append(
                ctx.evidence(
                    dimension=Dimension.IDENTITY,
                    code="hostname_note",
                    title="Multi-label hostname",
                    detail=f"The site uses the hostname '{final_host}' (registered domain '{final.registrable_domain}'). "
                    "Complex hostnames are normal for hosting platforms but deserve a second look on login pages.",
                    severity=Severity.INFO,
                    risk_points=0.0,
                    confidence=0.4,
                    source="url",
                    provenance={"host": final_host, "identity_hint": truncate(identity_hint, 60)},
                    tags=["url_structure"],
                )
            )

        if is_suspicious_tld(final_host):
            evidence.append(
                ctx.evidence(
                    dimension=Dimension.IDENTITY,
                    code="suspicious_tld",
                    title="Frequently abused top-level domain",
                    detail=f"The domain ends in '.{final.registrable_domain.rsplit('.', 1)[-1]}', a TLD with elevated "
                    "abuse rates. Many legitimate sites use it too, so this is only a weak contextual signal.",
                    severity=Severity.LOW,
                    risk_points=4.0,
                    confidence=0.4,
                    source="url",
                    provenance={"registrable_domain": final.registrable_domain},
                    tags=["url_structure", "weak_signal"],
                )
            )

        core_label = domain_core(final_host)
        hyphen_count = core_label.count("-")
        if hyphen_count >= 3:
            evidence.append(
                ctx.evidence(
                    dimension=Dimension.IDENTITY,
                    code="hyphenated_domain",
                    title="Heavily hyphenated domain",
                    detail=f"The domain label '{core_label}' contains {hyphen_count} hyphens. Long hyphenated "
                    "labels are common in automatically generated phishing domains but also in small businesses.",
                    severity=Severity.LOW,
                    risk_points=4.0,
                    confidence=0.4,
                    source="url",
                    provenance={"label": truncate(core_label, 80)},
                    tags=["url_structure", "weak_signal"],
                )
            )

        if len(host_labels) >= 5:
            evidence.append(
                ctx.evidence(
                    dimension=Dimension.IDENTITY,
                    code="deep_subdomains",
                    title="Unusually deep subdomain chain",
                    detail=f"The hostname has {len(host_labels)} labels. Deep nesting can obscure the real "
                    "registered domain in a narrow address bar.",
                    severity=Severity.LOW,
                    risk_points=3.0,
                    confidence=0.35,
                    source="url",
                    provenance={"host": truncate(final_host, 120)},
                    tags=["url_structure", "weak_signal"],
                )
            )

        path = urlsplit(ctx.final_url).path
        if RISKY_URL_TOKENS.search(path) and not ctx.has_password_form:
            evidence.append(
                ctx.evidence(
                    dimension=Dimension.IDENTITY,
                    code="risky_path_keywords",
                    title="Account-themed path on an unrecognized domain",
                    detail="The URL path uses account or verification wording. This is weak evidence by itself "
                    "but relevant when combined with credential collection.",
                    severity=Severity.INFO,
                    risk_points=3.0,
                    confidence=0.35,
                    source="url",
                    provenance={"path": truncate(path, 120)},
                    tags=["url_structure", "weak_signal"],
                )
            )

    provider = is_free_subdomain(final_host)
    if provider:
        risk = 25.0 if ctx.has_password_form else 8.0
        evidence.append(
            ctx.evidence(
                dimension=Dimension.IDENTITY,
                code="free_subdomain_host",
                title="Hosted on a shared free-subdomain service",
                detail=f"The site runs on '{provider}', where anyone can create a subdomain. This is normal for "
                "personal projects but unusual for a bank, wallet, or established merchant."
                + (" The page also requests credentials." if ctx.has_password_form else ""),
                severity=Severity.MEDIUM if ctx.has_password_form else Severity.LOW,
                risk_points=risk,
                confidence=0.65 if ctx.has_password_form else 0.45,
                source="url",
                provenance={"provider": provider, "host": final_host},
                tags=["hosting", "identity"],
            )
        )

    if is_file_host(final_host):
        evidence.append(
            ctx.evidence(
                dimension=Dimension.SECURITY,
                code="file_host_destination",
                title="Destination is a file-sharing or paste service",
                detail="The final page is hosted on a service intended for documents or file sharing, not "
                "for account or payment interactions.",
                severity=Severity.MEDIUM,
                risk_points=7.0,
                confidence=0.55,
                source="url",
                provenance={"host": final_host},
                tags=["hosting"],
            )
        )

    initial_host = initial.host
    if initial_host and initial.registrable_domain != final.registrable_domain:
        shortener = is_url_shortener(initial_host)
        evidence.append(
            ctx.evidence(
                dimension=Dimension.IDENTITY,
                code="cross_domain_redirect",
                title="URL redirects to a different domain",
                detail=(
                    f"The submitted URL on '{initial_host}' resolves to '{final.registrable_domain}'. "
                    + ("The submitted host is a link shortener, which hides the true destination. " if shortener else "")
                    + "This can be legitimate (for example, a regional site) but is also used to evade link checks."
                ),
                severity=Severity.LOW,
                risk_points=6.0 if shortener else 4.0,
                confidence=0.6 if shortener else 0.5,
                source="url",
                provenance={
                    "initial_host": initial_host,
                    "final_domain": final.registrable_domain,
                    "shortener": shortener,
                },
                tags=["redirect", "url_structure"],
            )
        )

    for code, dimension, title, detail, risk, confidence in _query_signals(ctx.final_url):
        evidence.append(
            ctx.evidence(
                dimension=dimension,
                code=code,
                title=title,
                detail=detail,
                severity=Severity.MEDIUM if risk >= 6 else Severity.LOW,
                risk_points=risk,
                confidence=confidence,
                source="url",
                provenance={"path": truncate(urlsplit(ctx.final_url).path, 100)},
                tags=["url_structure"],
            )
        )

    if official:
        brand_match = matching_brand_for_host(final_host)
        evidence.append(
            ctx.evidence(
                dimension=Dimension.IDENTITY,
                code="official_domain",
                title="Registered domain matches a known brand",
                detail=(
                    f"The site is on '{final.registrable_domain}', listed locally as an official domain for "
                    f"{brand_match.name if brand_match else 'a known brand'}. This says nothing about the integrity "
                    "of the specific page or the security of the connection."
                ),
                severity=Severity.INFO,
                risk_points=0.0,
                trust_points=2.0,
                confidence=0.9,
                source="url",
                provenance={"registrable_domain": final.registrable_domain},
                tags=["official_domain", "weak_trust"],
            )
        )

    return evidence
