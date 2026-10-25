"""Page-content evidence: credential collection, payment lures, impersonation, transparency."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..knowledge import brands_in_text, is_official_domain, is_trusted_checkout
from ..schemas import Dimension, Evidence, Severity
from ..security import registrable_domain
from .base import (
    PHONE_RE,
    ScanContext,
    free_email_domains,
    has_credential_fields,
    has_ordinary_pii_fields,
    has_sensitive_fields,
    page_emails,
    phrase_hit,
    form_field_blob,
    truncate,
    trust_links,
)

SEED_PATTERN = re.compile(
    r"\b(enter|provide|input|paste|type|share|send|submit|confirm|verify|restore|import)\b"
    r"[^.?!\n]{0,70}\b(seed|recovery|secret|mnemonic)\s*(phrase|words?)?\b",
    re.IGNORECASE,
)
SEED_WORDS_PATTERN = re.compile(
    r"\b(12|24)[-\s]?word\b[^.?!\n]{0,50}\b(phrase|recovery|seed|mnemonic)\b",
    re.IGNORECASE,
)
SEED_FIELD_PATTERN = re.compile(
    r"seed|mnemonic|recovery[_\s-]?phrase|secret[_\s-]?phrase|private[_\s-]?key", re.IGNORECASE
)
GIFT_CARD_PATTERN = re.compile(
    r"\b(pay|payment|paid)\b[^.\n]{0,50}\b(gift\s?cards?|itunes\s?cards?|google\s?play\s?cards?|amazon\s?cards?|steam\s?cards?)\b|"
    r"\b(gift\s?card)\b[^.\n]{0,40}\b(code|number|voucher)\b|"
    r"\bbuy\b[^.\n]{0,30}\bgift\s?cards?\b",
    re.IGNORECASE,
)
GIFT_DEMAND_PATTERN = re.compile(
    r"\b(pay|payment|paid|send|provide|share)\b[^.\n]{0,50}\b(gift\s?cards?|itunes\s?cards?|google\s?play\s?cards?|amazon\s?cards?|steam\s?cards?)\b|"
    r"\b(gift\s?card)\b[^.\n]{0,40}\b(code|number|voucher)\b",
    re.IGNORECASE,
)
SCAM_CONTEXT = re.compile(
    r"\btech(?:nical)?\s*support\b|\birs\b|\bincome tax\b|\btax refund\b|\bgovernment\b|"
    r"\blaw enforcement\b|\bpolice\b|\bfine\b|\bpenalt(?:y|ies)\b|\bcourt\b|\bprize\b|"
    r"\blottery\b|\bunlock (?:your|the) (?:account|device|funds?)\b|"
    r"\bactivate (?:your|the) (?:account|card|device)\b|\bverification fee\b|"
    r"\bprocessing fee\b|\bdelivery fee\b|\bbail\b|\bhospital\b|\bemergency\b",
    re.IGNORECASE,
)
REMOTE_ACCESS_PATTERN = re.compile(
    r"anydesk|teamviewer|quick\s?support|rustdesk|screen\s?connect|logmein|supremo",
    re.IGNORECASE,
)
ACCOUNT_THREAT_PATTERN = re.compile(
    r"\b(your\s+)?(account|profile|subscription|wallet)\s+(has\s+been|will\s+be|is)\s+"
    r"(suspended|locked|closed|limited|deactivated|blocked)\b|"
    r"\bunusual\s+(activity|sign[-\s]?in|login)\b|"
    r"\bverify\s+your\s+account\b|"
    r"\bconfirm\s+your\s+identity\b",
    re.IGNORECASE,
)
TECH_SUPPORT_LURE = re.compile(
    r"\b(microsoft|windows|apple|google|amazon)\b[^.\n]{0,40}\b(support|security|defender|technician)\b"
    r"[^.\n]{0,80}\b(virus|infected|hacked|locked|compromised|call|toll[-\s]?free|phone)\b|"
    r"\byour\s+(computer|device|pc)\s+(is|may\s+be)\s+(infected|compromised|at\s+risk)\b|"
    r"\bcall\s+(microsoft|apple|windows|google)\s+(support|technician)\b",
    re.IGNORECASE,
)
CRYPTO_LURE = re.compile(
    r"\bclaim\s+your\s+(airdrop|reward|bonus|crypto)\b|"
    r"\bdouble\s+your\s+(bitcoin|btc|eth|ethereum|crypto|usdt)\b|"
    r"\bfree\s+(crypto|bitcoin|eth|usdt)\s+(giveaway|reward)\b|"
    r"\bconnect\s+(your\s+)?wallet\s+to\s+(claim|verify|receive|unlock)\b|"
    r"\bvalidate\s+(your\s+)?wallet\b[^.\n]{0,40}\b(seed|recovery|phrase)\b",
    re.IGNORECASE,
)
REMOTE_COMMAND_LURE = re.compile(
    r"\b(win(?:dows)?\s*\+\s*r|ctrl\s*\+\s*v)\b[^.\n]{0,120}\b(powershell|mshta|cmd|run\s+dialog)\b|"
    r"\bpaste\s+(this|the\s+following)\s+(command|code)\b[^.\n]{0,80}\b(powershell|cmd|terminal|run)\b",
    re.IGNORECASE,
)
INVESTMENT_CONTEXT = re.compile(
    r"\b(?:invest(?:ment|or|ing)?|deposit|trading|portfolio|capital|profit|returns?|roi|plan)\b",
    re.IGNORECASE,
)
GUARANTEED_RETURN_LURE = re.compile(
    r"\b(?:guaranteed|assured|promised|fixed)\s+(?:returns?|profits?|income|roi)\b|"
    r"\b(?:risk[-\s]?free|no[-\s]?risk)\s+(?:investment|returns?|profit|income)\b|"
    r"\bdouble\s+your\s+(?:money|investment|capital|crypto|bitcoin)\b|"
    r"\b(?:earn|make)\s+(?:₹|rs\.?|inr|\$)\s*\d[\d,]*(?:\.\d+)?\s*(?:%|percent)?\s*"
    r"(?:daily|per\s+day|weekly|monthly|guaranteed)\b|"
    r"\b(?:fixed|assured)\s+\d+(?:\.\d+)?\s*%\s*(?:daily|monthly|per\s+annum|returns?)\b|"
    r"\b\d{2,4}\s*%\s*(?:guaranteed\s+)?(?:returns?|profit|income)\b",
    re.IGNORECASE,
)
ADVANCE_FEE_CONTEXT = re.compile(
    r"\b(?:job|employment|hiring|work[-\s]?from[-\s]?home|part[-\s]?time|"
    r"prize|lottery|reward|winner|refund|cashback|visa|immigration|customs|parcel|courier|"
    r"selected|candidate|claim|release)\b",
    re.IGNORECASE,
)
ADVANCE_FEE_DEMAND = re.compile(
    r"\b(?:pay|send|transfer|deposit|remit|wire)\b[^.\n]{0,80}\b"
    r"(?:processing|registration|security|verification|activation|delivery|handling|training|"
    r"documentation|customs|clearance|release|service)\s+(?:fee|charge|deposit|amount|cost)\b|"
    r"\b(?:processing|registration|security|verification|activation|delivery|handling|training|"
    r"documentation|customs|clearance|release|service)\s+(?:fee|charge|deposit)\b"
    r"[^.\n]{0,80}\b(?:pay|send|transfer|deposit|to\s+(?:receive|get|release|claim|start))\b",
    re.IGNORECASE,
)
UPI_ID_PATTERN = re.compile(
    r"\b[a-z0-9][a-z0-9._-]{1,}@(?:oksbi|okhdfcbank|okicici|okaxis|ybl|paytm|ibl|axl|upi|apl)"
    r"(?![\w.])",
    re.IGNORECASE,
)
UPI_PAYMENT_INSTRUCTION = re.compile(
    r"\b(?:pay|payment|send|transfer|deposit)\b[^.\n]{0,60}\b"
    r"(?:upi|gpay|google\s+pay|phonepe|paytm)\b|"
    r"\b(?:upi|gpay|google\s+pay|phonepe|paytm)\b[^.\n]{0,60}\b"
    r"(?:pay|payment|send|transfer|deposit)\b|"
    r"\bscan\b[^.\n]{0,40}\bqr(?:\s+code)?\b[^.\n]{0,60}\b"
    r"(?:pay|payment|send|transfer|deposit)\b",
    re.IGNORECASE,
)
BANK_TRANSFER_PATTERN = re.compile(
    r"\b(?:neft|imps|rtgs|bank\s+transfer|wire\s+transfer)\b|"
    r"\baccount\s+(?:number|no\.?)\b[^.\n]{0,50}\b(?:ifsc|bank|beneficiary)\b|"
    r"\bifsc\s*(?:code)?\b",
    re.IGNORECASE,
)
BANK_DEMAND_PATTERN = re.compile(
    r"\b(?:pay|send|transfer|deposit|remit|wire)\b[^.\n]{0,60}\b"
    r"(?:amount|money|funds?|fee|payment|deposit)\b",
    re.IGNORECASE,
)
MESSAGING_CONTACT = re.compile(r"\b(?:whatsapp|telegram)\b", re.IGNORECASE)
MESSAGING_LINK = re.compile(
    r"wa\.me|api\.whatsapp\.com|whatsapp\.com|t\.me|telegram\.me|telegram\.org",
    re.IGNORECASE,
)
CONTACT_LINK = re.compile(r"contact|support|help|customer[-\s]?care", re.IGNORECASE)
EXECUTABLE_RE = re.compile(r"\.(exe|msi|apk|scr|bat|cmd|dmg|pkg)(?:$|[?#])", re.IGNORECASE)
WALLET_ADDRESS_RE = re.compile(
    r"\b(0x[a-fA-F0-9]{40}|bc1[a-zA-HJ-NP-Z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|T[A-Za-z1-9]{33})\b"
)
SCRIPT_RISK_PATTERNS = {
    "eval": re.compile(r"\beval\s*\("),
    "function_constructor": re.compile(r"new\s+Function\s*\("),
    "atob": re.compile(r"\batob\s*\("),
    "unescape": re.compile(r"\bunescape\s*\("),
    "fromcharcode": re.compile(r"fromCharCode\s*\("),
    "document_write": re.compile(r"document\.write\s*\("),
}


def _action_host(form) -> tuple[str, str]:
    action = form.action or ""
    try:
        parts = urlsplit(action)
        return (parts.hostname or "").lower(), parts.scheme.lower()
    except ValueError:
        return "", ""


def _external_action(ctx: ScanContext, form) -> bool:
    action_host, _ = _action_host(form)
    if not action_host:
        return False
    try:
        return registrable_domain(action_host) != ctx.final_domain
    except Exception:
        return True


def _transactional(ctx: ScanContext) -> bool:
    return ctx.has_password_form or ctx.has_payment_form


def extract(ctx: ScanContext) -> list[Evidence]:
    evidence: list[Evidence] = []
    text = ctx.text
    lowered = text.lower()
    final_scheme = ctx.final_parts.scheme
    official = is_official_domain(ctx.final_host)
    links = trust_links(ctx.page)
    emails = page_emails(ctx.page)
    field_blob = form_field_blob(ctx)
    ctx.notes["has_login_form"] = ctx.has_password_form
    ctx.notes["has_payment_form"] = ctx.has_payment_form
    ctx.notes["official_domain"] = official
    ctx.notes["trust_links"] = links

    ctx.add_source("page", ctx.page_available)

    # ---- Credential handling -------------------------------------------------
    password_form = next((form for form in ctx.forms if form.has_password), None)
    if ctx.has_password_form:
        if final_scheme == "http":
            evidence.append(
                ctx.evidence(
                    dimension=Dimension.SECURITY,
                    code="password_form_http",
                    title="Password form on an unencrypted page",
                    detail=f"The page has {ctx.page.password_field_count or 1} password field(s) and is served over HTTP. "
                    "Anything typed can be read or altered on the network. Do not sign in.",
                    severity=Severity.CRITICAL,
                    risk_points=50.0,
                    confidence=0.95,
                    source="page",
                    provenance={"password_fields": ctx.page.password_field_count, "scheme": final_scheme},
                    tags=["credentials", "transport", "critical"],
                )
            )
        tls = (ctx.intel.tls or {}) if ctx.intel else {}
        if ctx.intel and ctx.intel.tls_ok and final_scheme == "https" and not tls.get("trusted", False):
            evidence.append(
                ctx.evidence(
                    dimension=Dimension.SECURITY,
                    code="password_form_untrusted_tls",
                    title="Password form protected by an untrusted certificate",
                    detail="Credential fields are present while the HTTPS certificate fails validation. Attackers can "
                    "present a self-signed or mismatched certificate to intercept credentials.",
                    severity=Severity.HIGH,
                    risk_points=28.0,
                    confidence=0.9,
                    source="page",
                    provenance={"issuer": truncate(str(tls.get("issuer") or ""), 100)},
                    tags=["credentials", "tls"],
                )
            )
        if password_form:
            action_host, action_scheme = _action_host(password_form)
            external = _external_action(ctx, password_form)
            action_official = is_official_domain(action_host) if action_host else False
            if action_scheme in {"javascript", "data", "file", "blob"}:
                evidence.append(
                    ctx.evidence(
                        dimension=Dimension.SECURITY,
                        code="unsafe_form_action",
                        title="Credential form targets an unsafe URL scheme",
                        detail=f"The login form action uses the '{action_scheme}' scheme rather than a normal HTTPS "
                        "endpoint.",
                        severity=Severity.HIGH,
                        risk_points=30.0,
                        confidence=0.8,
                        source="page",
                        provenance={"scheme": action_scheme},
                        tags=["credentials", "form"],
                    )
                )
            elif external and not is_trusted_checkout(action_host):
                if action_official or (official and action_host.endswith(ctx.final_domain)):
                    risk, severity, confidence = 4.0, Severity.INFO, 0.5
                    title = "Login form posts to another official domain"
                    detail = (
                        f"The form posts to '{action_host}', a domain also listed as official. Large organizations "
                        "often separate sign-in domains; verify the address before typing."
                    )
                elif official:
                    risk, severity, confidence = 30.0, Severity.HIGH, 0.75
                    title = "Login form on an official domain posts to an unverified third party"
                    detail = f"The page is on an official domain but submits credentials to '{action_host}', which is "
                    "not in the local official-domain list."
                else:
                    risk, severity, confidence = 32.0, Severity.HIGH, 0.8
                    title = "Login form submits credentials to a different domain"
                    detail = (
                        f"Credentials entered on '{ctx.final_domain}' are sent to '{action_host}'. Cross-domain "
                        "credential submission is normal only when both domains are clearly controlled by the same organization."
                    )
                evidence.append(
                    ctx.evidence(
                        dimension=Dimension.SECURITY,
                        code="cross_origin_login",
                        title=title,
                        detail=detail,
                        severity=severity,
                        risk_points=risk,
                        confidence=confidence,
                        source="page",
                        provenance={
                            "page_domain": ctx.final_domain,
                            "action_host": action_host,
                            "action_scheme": action_scheme,
                        },
                        tags=["credentials", "form", "exfiltration"],
                    )
                )
            if action_scheme == "http" and final_scheme == "https":
                evidence.append(
                    ctx.evidence(
                        dimension=Dimension.SECURITY,
                        code="https_to_http_form",
                        title="HTTPS page submits a form over HTTP",
                        detail="The login form action uses plain HTTP, which exposes the submitted data in transit.",
                        severity=Severity.HIGH,
                        risk_points=30.0,
                        confidence=0.9,
                        source="page",
                        provenance={"action_host": action_host},
                        tags=["credentials", "transport"],
                    )
                )

    # Seed phrase requests
    field_hit = bool(SEED_FIELD_PATTERN.search(field_blob))
    text_hit = bool(SEED_PATTERN.search(text) or SEED_WORDS_PATTERN.search(text))
    if field_hit or text_hit:
        if official:
            risk, confidence, severity = 6.0, 0.5, Severity.LOW
            title = "Page requests a wallet recovery phrase (verify carefully)"
            detail = "The page asks for a recovery phrase or private key. Even on an official domain, never paste a "
            "wallet recovery phrase into a web page unless you fully trust the service and understand the risk."
        elif field_hit and ctx.has_password_form:
            risk, confidence, severity = 50.0, 0.8, Severity.CRITICAL
            title = "Credential form collects a wallet recovery phrase"
            detail = "The page collects a seed/recovery phrase together with credentials. A legitimate service never "
            "needs your full recovery phrase to verify an account, airdrop, or refund. This is a common wallet-drainer pattern."
        elif field_hit:
            risk, confidence, severity = 38.0, 0.7, Severity.HIGH
            title = "Page asks for a wallet recovery phrase"
            detail = "The page provides fields for a seed/recovery phrase or private key. Whoever obtains it can take all "
            "funds in the wallet. Treat this as high risk unless you are on an official wallet app you explicitly trust."
        elif ctx.has_password_form:
            risk, confidence, severity = 35.0, 0.65, Severity.HIGH
            title = "Login page instructs visitors to enter a wallet phrase"
            detail = "The page combines a credential form with seed-phrase instructions. A legitimate account login does "
            "not require your wallet's full recovery phrase."
        else:
            risk, confidence, severity = 12.0, 0.45, Severity.MEDIUM
            title = "Wallet recovery phrase instructions"
            detail = "The page tells readers to enter a seed/recovery phrase. This may be documentation or a security "
            "warning, but never enter a phrase on a site you do not fully trust."
        evidence.append(
            ctx.evidence(
                dimension=Dimension.SECURITY,
                code="seed_phrase_request",
                title=title,
                detail=detail,
                severity=severity,
                risk_points=risk,
                confidence=confidence,
                source="page",
                provenance={
                    "field_signal": field_hit,
                    "text_signal": text_hit,
                    "snippet": phrase_hit(text, SEED_PATTERN) or phrase_hit(text, SEED_WORDS_PATTERN),
                },
                tags=["wallet", "credentials", "critical"] if risk >= 45 else ["wallet", "credentials"],
            )
        )

    # Payment handling
    payment_form = next((form for form in ctx.forms if form.has_card or form.has_cvv), None)
    if ctx.has_payment_form:
        if final_scheme == "http":
            evidence.append(
                ctx.evidence(
                    dimension=Dimension.SECURITY,
                    code="card_form_http",
                    title="Card payment fields on an unencrypted page",
                    detail="Card or CVV fields are present while the page is served over HTTP. Do not enter payment details.",
                    severity=Severity.CRITICAL,
                    risk_points=45.0,
                    confidence=0.95,
                    source="page",
                    provenance={"scheme": final_scheme},
                    tags=["payment", "transport", "critical"],
                )
            )
        if payment_form:
            action_host, action_scheme = _action_host(payment_form)
            external = _external_action(ctx, payment_form)
            if external and is_trusted_checkout(action_host):
                evidence.append(
                    ctx.evidence(
                        dimension=Dimension.SECURITY,
                        code="known_payment_processor",
                        title="Payment form uses a recognized processor",
                        detail=f"Checkout submits to '{action_host}', a known payment processor. This confirms a payment "
                        "path exists, not that the merchant is honest.",
                        severity=Severity.INFO,
                        risk_points=0.0,
                        trust_points=2.0,
                        confidence=0.75,
                        source="page",
                        provenance={"processor_host": action_host},
                        tags=["payment", "weak_trust"],
                    )
                )
            elif external:
                evidence.append(
                    ctx.evidence(
                        dimension=Dimension.SECURITY,
                        code="unknown_payment_processor",
                        title="Payment form posts to an unrecognized external domain",
                        detail=f"Card details submitted on '{ctx.final_domain}' are sent to '{action_host}', which is not "
                        "in the local list of known payment processors. Verify the merchant before paying.",
                        severity=Severity.MEDIUM,
                        risk_points=16.0,
                        confidence=0.6,
                        source="page",
                        provenance={"page_domain": ctx.final_domain, "action_host": action_host},
                        tags=["payment", "form"],
                    )
                )
            if action_scheme == "http" and final_scheme == "https":
                evidence.append(
                    ctx.evidence(
                        dimension=Dimension.SECURITY,
                        code="card_form_http_action",
                        title="Payment form submits over HTTP",
                        detail="The payment form action uses plain HTTP. Card data would be transmitted without encryption.",
                        severity=Severity.CRITICAL,
                        risk_points=45.0,
                        confidence=0.9,
                        source="page",
                        provenance={"action_host": action_host},
                        tags=["payment", "transport", "critical"],
                    )
                )
        if not any(form.has_card and form.has_cvv for form in ctx.forms):
            ctx.add_missing("No CVV field was observed on the payment form")

    # Cross-origin collection of contact data
    for form in ctx.forms:
        if form.has_password or form.has_card or form.has_cvv:
            continue
        if not form.sensitive:
            continue
        action_host, _ = _action_host(form)
        if not _external_action(ctx, form) or is_trusted_checkout(action_host):
            continue
        evidence.append(
            ctx.evidence(
                dimension=Dimension.PRIVACY,
                code="third_party_lead_form",
                title="Contact details are submitted to a third-party service",
                detail=f"A form collects contact information and sends it to '{action_host}'. This may be a marketing or "
                "form-hosting vendor; check the privacy policy before sharing personal data.",
                severity=Severity.LOW,
                risk_points=7.0,
                confidence=0.55,
                source="page",
                provenance={"action_host": action_host, "fields": [f.name for f in form.fields if f.name][:8]},
                tags=["privacy", "form"],
            )
        )
        break

    if has_sensitive_fields(ctx):
        evidence.append(
            ctx.evidence(
                dimension=Dimension.PRIVACY,
                code="sensitive_identifiers_requested",
                title="Sensitive identity fields are collected",
                detail="The page asks for identifiers such as a national ID, bank account, health, biometric, or tax "
                "number. Confirm the organization, legal basis, and policy before submitting. Values are never stored by TrustLens.",
                severity=Severity.MEDIUM,
                risk_points=11.0,
                confidence=0.7,
                source="page",
                provenance={"field_categories": truncate(field_blob, 200)},
                tags=["privacy", "pii"],
            )
        )
    if form_field_blob(ctx) and final_scheme == "http" and (has_ordinary_pii_fields(ctx) or has_sensitive_fields(ctx)):
        evidence.append(
            ctx.evidence(
                dimension=Dimension.PRIVACY,
                code="pii_over_http",
                title="Personal data form on an unencrypted connection",
                detail="The page collects personal information over HTTP. Submitted details can be read or altered in transit.",
                severity=Severity.HIGH,
                risk_points=25.0,
                confidence=0.9,
                source="page",
                provenance={"scheme": final_scheme},
                tags=["privacy", "transport"],
            )
        )

    # ---- Social-engineering content ----------------------------------------
    if ACCOUNT_THREAT_PATTERN.search(text):
        risk = 10.0 if official else (24.0 if ctx.has_password_form else 6.0)
        evidence.append(
            ctx.evidence(
                dimension=Dimension.SECURITY,
                code="account_threat_language",
                title="Account-suspension or verification pressure",
                detail="The page uses account suspension, unusual activity, or identity-verification pressure. This is "
                "common in legitimate security notices and also a core phishing script."
                + (" It is paired with a password form." if ctx.has_password_form else ""),
                severity=Severity.HIGH if risk >= 20 else Severity.MEDIUM if risk >= 8 else Severity.LOW,
                risk_points=risk,
                confidence=0.6 if official else 0.7,
                source="page",
                provenance={"snippet": phrase_hit(text, ACCOUNT_THREAT_PATTERN)},
                tags=["social_engineering", "urgency"],
            )
        )

    if not official and TECH_SUPPORT_LURE.search(text):
        evidence.append(
            ctx.evidence(
                dimension=Dimension.SECURITY,
                code="tech_support_lure",
                title="Tech-support scam language",
                detail="The page combines a technology brand with warnings about infection or demands to call support. "
                "Major vendors do not cold-contact users through web pop-ups.",
                severity=Severity.HIGH,
                risk_points=28.0,
                confidence=0.7,
                source="page",
                provenance={"snippet": phrase_hit(text, TECH_SUPPORT_LURE)},
                tags=["scam", "social_engineering"],
            )
        )
    if REMOTE_ACCESS_PATTERN.search(text) and (SCAM_CONTEXT.search(text) or ctx.has_password_form):
        evidence.append(
            ctx.evidence(
                dimension=Dimension.SECURITY,
                code="remote_access_request",
                title="Remote-access tool combined with support or refund pressure",
                detail="The page mentions remote-control software in a support, refund, or account context. Scammers "
                "use this to take control of a victim's computer.",
                severity=Severity.HIGH,
                risk_points=28.0,
                confidence=0.65,
                source="page",
                provenance={"snippet": phrase_hit(text, REMOTE_ACCESS_PATTERN)},
                tags=["scam", "remote_access"],
            )
        )
    gift_hit = GIFT_CARD_PATTERN.search(text)
    if gift_hit:
        demand_hit = GIFT_DEMAND_PATTERN.search(text)
        risky = bool(demand_hit and (SCAM_CONTEXT.search(text) or not ctx.has_payment_form))
        risk = 24.0 if risky else 3.0
        evidence.append(
            ctx.evidence(
                dimension=Dimension.SECURITY,
                code="gift_card_payment",
                title="Gift card requested as a payment method"
                if risky
                else "Gift card product language",
                detail=(
                    "The page asks for payment using gift-card codes. Government agencies, utilities, and legitimate "
                    "support desks do not demand gift cards; this is a common scam payment channel."
                    if risky
                    else "Gift cards are mentioned, which is normal for retail sites. It becomes a red flag only when "
                    "someone demands gift-card codes as payment for support, fines, or refunds."
                ),
                severity=Severity.HIGH if risky else Severity.INFO,
                risk_points=risk,
                confidence=0.65 if risky else 0.4,
                source="page",
                provenance={"snippet": phrase_hit(text, GIFT_CARD_PATTERN)},
                tags=["payment", "scam"],
            )
        )
    if not official and CRYPTO_LURE.search(text):
        evidence.append(
            ctx.evidence(
                dimension=Dimension.SECURITY,
                code="crypto_giveaway_lure",
                title="Crypto giveaway or wallet-connection lure",
                detail="The page uses giveaway, doubling, or airdrop language and asks users to connect or validate a wallet. "
                "Unsolicited crypto giveaways are overwhelmingly fraudulent.",
                severity=Severity.HIGH,
                risk_points=24.0,
                confidence=0.65,
                source="page",
                provenance={"snippet": phrase_hit(text, CRYPTO_LURE)},
                tags=["crypto", "scam"],
            )
        )
    wallets = WALLET_ADDRESS_RE.findall(text)
    if wallets and not ctx.has_payment_form and not official and any(
        word in lowered for word in ("pay", "send", "donate", "fee", "deposit", "payment")
    ):
        evidence.append(
            ctx.evidence(
                dimension=Dimension.SECURITY,
                code="direct_crypto_payment",
                title="Direct cryptocurrency wallet payment",
                detail="The page asks for payment to a raw crypto address without a recognized checkout flow. Payments "
                "are irreversible and offer little recourse if the recipient is fraudulent.",
                severity=Severity.MEDIUM,
                risk_points=12.0,
                confidence=0.55,
                source="page",
                provenance={"wallet_addresses_seen": len(wallets)},
                tags=["crypto", "payment"],
            )
        )
    if REMOTE_COMMAND_LURE.search(text) and not official and (SCAM_CONTEXT.search(text) or ctx.has_password_form):
        evidence.append(
            ctx.evidence(
                dimension=Dimension.SECURITY,
                code="manual_command_lure",
                title="Instructions to run a command or paste code",
                detail="The page tells visitors to open a system dialog and run or paste code. This is a malware-delivery "
                "pattern; legitimate support never asks for this.",
                severity=Severity.CRITICAL,
                risk_points=45.0,
                confidence=0.7,
                source="page",
                provenance={"snippet": phrase_hit(text, REMOTE_COMMAND_LURE)},
                tags=["malware", "social_engineering"],
            )
        )

    if not official and INVESTMENT_CONTEXT.search(text) and GUARANTEED_RETURN_LURE.search(text):
        evidence.append(
            ctx.evidence(
                dimension=Dimension.SECURITY,
                code="guaranteed_return_lure",
                title="Guaranteed or risk-free investment returns",
                detail="The page promises guaranteed, fixed, or risk-free investment returns. Markets do not offer "
                "guaranteed profits; this wording is common in investment fraud. Verify the seller's registration "
                "through an independent regulator before sending money.",
                severity=Severity.HIGH,
                risk_points=20.0,
                confidence=0.6,
                source="page",
                provenance={"snippet": phrase_hit(text, GUARANTEED_RETURN_LURE)},
                tags=["scam", "investment", "financial_fraud"],
            )
        )

    advance_fee = ADVANCE_FEE_DEMAND.search(text)
    if not official and advance_fee and ADVANCE_FEE_CONTEXT.search(text):
        evidence.append(
            ctx.evidence(
                dimension=Dimension.SECURITY,
                code="advance_fee_lure",
                title="Upfront fee for a promised job, prize, refund, or delivery",
                detail="The page asks for an upfront processing, registration, security, or delivery fee in a context "
                "where legitimate organisations normally do not require payment to release a job, prize, refund, or "
                "parcel. Verify the request through an independent channel.",
                severity=Severity.HIGH,
                risk_points=18.0,
                confidence=0.6,
                source="page",
                provenance={"snippet": phrase_hit(text, ADVANCE_FEE_DEMAND)},
                tags=["scam", "advance_fee", "payment"],
            )
        )

    upi_ids = UPI_ID_PATTERN.findall(text)
    upi_instruction = UPI_PAYMENT_INSTRUCTION.search(text)
    if (
        not official
        and not ctx.has_payment_form
        and (
            upi_ids
            or (
                upi_instruction
                and (SCAM_CONTEXT.search(text) or advance_fee)
            )
        )
    ):
        evidence.append(
            ctx.evidence(
                dimension=Dimension.SECURITY,
                code="direct_upi_payment",
                title="Payment directed to a raw UPI address or QR",
                detail="The page asks for payment to a UPI address or QR code without a hosted checkout. Verify the "
                "payee name inside your own UPI app; transfers to a personal handle offer little recourse if the "
                "recipient is fraudulent.",
                severity=Severity.MEDIUM,
                risk_points=14.0 if upi_ids else 10.0,
                confidence=0.6 if upi_ids else 0.45,
                source="page",
                provenance={
                    "upi_ids_seen": len(upi_ids),
                    "instruction_without_id": bool(upi_instruction) and not upi_ids,
                },
                tags=["payment", "upi", "scam"],
            )
        )

    bank_transfer = BANK_TRANSFER_PATTERN.search(text)
    if (
        not official
        and not ctx.has_payment_form
        and bank_transfer
        and BANK_DEMAND_PATTERN.search(text)
        and (SCAM_CONTEXT.search(text) or advance_fee)
    ):
        evidence.append(
            ctx.evidence(
                dimension=Dimension.SECURITY,
                code="direct_bank_transfer",
                title="Payment requested by direct bank transfer",
                detail="The page asks for a bank transfer in a context that also mentions a prize, refund, job, "
                "delivery, penalty, or other pressure. Direct transfers are difficult to reverse; confirm the "
                "beneficiary through an independent channel before paying.",
                severity=Severity.MEDIUM,
                risk_points=14.0,
                confidence=0.55,
                source="page",
                provenance={"matched": truncate(bank_transfer.group(0), 60)},
                tags=["payment", "bank_transfer", "scam"],
            )
        )

    if not official and MESSAGING_CONTACT.search(text):
        messaging_links = [
            link
            for link in ctx.page.links
            if MESSAGING_LINK.search(
                f"{link.get('href', '')} {link.get('text', '')}"
            )
        ]
        non_messaging_contact = any(
            CONTACT_LINK.search(haystack)
            and not MESSAGING_LINK.search(haystack)
            for link in ctx.page.links
            for haystack in (f"{link.get('href', '')} {link.get('text', '')}",)
        )
        direct_channel = bool(emails) or bool(PHONE_RE.search(text)) or any(
            str(link.get("href", "")).lower().startswith("tel:")
            for link in ctx.page.links
        )
        if (messaging_links or MESSAGING_CONTACT.search(text)) and not non_messaging_contact and not direct_channel:
            risk = 8.0 if (ctx.has_payment_form or ctx.has_password_form) else 4.0
            evidence.append(
                ctx.evidence(
                    dimension=Dimension.IDENTITY,
                    code="messaging_only_contact",
                    title="Support is routed only through WhatsApp or Telegram",
                    detail="The page directs contact to a personal messaging app and shows no contact page, email, or "
                    "phone number. Small businesses sometimes do this legitimately, but it reduces accountability; treat "
                    "it as a weak signal and verify the business independently.",
                    severity=Severity.MEDIUM if risk >= 8 else Severity.LOW,
                    risk_points=risk,
                    confidence=0.5,
                    source="page",
                    provenance={
                        "messaging_links": len(messaging_links),
                        "email_visible": bool(emails),
                        "phone_visible": bool(PHONE_RE.search(text)),
                    },
                    tags=["contact", "off_platform", "scam"],
                )
            )

    executables = [
        link
        for link in ctx.page.links
        if EXECUTABLE_RE.search(str(link.get("href", "")))
    ]
    support_pressure = bool(
        TECH_SUPPORT_LURE.search(text)
        or REMOTE_ACCESS_PATTERN.search(text)
        or REMOTE_COMMAND_LURE.search(text)
    )
    if executables and (
        support_pressure or (ctx.has_password_form and SCAM_CONTEXT.search(text))
    ):
        evidence.append(
            ctx.evidence(
                dimension=Dimension.SECURITY,
                code="executable_download",
                title="Executable download offered alongside support pressure",
                detail="Links to installable binaries appear together with remote-support, account, or "
                "troubleshooting pressure. Verify the publisher and file signature before running anything.",
                severity=Severity.MEDIUM,
                risk_points=14.0,
                confidence=0.55,
                source="page",
                provenance={
                    "download_hosts": sorted(
                        {
                            (urlsplit(str(link.get("href", ""))).hostname or "")
                            for link in executables[:6]
                        }
                    )[:5],
                    "support_pressure": support_pressure,
                },
                tags=["download", "malware"],
            )
        )

    # ---- Script / framing tricks ------------------------------------------
    inline = "\n".join(ctx.page.inline_scripts)
    obfuscation_hits = {name: len(pattern.findall(inline)) for name, pattern in SCRIPT_RISK_PATTERNS.items()}
    strong_hits = obfuscation_hits.get("eval", 0) + obfuscation_hits.get("function_constructor", 0) + obfuscation_hits.get("atob", 0)
    if strong_hits >= 3 or (obfuscation_hits.get("atob", 0) >= 2 and obfuscation_hits.get("fromcharcode", 0) >= 1):
        evidence.append(
            ctx.evidence(
                dimension=Dimension.SECURITY,
                code="obfuscated_javascript",
                title="Obfuscated or dynamically decoded JavaScript",
                detail="The page uses several dynamic-code constructs (for example eval, Function, atob, or fromCharCode). "
                "Build tools sometimes produce these, but they are also used to hide malicious behavior.",
                severity=Severity.LOW,
                risk_points=9.0,
                confidence=0.5,
                source="page",
                provenance={"construct_counts": {key: value for key, value in obfuscation_hits.items() if value}},
                tags=["javascript", "obfuscation"],
            )
        )

    hidden_external_iframes = [
        frame
        for frame in ctx.page.iframes
        if frame.get("hidden")
        or (frame.get("width") in (0, "0") and frame.get("height") in (0, "0"))
    ]
    if hidden_external_iframes:
        evidence.append(
            ctx.evidence(
                dimension=Dimension.SECURITY,
                code="hidden_iframe",
                title="Hidden iframe embedded in the page",
                detail="One or more iframes are hidden from view. Hidden frames can load third-party content, tracking, "
                "or exploit kits without being noticeable.",
                severity=Severity.LOW,
                risk_points=6.0,
                confidence=0.55,
                source="page",
                provenance={
                    "iframe_hosts": sorted(
                        {
                            (urlsplit(str(frame.get("src", ""))).hostname or "")
                            for frame in hidden_external_iframes[:5]
                        }
                    )
                },
                tags=["iframe", "obfuscation"],
            )
        )

    refresh = ctx.page.meta.get("refresh", "")
    if refresh:
        refresh_url = refresh.split("url=", 1)[1].strip(" \"'") if "url=" in refresh.lower() else ""
        if refresh_url:
            try:
                target = urlsplit(refresh_url)
                target_host = (target.hostname or "").lower()
                external = target_host and registrable_domain(target_host) != ctx.final_domain
            except ValueError:
                external = False
            if external:
                evidence.append(
                    ctx.evidence(
                        dimension=Dimension.SECURITY,
                        code="meta_refresh_redirect",
                        title="Automatic redirect to another domain",
                        detail="The page uses a meta refresh to send visitors to a different domain, which hides the final "
                        "destination and is used to evade link scanning.",
                        severity=Severity.MEDIUM,
                        risk_points=8.0,
                        confidence=0.65,
                        source="page",
                        provenance={"target_host": truncate(target_host, 100)},
                        tags=["redirect"],
                    )
                )

    # ---- Identity and transparency ----------------------------------------
    meta_text = " ".join(
        filter(
            None,
            [
                ctx.page.meta.get("og:site_name", ""),
                ctx.page.meta.get("application-name", ""),
                ctx.page.meta.get("author", ""),
            ],
        )
    )
    title_heading_text = " ".join([ctx.page.title, *ctx.page.headings[:6], meta_text])
    claimed = brands_in_text(title_heading_text, limit=3)
    if not claimed and ctx.page.visible_text:
        claimed = brands_in_text(ctx.page.visible_text[:400], limit=2)
    if claimed:
        claimed_brand = claimed[0]
        ctx.notes["claimed_brand"] = claimed_brand.name
        official_for_brand = any(
            ctx.final_host == domain or ctx.final_host.endswith("." + domain)
            for domain in claimed_brand.domains
        )
        if not official_for_brand and not official:
            strong_claim = claimed_brand.name.lower() in ctx.page.title.lower() or claimed_brand.name.lower() in meta_text.lower()
            if ctx.has_password_form or ctx.has_payment_form or strong_claim:
                risk = 34.0 if _transactional(ctx) else 10.0
                evidence.append(
                    ctx.evidence(
                        dimension=Dimension.IDENTITY,
                        code="claimed_brand_mismatch",
                        title="Page claims a brand on a domain outside the brand's official list",
                        detail=(
                            f"The page presents itself as {claimed_brand.name} ('{truncate(ctx.page.title, 120)}') but runs on "
                            f"'{ctx.final_domain}'. Locally known official domains for {claimed_brand.name}: "
                            f"{', '.join(claimed_brand.domains[:4])}. A brand word on a page is not proof of affiliation."
                        ),
                        severity=Severity.HIGH if risk >= 20 else Severity.MEDIUM,
                        risk_points=risk,
                        confidence=0.7,
                        source="page",
                        provenance={
                            "claimed_brand": claimed_brand.name,
                            "official_domains": list(claimed_brand.domains[:4]),
                            "transactional": _transactional(ctx),
                        },
                        tags=["impersonation", "brand"],
                    )
                )

    if _transactional(ctx):
        missing_links = [name for name in ("privacy", "terms", "contact") if not links.get(name)]
        if not links.get("privacy") and not links.get("terms") and ctx.has_password_form:
            evidence.append(
                ctx.evidence(
                    dimension=Dimension.IDENTITY,
                    code="login_without_transparency",
                    title="Login page lacks privacy, terms, or contact links",
                    detail="The page requests credentials but does not link to a privacy policy, terms, or support contact. "
                    "Established services normally make ownership and data handling easy to find.",
                    severity=Severity.MEDIUM,
                    risk_points=9.0 if links.get("contact") else 12.0,
                    confidence=0.55,
                    source="page",
                    provenance={"missing": missing_links},
                    tags=["transparency", "identity"],
                )
            )
        elif ctx.has_payment_form and len(missing_links) >= 3:
            evidence.append(
                ctx.evidence(
                    dimension=Dimension.IDENTITY,
                    code="checkout_without_policies",
                    title="Checkout page lacks policies and contact details",
                    detail="A page collecting payment is missing privacy, terms, and contact links. Reputable merchants "
                    "publish refund, contact, and data-handling information before payment.",
                    severity=Severity.MEDIUM,
                    risk_points=8.0,
                    confidence=0.55,
                    source="page",
                    provenance={"missing": missing_links},
                    tags=["transparency", "identity"],
                )
            )
        if len([name for name, present in links.items() if present and name in {"privacy", "terms", "contact", "about"}]) >= 3:
            evidence.append(
                ctx.evidence(
                    dimension=Dimension.IDENTITY,
                    code="transparency_links",
                    title="Privacy, terms, contact, and about links are present",
                    detail="Ownership and policy links are easy to find. This is a weak positive signal; the content can "
                    "still be inaccurate or copied.",
                    severity=Severity.INFO,
                    risk_points=0.0,
                    trust_points=3.0,
                    confidence=0.6,
                    source="page",
                    provenance={"links": [name for name, present in links.items() if present]},
                    tags=["transparency", "weak_trust"],
                )
            )
        if emails:
            domains = {email.split("@", 1)[1].lower() for email in emails if "@" in email}
            if domains and all(domain in free_email_domains() for domain in domains) and not links.get("contact"):
                evidence.append(
                    ctx.evidence(
                        dimension=Dimension.IDENTITY,
                        code="free_email_contact",
                        title="Only free-email contact details are shown",
                        detail="The only visible email contact uses a free consumer email provider and no contact page is "
                        "linked. Small businesses do this legitimately, but it offers little accountability.",
                        severity=Severity.LOW,
                        risk_points=3.0,
                        confidence=0.45,
                        source="page",
                        provenance={"email_domains": sorted(domains)[:4]},
                        tags=["contact", "weak_signal"],
                    )
                )
    elif ctx.page_available and not emails and not links.get("contact"):
        ctx.add_missing("No contact information was found on the landing page")

    if ctx.page_available and not ctx.page.inline_scripts and ctx.page.engine == "http":
        ctx.add_missing("JavaScript was not executed; interactive or client-rendered content is not visible")

    if not has_credential_fields(ctx) and ctx.page.password_field_count:
        ctx.add_missing("Password fields exist but no enclosing form could be inspected")

    return evidence
