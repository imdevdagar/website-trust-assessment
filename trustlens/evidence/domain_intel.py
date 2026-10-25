"""Domain-level evidence from RDAP, DNS, and a direct TLS handshake."""

from __future__ import annotations

import asyncio
import json
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import dns.asyncresolver
import dns.resolver
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from ..crawler import decode_body, fetch_bytes
from ..schemas import Dimension, Evidence, Severity
from ..security import resolve_public_sync
from .. import storage
from .base import DomainIntel, ScanContext, truncate

RDAP_TTL = 7 * 24 * 3600
RDAP_ERROR_TTL = 6 * 3600
TLS_TTL = 3600


def _cache_get(key: str, ttl: int) -> Any | None:
    try:
        return storage.cache_get(key, ttl)
    except Exception:
        return None


def _cache_set(key: str, value: Any) -> None:
    try:
        storage.cache_set(key, value)
    except Exception:
        pass


async def enrich(ctx: ScanContext) -> list[Evidence]:
    domain = ctx.final_domain
    host = ctx.final_host
    intel = DomainIntel(domain=domain)
    ctx.intel = intel

    rdap_task = asyncio.create_task(_fetch_rdap(domain))
    dns_task = asyncio.create_task(_probe_dns(domain))
    tls_task = asyncio.create_task(_probe_tls(host))
    results = await asyncio.gather(rdap_task, dns_task, tls_task, return_exceptions=True)

    rdap_result, dns_result, tls_result = results
    if isinstance(rdap_result, Exception):
        intel.rdap = {"ok": False, "error": f"rdap_{type(rdap_result).__name__}"}
    else:
        intel.rdap = rdap_result or {"ok": False}
    intel.rdap_ok = bool(intel.rdap.get("ok"))

    if isinstance(dns_result, Exception):
        intel.dns = {"ok": False, "error": f"dns_{type(dns_result).__name__}"}
    else:
        intel.dns = dns_result or {"ok": False}
    intel.dns_ok = bool(intel.dns.get("ok"))

    if isinstance(tls_result, Exception):
        intel.tls = {"ok": False, "error": f"tls_{type(tls_result).__name__}"}
    else:
        intel.tls = tls_result
    intel.tls_ok = bool(intel.tls and intel.tls.get("ok"))

    ctx.add_source("rdap", intel.rdap_ok)
    ctx.add_source("dns", intel.dns_ok)
    ctx.add_source("tls", intel.tls_ok)
    if not intel.rdap_ok:
        ctx.add_missing("Domain registration data (RDAP) could not be retrieved")
    if not intel.dns_ok:
        ctx.add_missing("DNS records could not be retrieved")
    if not intel.tls_ok and ctx.final_parts.scheme == "https":
        ctx.add_missing("TLS certificate could not be inspected")

    evidence: list[Evidence] = []
    evidence.extend(_age_evidence(ctx, intel))
    evidence.extend(_tls_evidence(ctx, intel))
    evidence.extend(_dns_evidence(ctx, intel))
    evidence.extend(_status_evidence(ctx, intel))

    ctx.notes["domain_intel"] = {
        "domain": domain,
        "age_days": intel.age_days,
        "registrar": intel.rdap.get("registrar"),
        "created_at": intel.rdap.get("created_at"),
        "expires_at": intel.rdap.get("expires_at"),
        "nameservers": intel.dns.get("ns", [])[:5],
        "has_mx": intel.dns.get("has_mx", False),
        "spf": intel.dns.get("spf", {}).get("present", False),
        "dmarc": intel.dns.get("dmarc", {}).get("present", False),
        "tls_issuer": (intel.tls or {}).get("issuer"),
        "tls_trusted": (intel.tls or {}).get("trusted", False),
        "tls_days_remaining": (intel.tls or {}).get("days_remaining"),
        "tls_fingerprint": (intel.tls or {}).get("fingerprint_sha256"),
    }
    return evidence


def _age_evidence(ctx: ScanContext, intel: DomainIntel) -> list[Evidence]:
    age = intel.age_days
    if age is None:
        return []
    transactional = ctx.has_password_form or ctx.has_payment_form
    registrar = intel.rdap.get("registrar") or "unknown registrar"
    created = intel.rdap.get("created_at") or "unknown date"
    if age <= 30:
        risk = 26.0 if transactional else 14.0
        severity = Severity.HIGH if transactional else Severity.MEDIUM
        title = (
            "Very new domain requesting credentials or payment"
            if transactional
            else "Very recently registered domain"
        )
        detail = (
            f"The domain was registered {age} day(s) ago (created {created}, registrar: {registrar}). "
            + (
                "New domains that collect credentials or payment are a strong phishing pattern."
                if transactional
                else "Recent registration is common for new businesses, but also for disposable fraud infrastructure."
            )
        )
        confidence = 0.8 if transactional else 0.65
    elif age <= 90:
        risk = 13.0 if transactional else 7.0
        severity = Severity.MEDIUM if transactional else Severity.LOW
        title = "Recently registered domain"
        detail = f"The domain is {age} days old (created {created}, registrar: {registrar})."
        confidence = 0.65
    elif age <= 365:
        risk = 5.0 if transactional else 2.0
        severity = Severity.LOW
        title = "Domain is less than one year old"
        detail = f"The domain is {age} days old (created {created}, registrar: {registrar})."
        confidence = 0.5
    else:
        years = round(age / 365, 1)
        return [
            ctx.evidence(
                dimension=Dimension.IDENTITY,
                code="established_domain",
                title="Domain has an established registration history",
                detail=f"The domain is about {years} years old (created {created}, registrar: {registrar}). "
                "Age is a weak positive signal: aged domains can be compromised or reused.",
                severity=Severity.INFO,
                risk_points=0.0,
                trust_points=2.0,
                confidence=0.7,
                source="rdap",
                provenance={"age_days": age, "created_at": created, "registrar": registrar},
                tags=["domain_age", "weak_trust"],
            )
        ]
    return [
        ctx.evidence(
            dimension=Dimension.IDENTITY,
            code="domain_age",
            title=title,
            detail=detail,
            severity=severity,
            risk_points=risk,
            confidence=confidence,
            source="rdap",
            provenance={
                "age_days": age,
                "created_at": created,
                "registrar": registrar,
                "transactional": transactional,
            },
            tags=["domain_age", "identity"],
        )
    ]


def _status_evidence(ctx: ScanContext, intel: DomainIntel) -> list[Evidence]:
    statuses = {str(item).lower() for item in (intel.rdap.get("statuses") or [])}
    concerning = sorted(
        status
        for status in statuses
        if "hold" in status or "pendingdelete" in status or "redemption" in status
    )
    if not concerning:
        return []
    return [
        ctx.evidence(
            dimension=Dimension.IDENTITY,
            code="domain_status_hold",
            title="Registry reports a restrictive domain status",
            detail=f"RDAP status includes: {', '.join(concerning)}. The domain may be suspended or pending deletion.",
            severity=Severity.MEDIUM,
            risk_points=12.0,
            confidence=0.75,
            source="rdap",
            provenance={"statuses": sorted(statuses)[:10]},
            tags=["domain_status"],
        )
    ]


def _dns_evidence(ctx: ScanContext, intel: DomainIntel) -> list[Evidence]:
    if not intel.dns_ok:
        return []
    evidence: list[Evidence] = []
    has_mx = bool(intel.dns.get("has_mx"))
    spf = bool(intel.dns.get("spf", {}).get("present"))
    dmarc = bool(intel.dns.get("dmarc", {}).get("present"))
    if has_mx and not (spf and dmarc):
        missing = []
        if not spf:
            missing.append("SPF")
        if not dmarc:
            missing.append("DMARC")
        evidence.append(
            ctx.evidence(
                dimension=Dimension.SECURITY,
                code="email_auth_missing",
                title="Email authentication records are incomplete",
                detail=f"The domain accepts mail but lacks {', '.join(missing)} records. This makes brand-email "
                "spoofing easier. It is an infrastructure hygiene signal, not evidence that this website is fraudulent.",
                severity=Severity.LOW,
                risk_points=3.0,
                confidence=0.5,
                source="dns",
                provenance={"has_mx": has_mx, "spf": spf, "dmarc": dmarc},
                tags=["email", "hygiene", "weak_signal"],
            )
        )
    return evidence


def _tls_evidence(ctx: ScanContext, intel: DomainIntel) -> list[Evidence]:
    tls = intel.tls
    if not tls or not tls.get("ok"):
        return []
    if ctx.final_parts.scheme != "https":
        return []
    evidence: list[Evidence] = []
    trusted = bool(tls.get("trusted"))
    hostname_match = bool(tls.get("hostname_match"))
    expired = bool(tls.get("expired"))
    self_signed = bool(tls.get("self_signed"))
    days = tls.get("days_remaining")
    issuer = truncate(str(tls.get("issuer") or "unknown issuer"), 120)
    subject = truncate(str(tls.get("subject") or ""), 120)
    reason = truncate(str(tls.get("verify_error") or ""), 200)

    if trusted and hostname_match and not expired:
        evidence.append(
            ctx.evidence(
                dimension=Dimension.SECURITY,
                code="tls_certificate_valid",
                title="TLS certificate is valid (weak positive signal)",
                detail=f"The HTTPS certificate chains to a public CA and matches this hostname. Issuer: {issuer}. "
                f"Expires in {days} days. A certificate only proves control of the connection; it does not prove "
                "the operator is honest, so it is not counted as trust.",
                severity=Severity.INFO,
                risk_points=0.0,
                trust_points=0.0,
                confidence=0.95,
                source="tls",
                provenance={
                    "issuer": issuer,
                    "subject": subject,
                    "days_remaining": days,
                    "fingerprint_sha256": tls.get("fingerprint_sha256"),
                },
                tags=["tls", "padlock_paradox", "weak_signal"],
            )
        )
        if isinstance(days, (int, float)) and days <= 14:
            evidence.append(
                ctx.evidence(
                    dimension=Dimension.SECURITY,
                    code="tls_certificate_expiring",
                    title="TLS certificate expires soon",
                    detail=f"The certificate expires in {days} days. Short-lived certificates are common with modern "
                    "automation, but an expiry during your visit can cause warnings or outages.",
                    severity=Severity.LOW,
                    risk_points=3.0,
                    confidence=0.7,
                    source="tls",
                    provenance={"days_remaining": days, "issuer": issuer},
                    tags=["tls", "hygiene"],
                )
            )
        return evidence

    risk = 30.0
    if self_signed:
        risk = 35.0
    elif expired:
        risk = 25.0
    if not hostname_match:
        risk = max(risk, 35.0)
    issues = []
    if expired:
        issues.append("certificate is expired")
    if self_signed:
        issues.append("certificate is self-signed")
    if not hostname_match:
        issues.append("certificate does not match this hostname")
    if not issues:
        issues.append("certificate chain is not trusted by the operating system")
    detail = "The HTTPS certificate has problems: " + "; ".join(issues) + "."
    if reason:
        detail += f" Verifier: {reason}"
    evidence.append(
        ctx.evidence(
            dimension=Dimension.SECURITY,
            code="tls_certificate_invalid",
            title="Invalid HTTPS certificate",
            detail=detail,
            severity=Severity.HIGH,
            risk_points=risk,
            confidence=0.95,
            source="tls",
            provenance={
                "issuer": issuer,
                "subject": subject,
                "expired": expired,
                "self_signed": self_signed,
                "hostname_match": hostname_match,
                "verify_error": reason,
                "fingerprint_sha256": tls.get("fingerprint_sha256"),
            },
            tags=["tls", "encryption"],
        )
    )
    return evidence


async def _fetch_rdap(domain: str) -> dict[str, Any]:
    if not domain or "." not in domain:
        return {"ok": False, "error": "invalid_domain"}
    success_key = f"rdap:{domain}"
    error_key = f"rdap_err:{domain}"
    cached = _cache_get(success_key, RDAP_TTL)
    if cached:
        return cached
    cached_error = _cache_get(error_key, RDAP_ERROR_TTL)
    if cached_error:
        return cached_error
    result = await fetch_bytes(
        f"https://rdap.org/domain/{quote(domain, safe='')}",
        max_bytes=700_000,
        timeout=8.0,
        accept="application/rdap+json,application/json",
    )
    if result.error or result.status != 200:
        payload = {
            "ok": False,
            "error": truncate(result.error or f"http_{result.status}", 120),
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        _cache_set(error_key, payload)
        return payload
    try:
        raw = json.loads(decode_body(result.content, result.content_type))
    except (json.JSONDecodeError, ValueError):
        payload = {"ok": False, "error": "invalid_rdap_json"}
        _cache_set(error_key, payload)
        return payload

    events = {}
    for event in raw.get("events", []) or []:
        action = str(event.get("eventAction", "")).lower()
        date = event.get("eventDate")
        if action and date and action not in events:
            events[action] = str(date)
    created = events.get("registration") or events.get("registered") or events.get("created")
    expires = events.get("expiration") or events.get("expiry")
    updated = events.get("last changed") or events.get("last update")
    now = datetime.now(timezone.utc)
    age_days = None
    expires_days = None
    if created:
        parsed = _parse_datetime(created)
        if parsed:
            age_days = max(0, int((now - parsed).total_seconds() // 86400))
    if expires:
        parsed = _parse_datetime(expires)
        if parsed:
            expires_days = int((parsed - now).total_seconds() // 86400)

    statuses = [str(item) for item in raw.get("status", []) if item]
    nameservers = []
    for item in raw.get("nameservers", []) or []:
        name = item.get("ldhName") or item.get("unicodeName")
        if name:
            nameservers.append(str(name).lower().rstrip("."))
    registrar = _find_registrar(raw.get("entities", []))

    payload = {
        "ok": True,
        "domain": domain,
        "created_at": created,
        "expires_at": expires,
        "updated_at": updated,
        "age_days": age_days,
        "expires_days": expires_days,
        "registrar": registrar,
        "statuses": statuses,
        "nameservers": sorted(set(nameservers))[:10],
        "dnssec": bool((raw.get("secureDNS") or {}).get("delegationSigned")),
        "fetched_at": now.isoformat(),
    }
    _cache_set(success_key, payload)
    return payload


def _parse_datetime(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _find_registrar(entities: Any, depth: int = 0) -> str | None:
    if depth > 3 or not isinstance(entities, list):
        return None
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        roles = {str(role).lower() for role in entity.get("roles", []) or []}
        if "registrar" in roles:
            name = _vcard_name(entity.get("vcardArray"))
            return name or str(entity.get("handle") or "")[:120] or None
        nested = _find_registrar(entity.get("entities"), depth + 1)
        if nested:
            return nested
    return None


def _vcard_name(vcard: Any) -> str | None:
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return None
    for entry in vcard[1]:
        if isinstance(entry, list) and len(entry) >= 4 and str(entry[0]).lower() == "fn":
            return str(entry[3])[:120]
    return None


async def _probe_dns(domain: str) -> dict[str, Any]:
    if not domain:
        return {"ok": False, "error": "no_domain"}

    async def query(name: str, rdtype: str) -> Any:
        resolver = dns.asyncresolver.Resolver(configure=True)
        resolver.timeout = 3.0
        resolver.lifetime = 4.0
        try:
            return await resolver.resolve(name, rdtype, raise_on_no_answer=False)
        except Exception as exc:
            return exc

    tasks = [
        query(domain, "A"),
        query(domain, "AAAA"),
        query(domain, "NS"),
        query(domain, "MX"),
        query(domain, "TXT"),
        query(f"_dmarc.{domain}", "TXT"),
    ]
    try:
        a_ans, aaaa_ans, ns_ans, mx_ans, txt_ans, dmarc_ans = await asyncio.wait_for(
            asyncio.gather(*tasks), timeout=12.0
        )
    except TimeoutError:
        return {"ok": False, "error": "dns_timeout"}

    def addresses(answer: Any) -> list[str]:
        if isinstance(answer, Exception):
            return []
        try:
            return sorted({str(item.address) for item in answer})
        except Exception:
            return []

    def names(answer: Any) -> list[str]:
        if isinstance(answer, Exception):
            return []
        try:
            return sorted({str(item.target).rstrip(".") for item in answer})
        except Exception:
            return []

    a_records = addresses(a_ans)
    aaaa_records = addresses(aaaa_ans)
    ns_records = names(ns_ans)
    mx_records = []
    if not isinstance(mx_ans, Exception):
        try:
            mx_records = sorted(
                ({"host": str(item.exchange).rstrip("."), "preference": int(item.preference)} for item in mx_ans),
                key=lambda item: item["preference"],
            )
        except Exception:
            mx_records = []

    txt_values: list[str] = []
    if not isinstance(txt_ans, Exception):
        try:
            for record in txt_ans:
                txt_values.append(b"".join(record.strings).decode("utf-8", errors="replace"))
        except Exception:
            txt_values = []
    spf_record = next((value for value in txt_values if value.lower().startswith("v=spf1")), "")
    spf = {"present": bool(spf_record)}
    if spf_record:
        spf["all"] = "strict" if "-all" in spf_record else "soft" if "~all" in spf_record else "neutral"

    dmarc_record = ""
    if not isinstance(dmarc_ans, Exception):
        try:
            for record in dmarc_ans:
                value = b"".join(record.strings).decode("utf-8", errors="replace")
                if value.lower().startswith("v=dmarc1"):
                    dmarc_record = value
                    break
        except Exception:
            dmarc_record = ""
    dmarc_policy = ""
    if dmarc_record:
        for part in dmarc_record.split(";"):
            if part.strip().lower().startswith("p="):
                dmarc_policy = part.split("=", 1)[1].strip().lower()
                break

    ok = bool(a_records or aaaa_records or ns_records)
    return {
        "ok": ok,
        "a": a_records,
        "aaaa": aaaa_records,
        "ns": ns_records,
        "mx": mx_records[:5],
        "has_mx": bool(mx_records),
        "spf": spf,
        "dmarc": {"present": bool(dmarc_record), "policy": dmarc_policy},
    }


async def _probe_tls(host: str) -> dict[str, Any]:
    if not host:
        return {"ok": False, "error": "no_host"}
    cache_key = f"tls:{host}"
    cached = _cache_get(cache_key, TLS_TTL)
    if cached:
        return cached
    try:
        result = await asyncio.to_thread(_tls_probe_sync, host)
    except Exception as exc:
        result = {"ok": False, "error": f"tls_{type(exc).__name__}"}
    if result.get("ok"):
        _cache_set(cache_key, result)
    return result


def _tls_probe_sync(host: str) -> dict[str, Any]:
    try:
        resolve_public_sync(host, 443)
    except Exception as exc:
        return {"ok": False, "error": f"blocked_or_unresolved: {type(exc).__name__}"}

    der: bytes | None = None
    trusted = False
    verify_error = ""
    protocol = ""
    cipher_name = ""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=7) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                der = tls_sock.getpeercert(binary_form=True)
                trusted = True
                protocol = tls_sock.version() or ""
                cipher = tls_sock.cipher()
                cipher_name = cipher[0] if cipher else ""
    except ssl.SSLCertVerificationError as exc:
        verify_error = str(exc)
        insecure = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        insecure.check_hostname = False
        insecure.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, 443), timeout=7) as sock:
                with insecure.wrap_socket(sock, server_hostname=host) as tls_sock:
                    der = tls_sock.getpeercert(binary_form=True)
                    protocol = tls_sock.version() or ""
                    cipher = tls_sock.cipher()
                    cipher_name = cipher[0] if cipher else ""
        except Exception as exc2:
            return {"ok": False, "error": f"{type(exc2).__name__}: {str(exc2)[:120]}"}
    except (ssl.SSLError, socket.timeout, TimeoutError, OSError) as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:120]}"}
    if not der:
        return {"ok": False, "error": "no_certificate"}

    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return {"ok": False, "error": "certificate_parse_failed"}

    subject = _name(cert.subject, NameOID.COMMON_NAME) or _name(cert.subject, NameOID.ORGANIZATION_NAME)
    issuer = _name(cert.issuer, NameOID.ORGANIZATION_NAME) or _name(cert.issuer, NameOID.COMMON_NAME)
    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    san_names: list[str] = []
    try:
        extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_names = [str(name) for name in extension.value.get_values_for_type(x509.DNSName)]
    except x509.ExtensionNotFound:
        san_names = []
    hostname_match = _hostname_matches(host, san_names or ([subject] if subject else []))
    expired = now > not_after
    self_signed = cert.subject == cert.issuer
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    days_remaining = int((not_after - now).total_seconds() // 86400)
    return {
        "ok": True,
        "trusted": trusted,
        "hostname_match": hostname_match,
        "expired": expired,
        "self_signed": self_signed,
        "subject": subject,
        "issuer": issuer,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_remaining": days_remaining,
        "san": san_names[:25],
        "fingerprint_sha256": fingerprint,
        "protocol": protocol,
        "cipher": cipher_name,
        "verify_error": truncate(verify_error, 300),
    }


def _name(name: x509.Name, oid: x509.ObjectIdentifier) -> str:
    attributes = name.get_attributes_for_oid(oid)
    return str(attributes[0].value) if attributes else ""


def _hostname_matches(host: str, names: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for raw in names:
        name = str(raw).lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*.") and host.count(".") == name.count(".") and host.endswith(name[1:]):
            return True
    return False
