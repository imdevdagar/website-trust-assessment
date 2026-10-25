"""Third-party tracking, cookie, and consent evidence (privacy dimension)."""

from __future__ import annotations

import re
from collections import defaultdict
from urllib.parse import urlsplit

from ..knowledge import match_trackers, tracking_cookie
from ..schemas import Dimension, Evidence, Severity
from ..security import registrable_domain
from .base import ScanContext

CATEGORY_TITLES = {
    "session_replay": "Session recording or behavioral replay",
    "fingerprinting": "Device fingerprinting",
    "advertising": "Advertising and retargeting trackers",
    "customer_data": "Customer-data and marketing platforms",
    "analytics": "Third-party analytics",
    "media": "Third-party media embeds",
    "support": "Third-party support widgets",
}
CONSENT_UI_RE = re.compile(
    r"\b(accept all|reject all|manage (preferences|options|cookies)|"
    r"cookie (settings|preferences)|consent (settings|preferences)|"
    r"i (consent|agree)|allow all)\b",
    re.IGNORECASE,
)
TRACKING_FOCUS = {"session_replay", "fingerprinting", "advertising", "customer_data", "analytics", "media"}


def _third_party_hosts(ctx: ScanContext) -> set[str]:
    hosts: set[str] = set()
    for url in ctx.page.network_urls:
        try:
            host = (urlsplit(url).hostname or "").lower()
        except ValueError:
            continue
        if not host:
            continue
        try:
            if registrable_domain(host) != ctx.final_domain:
                hosts.add(host)
        except Exception:
            continue
    return hosts


def extract(ctx: ScanContext) -> list[Evidence]:
    evidence: list[Evidence] = []
    ctx.add_source("network", bool(ctx.page.network_urls))
    if not ctx.page.network_urls:
        ctx.add_missing("Network requests were not captured")
        return evidence

    matches = match_trackers(ctx.page.network_urls, ctx.final_host)
    third_party = [match for match in matches if match["third_party"]]
    groups: dict[str, list[dict]] = defaultdict(list)
    for match in third_party:
        groups[match["category"]].append(match)

    ctx.notes["trackers"] = {
        "total": len(matches),
        "third_party": len(third_party),
        "categories": {category: len(items) for category, items in groups.items()},
        "names": sorted({match["name"] for match in third_party})[:12],
    }

    evidence.extend(_category_evidence(ctx, groups))
    evidence.extend(_footprint_evidence(ctx, groups))
    evidence.extend(_cookie_evidence(ctx))

    consent_controls = bool(
        CONSENT_UI_RE.search(
            " ".join(ctx.page.buttons[:40] + [str(item.get("text", "")) for item in ctx.page.sticky_elements[:10]])
        )
    )
    if consent_controls:
        ctx.notes["consent_ui"] = True
    non_essential = {
        category for category in ("advertising", "session_replay", "fingerprinting", "customer_data")
        if category in groups
    }
    if non_essential and not consent_controls and ctx.page.engine == "playwright":
        evidence.append(
            ctx.evidence(
                dimension=Dimension.PRIVACY,
                code="no_consent_controls",
                title="Tracking requests without visible consent controls",
                detail="Advertising, session-recording, or fingerprinting services were observed, but no consent or "
                "preference controls were visible in the initial viewport. Consent requirements depend on jurisdiction; "
                "this is a transparency concern, not a legal determination.",
                severity=Severity.LOW,
                risk_points=3.5,
                confidence=0.4,
                source="page",
                provenance={
                    "categories": sorted(non_essential),
                    "control_scan": "visible buttons and sticky elements",
                },
                tags=["privacy", "consent"],
            )
        )

    if not any(category in groups for category in ("advertising", "session_replay", "fingerprinting")):
        evidence.append(
            ctx.evidence(
                dimension=Dimension.PRIVACY,
                code="no_high_impact_trackers",
                title="No advertising, session-replay, or fingerprinting requests observed",
                detail="Only low-impact or functional third parties were visible during this load. Scripts can load "
                "conditionally, so this is a weak positive signal.",
                severity=Severity.INFO,
                risk_points=0.0,
                trust_points=2.0,
                confidence=0.45,
                source="page",
                provenance={"categories": sorted(groups)},
                tags=["privacy", "weak_trust"],
            )
        )

    return evidence


def _category_evidence(ctx: ScanContext, groups: dict[str, list[dict]]) -> list[Evidence]:
    evidence: list[Evidence] = []
    for category, items in sorted(groups.items(), key=lambda pair: len(pair[1]), reverse=True):
        if category not in TRACKING_FOCUS:
            continue
        if category == "analytics":
            base, cap = 2.0, 4.0
        elif category == "session_replay":
            base, cap = 13.0, 20.0
        elif category == "fingerprinting":
            base, cap = 13.0, 17.0
        elif category == "advertising":
            base, cap = 4.0, 10.0
        elif category == "customer_data":
            base, cap = 4.0, 8.0
        else:
            base, cap = 2.0, 4.0
        count = len(items)
        risk = min(cap, base + max(0, count - 1) * 2.0)
        if category == "session_replay" and ctx.has_password_form:
            risk = min(22.0, risk + 2.0)
        if risk < 2.5:
            continue
        names = ", ".join(sorted({item["name"] for item in items})[:6])
        detail = {
            "session_replay": "Session replay scripts can record clicks, scrolling, and form interactions. Most tools "
            "mask passwords, but masking errors and sensitive-field capture have been documented. ",
            "fingerprinting": "Fingerprinting scripts combine browser and device attributes to recognize visitors "
            "across sites, often without cookies. ",
            "advertising": "Advertising pixels build cross-site behavioral profiles and share data with ad networks. ",
            "customer_data": "Customer-data platforms can link page activity to identified contacts and marketing lists. ",
            "analytics": "Third-party analytics observe page activity. The privacy impact is lower than session replay "
            "but still involves third-party data collection. ",
            "media": "Embedded media can set its own cookies and observe playback or interaction. ",
        }[category] + f"Observed: {names}."
        if category == "session_replay" and ctx.has_password_form:
            detail += " A credential form is on the same page, which raises the impact of any recording."
        evidence.append(
            ctx.evidence(
                dimension=Dimension.PRIVACY,
                code=f"tracker_{category}",
                title=CATEGORY_TITLES[category],
                detail=detail,
                severity=Severity.HIGH if risk >= 18 else Severity.MEDIUM if risk >= 8 else Severity.LOW,
                risk_points=risk,
                confidence=0.85 if category in {"session_replay", "fingerprinting"} else 0.7,
                source="page",
                provenance={
                    "count": count,
                    "trackers": sorted({item["name"] for item in items})[:8],
                    "hosts": sorted({item["host"] for item in items})[:8],
                },
                tags=["privacy", "tracking", category],
            )
        )
    return evidence


def _footprint_evidence(ctx: ScanContext, groups: dict[str, list[dict]]) -> list[Evidence]:
    hosts = _third_party_hosts(ctx)
    if len(hosts) < 20:
        return []
    risk = 7.0 if len(hosts) >= 40 else 4.0
    return [
        ctx.evidence(
            dimension=Dimension.PRIVACY,
            code="large_third_party_footprint",
            title="Large third-party request footprint",
            detail=f"The page contacted {len(hosts)} distinct third-party hosts. More parties mean more data-sharing "
            "surfaces and a larger supply-chain attack surface.",
            severity=Severity.LOW if len(hosts) < 40 else Severity.MEDIUM,
            risk_points=risk,
            confidence=0.65,
            source="page",
            provenance={
                "third_party_hosts": len(hosts),
                "sample": sorted(hosts)[:10],
                "tracker_categories": sorted(groups)[:10],
            },
            tags=["privacy", "third_party"],
        )
    ]


def _cookie_evidence(ctx: ScanContext) -> list[Evidence]:
    names = [str(cookie.get("name", "")) for cookie in ctx.page.cookies if cookie.get("name")]
    tracking = sorted({name for name in names if tracking_cookie(name)})
    if not tracking:
        return []
    return [
        ctx.evidence(
            dimension=Dimension.PRIVACY,
            code="tracking_cookies",
            title="Known tracking cookies were set",
            detail=f"Cookie names associated with analytics or advertising were observed: {', '.join(tracking[:8])}. "
            "Cookie values are not stored by TrustLens.",
            severity=Severity.LOW,
            risk_points=3.0,
            confidence=0.75,
            source="page",
            provenance={"cookie_names": tracking[:10], "total_cookies": len(names)},
            tags=["privacy", "cookies"],
        )
    ]
