"""Consumer-manipulation signals, including dark patterns and pre-checked consent."""

from __future__ import annotations

import re

from ..knowledge import dark_pattern_defs
from ..schemas import Dimension, Evidence, Severity
from .base import ScanContext, truncate

MARKETING_CHECKBOX_RE = re.compile(
    r"newsletter|marketing|promotional|offers?|deals?|updates?|sms|whatsapp|"
    r"third[-\s]?part|partners?|share (my|your) (data|information)|product news",
    re.IGNORECASE,
)
CONSENT_CHECKBOX_RE = re.compile(
    r"i (agree|accept|consent)|terms|privacy|conditions|age of majority|18\+",
    re.IGNORECASE,
)
COUNTDOWN_VALUE_RE = re.compile(r"\b\d{1,3}\s*[:hms]|(\d{1,2}:\d{2})", re.IGNORECASE)
TRIAL_RE = re.compile(r"\bfree\s+(trial|for\s+\d+\s+days?)\b", re.IGNORECASE)
AUTO_RENEW_RE = re.compile(
    r"\bauto[-\s]?renew|automatically\s+renews?|recurring\s+(billing|charge|payment)|"
    r"subscription\s+renews?|billed\s+(monthly|annually|every)\b",
    re.IGNORECASE,
)


def _severity(value: str) -> Severity:
    try:
        return Severity(value.lower())
    except ValueError:
        return Severity.LOW


def extract(ctx: ScanContext) -> list[Evidence]:
    evidence: list[Evidence] = []
    text = ctx.text
    if not text and not ctx.page.buttons:
        return evidence
    haystack = "\n".join(
        [
            text,
            " ".join(ctx.page.buttons[:60]),
            " ".join(str(link.get("text", "")) for link in ctx.page.links[:250]),
        ]
    )
    detected: list[dict] = []

    for definition in dark_pattern_defs():
        snippets: list[str] = []
        for pattern in definition.regexes:
            for match in pattern.finditer(haystack):
                start = max(0, match.start() - 50)
                end = min(len(haystack), match.end() + 60)
                snippet = truncate(haystack[start:end], 160)
                if snippet and snippet not in snippets:
                    snippets.append(snippet)
                if len(snippets) >= 4:
                    break
            if len(snippets) >= 4:
                break
        if not snippets:
            continue
        detected.append(
            {
                "definition": definition,
                "snippets": snippets[:3],
                "count": len(snippets),
            }
        )

    detected.sort(key=lambda item: item["definition"].risk_points, reverse=True)
    for item in detected[:9]:
        definition = item["definition"]
        risk = min(14.0, definition.risk_points + max(0, item["count"] - 1) * 1.0)
        detail = (
            f"{definition.description} Observed wording: \"{item['snippets'][0]}\"."
            if item["snippets"]
            else definition.description
        )
        evidence.append(
            ctx.evidence(
                dimension=Dimension.MANIPULATION,
                code=f"dark_{definition.code}",
                title=definition.title,
                detail=detail,
                severity=_severity(definition.severity),
                risk_points=risk,
                confidence=definition.confidence,
                source="page",
                provenance={
                    "category": definition.category,
                    "match_count": item["count"],
                    "snippets": item["snippets"],
                },
                tags=["dark_pattern", *definition.tags, definition.category],
            )
        )

    marketing_checked = []
    consent_checked = []
    for checkbox in ctx.page.checkboxes:
        if not checkbox.get("checked") or checkbox.get("hidden"):
            continue
        label = str(checkbox.get("label") or "")
        if not label:
            continue
        if MARKETING_CHECKBOX_RE.search(label):
            marketing_checked.append(truncate(label, 140))
        elif CONSENT_CHECKBOX_RE.search(label):
            consent_checked.append(truncate(label, 140))
    if marketing_checked:
        evidence.append(
            ctx.evidence(
                dimension=Dimension.MANIPULATION,
                code="prechecked_marketing",
                title="Marketing consent is pre-selected",
                detail="One or more marketing or data-sharing checkboxes are selected before the visitor acts: "
                + "; ".join(marketing_checked[:3])
                + ". Opt-in consent should normally require an affirmative choice.",
                severity=Severity.MEDIUM,
                risk_points=8.0,
                confidence=0.8,
                source="page",
                provenance={"labels": marketing_checked[:4], "count": len(marketing_checked)},
                tags=["dark_pattern", "consent", "privacy_choice"],
            )
        )
    if consent_checked:
        evidence.append(
            ctx.evidence(
                dimension=Dimension.MANIPULATION,
                code="prechecked_terms",
                title="Terms or privacy consent is pre-selected",
                detail="A terms/privacy consent checkbox is selected in advance. This can undermine meaningful consent, "
                "even when the practice is common.",
                severity=Severity.LOW,
                risk_points=4.0,
                confidence=0.65,
                source="page",
                provenance={"labels": consent_checked[:4], "count": len(consent_checked)},
                tags=["dark_pattern", "consent"],
            )
        )

    countdowns = [
        element
        for element in ctx.page.countdown_elements
        if COUNTDOWN_VALUE_RE.search(str(element.get("text", "")))
    ]
    if countdowns:
        sample = truncate(str(countdowns[0].get("text", "")), 120)
        evidence.append(
            ctx.evidence(
                dimension=Dimension.MANIPULATION,
                code="visual_countdown",
                title="Visible countdown or timer element",
                detail=f"A countdown-style element is displayed (\"{sample}\"). Timers can create real deadlines, but "
                "they are often reset or fabricated to pressure a purchase.",
                severity=Severity.LOW,
                risk_points=5.0,
                confidence=0.55,
                source="page",
                provenance={"elements": [truncate(str(c.get("text", "")), 100) for c in countdowns[:3]]},
                tags=["dark_pattern", "urgency"],
            )
        )

    if TRIAL_RE.search(text) and AUTO_RENEW_RE.search(text) and ctx.has_payment_form:
        evidence.append(
            ctx.evidence(
                dimension=Dimension.MANIPULATION,
                code="trial_auto_renew",
                title="Free trial paired with automatic renewal and payment collection",
                detail="The page mentions a free trial, recurring billing, and takes payment details. Check the renewal "
                "amount and cancellation process before continuing.",
                severity=Severity.MEDIUM,
                risk_points=9.0,
                confidence=0.6,
                source="page",
                provenance={
                    "trial_snippet": truncate(TRIAL_RE.search(text).group(0), 80) if TRIAL_RE.search(text) else "",
                    "renewal_snippet": truncate(AUTO_RENEW_RE.search(text).group(0), 80) if AUTO_RENEW_RE.search(text) else "",
                },
                tags=["dark_pattern", "forced_continuity"],
            )
        )

    if detected:
        ctx.notes["dark_patterns"] = [item["definition"].code for item in detected[:10]]
    if marketing_checked:
        ctx.notes["prechecked_marketing"] = True
    return evidence
