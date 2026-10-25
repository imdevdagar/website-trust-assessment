"""Human-readable, action-aware explanations built only from scored evidence."""

from __future__ import annotations

from dataclasses import dataclass

from ..schemas import Action, DIMENSION_LABELS, Evidence, RiskLevel
from .aggregate import AggregateResult
from .rules import action_label


@dataclass(frozen=True)
class Explanation:
    headline: str
    recommendation: str
    rationale: str


SPECIAL_HEADLINES = {
    "known_malicious_label": "Domain is on the local malicious list",
    "known_suspicious_label": "Domain is on the local suspicious list",
    "password_form_http": "Password form on an unencrypted page",
    "hidden_prompt_injection": "Hidden content targets automated reviewers",
    "malicious_infrastructure_overlap": "Infrastructure overlaps with malicious domains",
    "brand_subdomain_impersonation": "Possible brand impersonation in the hostname",
    "brand_action_domain": "Brand name combined with account wording",
    "typosquatting_domain": "Lookalike domain name detected",
    "claimed_brand_mismatch": "Page claims a brand it does not belong to",
}

RECOMMENDATIONS: dict[Action, dict[RiskLevel, str]] = {
    Action.BROWSE: {
        RiskLevel.CRITICAL: (
            "Do not enter credentials, payment details, or personal information. Leave the page and "
            "reach the organization through an address or app you already trust."
        ),
        RiskLevel.HIGH: (
            "Avoid signing in, downloading files, or sharing data here. Verify the organization "
            "independently before continuing."
        ),
        RiskLevel.MEDIUM: (
            "Proceed cautiously. Verify who operates the site and avoid reusing passwords; do not "
            "share sensitive data unless you can confirm the destination."
        ),
        RiskLevel.LOW: (
            "No significant risk signals appeared in the evidence checked. That is not a guarantee: "
            "stay alert for credential requests, unusual payment methods, or pressure to act quickly."
        ),
        RiskLevel.UNKNOWN: (
            "TrustLens could not collect enough reliable evidence. Treat the site as unverified until "
            "you can confirm who operates it."
        ),
    },
    Action.SIGNUP: {
        RiskLevel.CRITICAL: (
            "Do not create an account or enter credentials. Leave the page and verify the service "
            "through an independent source before providing any personal data."
        ),
        RiskLevel.HIGH: (
            "Do not reuse an existing password and do not provide identity documents. Confirm the "
            "operator independently before creating an account."
        ),
        RiskLevel.MEDIUM: (
            "Check the organization and the privacy terms before signing up. Use a unique password, "
            "share the minimum data required, and be wary of pre-selected marketing consent."
        ),
        RiskLevel.LOW: (
            "No significant risk signals appeared in the evidence checked. Still use a unique password "
            "and review what data and consent options are selected before submitting."
        ),
        RiskLevel.UNKNOWN: (
            "Treat sign-up as unverified. Do not provide a password or identity data until you can "
            "confirm who operates the site."
        ),
    },
    Action.PURCHASE: {
        RiskLevel.CRITICAL: (
            "Do not pay or enter card details. Leave the page and reach the merchant through its "
            "official app or an address you already trust."
        ),
        RiskLevel.HIGH: (
            "Do not pay yet. Verify the seller, the returns process, and payment protection through an "
            "independent channel; avoid bank transfer, crypto, and gift-card payment."
        ),
        RiskLevel.MEDIUM: (
            "Confirm the seller's identity and refund terms before paying. Prefer payment methods with "
            "chargeback protection, and avoid being moved off the checkout page."
        ),
        RiskLevel.LOW: (
            "No significant risk signals appeared in the evidence checked. Confirm the seller and refund "
            "terms, keep payment inside the checkout, and avoid gift-card or crypto payment."
        ),
        RiskLevel.UNKNOWN: (
            "Treat the purchase as unverified. Do not pay or enter card details until you can confirm "
            "the seller independently."
        ),
    },
}


def _top_risks(result: AggregateResult, limit: int = 3) -> list[Evidence]:
    risks = [item for item in result.evidence if item.risk_points > 0]
    return sorted(
        risks,
        key=lambda item: item.risk_points * item.confidence,
        reverse=True,
    )[:limit]


def _top_trust(result: AggregateResult, limit: int = 2) -> list[Evidence]:
    trusts = [item for item in result.evidence if item.trust_points > 0]
    return sorted(
        trusts,
        key=lambda item: item.trust_points * item.confidence,
        reverse=True,
    )[:limit]


def _headline(result: AggregateResult, action: Action) -> str:
    if result.floors and result.floors[0] in SPECIAL_HEADLINES:
        return SPECIAL_HEADLINES[result.floors[0]]
    top = _top_risks(result, limit=1)
    if top and top[0].code in SPECIAL_HEADLINES and top[0].risk_points >= 10:
        return SPECIAL_HEADLINES[top[0].code]
    level = result.overall_level
    if level == RiskLevel.UNKNOWN:
        return "Evidence is insufficient to rate this site"
    if level == RiskLevel.CRITICAL:
        return f"Critical risk signals for {action_label(action)}"
    if level == RiskLevel.HIGH:
        return f"High-risk signals for {action_label(action)}"
    if level == RiskLevel.MEDIUM:
        return "Some risk signals warrant caution"
    return "No significant risk signals in the evidence checked"


def _rationale(
    result: AggregateResult,
    action: Action,
    final_domain: str,
    missing_evidence: list[str],
) -> str:
    level = result.overall_level.value
    sentences = [
        f"TrustLens combined {len(result.evidence)} evidence item(s) across four dimensions for "
        f"{action_label(action)} on {final_domain}. The action-weighted risk score is "
        f"{result.overall_risk:.0f}/100 ({level}) with {result.confidence:.0%} confidence."
    ]
    top = _top_risks(result, limit=3)
    if top:
        concerns = []
        for item in top:
            label = DIMENSION_LABELS[item.dimension]
            concerns.append(
                f"{label}: {item.title} (+{item.risk_points:.0f})"
            )
        sentences.append("Strongest concerns: " + "; ".join(concerns) + ".")
    elif result.overall_level != RiskLevel.UNKNOWN:
        sentences.append(
            "No adverse pattern crossed the scoring thresholds in the evidence that could be collected."
        )
    if result.floors:
        sentences.append(
            "A locally imported reputation label sets a minimum risk floor; it is not a live lookup "
            "and should be verified independently."
        )
    trust = _top_trust(result)
    if trust:
        sentences.append(
            "Positive signals: "
            + "; ".join(item.title for item in trust)
            + ". Trust signals are deliberately weak and do not cancel serious findings."
        )
    abstained = [
        item.label for item in result.dimensions.values() if item.abstained
    ]
    if abstained:
        sentences.append(
            "Insufficient evidence for: " + ", ".join(abstained) + "."
        )
    if missing_evidence:
        messages = "; ".join(message.rstrip(".") for message in missing_evidence[:3])
        sentences.append(f"Unavailable evidence: {messages}. This lowers confidence and can hide problems.")
    sentences.append(
        "Automated checks are advisory: a site can show different content to different visitors, "
        "and a low score is not a guarantee that a site is safe."
    )
    return " ".join(sentences)


def compose(
    result: AggregateResult,
    *,
    action: Action,
    final_domain: str,
    missing_evidence: list[str],
) -> Explanation:
    return Explanation(
        headline=_headline(result, action),
        recommendation=RECOMMENDATIONS[action][result.overall_level],
        rationale=_rationale(result, action, final_domain, missing_evidence),
    )
