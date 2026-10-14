"""
src/scoring/risk_scorer.py

Multi-Layer Composite Risk Scoring Engine
==========================================
Combines 5 signal layers into a 0-100 Trust Score:
  Layer 0: ML Model prediction (hard ceiling)
  Layer 1: URL structure signals      (0-25)
  Layer 2: Domain / Whois age         (0-25)
  Layer 3: Live HTML content analysis (0-25)
  Layer 4: Reputation DB lookup       (0-25)

The ML model prediction (Layer 0) acts as a hard ceiling --
no matter how clean the URL looks, a confident Scam/Phishing
prediction from the model will cap the final score.

Score interpretation:
    80-100  -> Likely Legitimate (green)
    55-79   -> Low Risk / Proceed with Caution (yellow-green)
    30-54   -> Suspicious / Needs Review (orange)
    0-29    -> High Risk (red)
"""

import re
import requests
from dataclasses import dataclass, field

_URGENCY_PATTERNS = [
    r"limited\s+time", r"act\s+now", r"expires?\s+in", r"today\s+only",
    r"while\s+stocks?\s+last", r"hurry", r"don.t\s+miss", r"last\s+chance",
    r"offer\s+ends", r"only\s+\d+\s+left",
]
_FAKE_REVIEW_PATTERNS = [
    r"\b5[\s\-]?star\b", r"verified\s+buyer", r"trusted\s+by\s+\d+",
    r"rated\s+#?1", r"best\s+seller", r"award.winning",
]
_PAYMENT_RISK_PATTERNS = [
    r"bitcoin", r"crypto(currency)?", r"ethereum", r"usdt", r"wire\s+transfer",
    r"western\s+union", r"moneygram", r"gift\s+card\s+payment",
    r"zelle", r"cashapp", r"venmo\s+payment",
]
_CONTACT_MISSING_SIGNALS = [
    r"contact\s+us", r"support@", r"\+\d[\d\s\-]{7,}", r"live\s+chat",
]
_TRUST_BADGE_KEYWORDS = [
    r"ssl\s+secured", r"100%\s+secure", r"money.back\s+guarantee",
    r"safe\s+checkout", r"verified\s+site", r"trusted\s+shop",
]
_INVESTMENT_SCAM_PATTERNS = [
    r"guaranteed\s+(profit|return|income)", r"double\s+your\s+(money|investment)",
    r"passive\s+income", r"financial\s+freedom", r"forex", r"trading\s+bot",
    r"investment\s+opportunity", r"high\s+yield",
]
_PET_SCAM_PATTERNS = [
    r"puppy|puppies|kitten|kittens", r"shipping\s+fee", r"transport\s+cage",
    r"adoption\s+fee",
]

def _count_pattern_matches(text: str, patterns: list) -> int:
    text = text.lower()
    return sum(1 for p in patterns if re.search(p, text))

_URLHAUS_LOOKUP = "https://urlhaus-api.abuse.ch/v1/url/"

def _check_urlhaus(url: str, timeout: int = 5) -> dict:
    try:
        resp = requests.post(
            _URLHAUS_LOOKUP, data={"url": url}, timeout=timeout,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "is_listed":
                return {"listed": True, "threat": data.get("threat", "unknown")}
    except Exception:
        pass
    return {"listed": False}

def _check_google_safe_browsing(url: str, api_key: str = None, timeout: int = 5) -> dict:
    if not api_key:
        return {"threat": None, "available": False}
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "website-trust-assessor", "clientVersion": "2.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        resp = requests.post(endpoint, json=payload, timeout=timeout)
        data = resp.json()
        if data.get("matches"):
            return {"threat": data["matches"][0].get("threatType", "UNKNOWN"), "available": True}
        return {"threat": None, "available": True}
    except Exception:
        return {"threat": None, "available": False}

@dataclass
class RiskResult:
    trust_score: int = 100
    risk_label: str = "Unknown"
    risk_color: str = "#22c55e"
    # Layer scores
    layer0_model_ceiling: int = 100   # Hard ceiling imposed by ML model
    layer1_url_score: int = 25
    layer2_whois_score: int = 25
    layer3_html_score: int = 25
    layer4_reputation_score: int = 25
    flags: list = field(default_factory=list)
    domain_age_days: int = -1
    urlhaus_listed: bool = False
    gsb_threat: str = None
    urgency_signals: int = 0
    payment_risk_signals: int = 0
    investment_signals: int = 0
    pet_scam_signals: int = 0
    has_real_contact: bool = True
    fake_trust_badges: int = 0
    # ML model signals
    model_scam_proba: float = 0.0
    model_phish_proba: float = 0.0
    model_legit_proba: float = 0.0
    # Consensus & Divergence Safety Net (Phase 7)
    divergence_index: float = 0.0     # 0.0 = perfect consensus, 1.0 = total contradiction
    consensus_status: str = "High Agreement"
    safety_net_triggered: bool = False
    evidence_breakdown: dict = field(default_factory=dict)

def compute_risk_score(
    url: str,
    url_features: dict,
    html_features: dict = None,
    domain_features: dict = None,
    google_safe_browsing_key: str = None,
    html_text: str = "",
    model_proba: list = None,   # [P(Legitimate), P(Phishing), P(Scam)] from ML model
    fast_mode: bool = False,    # When True, skips external network requests (URLhaus) for instant offline benchmarking
) -> RiskResult:
    """
    Compute the composite trust score.

    model_proba: list of 3 floats [P(Legit), P(Phishing), P(Scam)].
                 When provided, the ML model prediction acts as a hard
                 ceiling so a confident Scam/Phishing prediction always
                 results in a low trust score, even if URL signals look clean.
    """
    result = RiskResult()
    flags = []

    # LAYER 1: URL Signal Score (0-25)
    l1 = 25
    uf = url_features or {}
    
    # Critical threat indicators (Brand Impersonation & Typosquatting)
    if uf.get("HasBrandImpersonation", 0):
        l1 -= 20; flags.append("CRITICAL: Brand Impersonation detected (domain spoofing a trusted trademark)")
    if uf.get("HasTyposquatting", 0):
        l1 -= 15; flags.append("HIGH RISK: Typosquatting detected (domain visually mimics a major brand)")
    if uf.get("HasHomographChar", 0):
        l1 -= 15; flags.append("HIGH RISK: Homograph attack (Unicode lookalike characters used in domain)")
    if uf.get("HasSuspiciousTLD", 0):
        l1 -= 10; flags.append("HIGH RISK: High-abuse TLD (.xyz, .top, .buzz, etc.)")
    if uf.get("HasCompoundTLD", 0):
        l1 -= 8; flags.append("WARNING: Suspicious compound TLD (.com.co, .net.ru)")
    if uf.get("IsDomainIP", 0):
        l1 -= 12; flags.append("CRITICAL: Bare IP address used instead of domain name")
    if uf.get("IsHTTPS", 1) == 0:
        l1 -= 6; flags.append("WARNING: No HTTPS encryption")
    if uf.get("HasPhishKeyword", 0):
        l1 -= 10; flags.append("HIGH RISK: Phishing credential keywords (login, verify, secure)")
    if uf.get("HasInvestKeyword", 0):
        l1 -= 8; flags.append("WARNING: High-yield investment keywords")
    if uf.get("HasCryptoKeyword", 0):
        l1 -= 6; flags.append("WARNING: Crypto token keywords")
    if uf.get("NoOfHyphensInDomain", 0) > 1:
        l1 -= 4; flags.append("WARNING: Multiple hyphens in domain name")
    if uf.get("SubdomainDepth", 0) > 2:
        l1 -= 4; flags.append("WARNING: Deep subdomain abuse")
    
    result.layer1_url_score = max(0, l1)

    # LAYER 2: Domain / Whois Score (0-25)
    l2 = 25
    df = domain_features or {}
    age = df.get("DomainAgeDays", -1)
    result.domain_age_days = age
    if age == -1:
        l2 -= 5; flags.append("🟡 Domain age unknown (private registration or Whois failed)")
    elif age < 30:
        l2 -= 15; flags.append(f"🔴 VERY new domain -- only {age} days old (high fraud risk)")
    elif age < 180:
        l2 -= 8; flags.append(f"🟠 New domain -- only {age} days old")
    elif age < 365:
        l2 -= 3; flags.append(f"🟡 Domain is less than 1 year old ({age} days)")
    result.layer2_whois_score = max(0, l2)

    # LAYER 3: HTML Content Analysis Score (0-25)
    l3 = 25
    if html_features is None:
        l3 = 25; flags.append("ℹ️ HTML content skipped (site blocked crawler or is offline)")
    else:
        hf = html_features
        if hf.get("HasExternalFormSubmit", 0):
            l3 -= 6; flags.append("🔴 Form data submitted to an external/third-party domain")
        if hf.get("NoOfiFrame", 0) > 2:
            l3 -= 3; flags.append("🟡 Multiple hidden iframes detected")
        if hf.get("NoOfPopup", 0) > 0:
            l3 -= 2; flags.append("🟡 JavaScript popups detected")
        if hf.get("HasHiddenFields", 0):
            l3 -= 2; flags.append("🟡 Hidden form fields present")
        if not hf.get("HasCopyrightInfo", 0):
            l3 -= 2; flags.append("🟡 No copyright information found")
        if not hf.get("HasFavicon", 0):
            l3 -= 1; flags.append("🟡 No favicon")
        if hf.get("NoOfURLRedirect", 0) > 2:
            l3 -= 2; flags.append("🟡 Multiple URL redirects")

        if html_text:
            urgency = _count_pattern_matches(html_text, _URGENCY_PATTERNS)
            payment_risk = _count_pattern_matches(html_text, _PAYMENT_RISK_PATTERNS)
            invest_risk = _count_pattern_matches(html_text, _INVESTMENT_SCAM_PATTERNS)
            pet_risk = _count_pattern_matches(html_text, _PET_SCAM_PATTERNS)
            fake_badges = _count_pattern_matches(html_text, _TRUST_BADGE_KEYWORDS)
            real_contact = _count_pattern_matches(html_text, _CONTACT_MISSING_SIGNALS) > 0

            result.urgency_signals = urgency
            result.payment_risk_signals = payment_risk
            result.investment_signals = invest_risk
            result.pet_scam_signals = pet_risk
            result.fake_trust_badges = fake_badges
            result.has_real_contact = real_contact

            if urgency >= 3:
                l3 -= 5; flags.append(f"🔴 High-pressure urgency language ({urgency} patterns found)")
            elif urgency >= 1:
                l3 -= 2; flags.append(f"🟡 Urgency language detected ({urgency} patterns)")
            if payment_risk >= 2:
                l3 -= 6; flags.append("🔴 Risky payment methods requested (crypto/wire transfer/gift cards)")
            elif payment_risk == 1:
                l3 -= 3; flags.append("🟠 Non-standard payment method detected")
            if invest_risk >= 2:
                l3 -= 5; flags.append("🔴 Investment scam language detected (guaranteed returns, passive income)")
            if pet_risk >= 2:
                l3 -= 5; flags.append("🔴 Pet scam patterns detected (shipping/adoption fees)")
            if fake_badges >= 2:
                l3 -= 3; flags.append(f"🟠 Fake trust badges detected ({fake_badges} patterns)")
            if not real_contact:
                l3 -= 3; flags.append("🟠 No verifiable contact info (phone/email) found")

    result.layer3_html_score = max(0, l3)

    # LAYER 4: Reputation DB Score (0-25)
    l4 = 25
    urlhaus = {"listed": False} if fast_mode else _check_urlhaus(url)
    result.urlhaus_listed = urlhaus.get("listed", False)
    if urlhaus.get("listed"):
        l4 -= 25
        flags.append(f"BLACKLISTED on URLhaus (abuse.ch) -- Threat: {urlhaus.get('threat', 'unknown')}")
    gsb = {"threat": None, "available": False} if fast_mode else _check_google_safe_browsing(url, api_key=google_safe_browsing_key)
    result.gsb_threat = gsb.get("threat")
    if gsb.get("threat"):
        l4 -= 20
        flags.append(f"Google Safe Browsing warning -- Threat: {gsb['threat']}")
    elif not gsb.get("available", False) and not urlhaus.get("listed"):
        flags.append("ℹ️ Google Safe Browsing not configured (add API key for full check)")
    result.layer4_reputation_score = max(0, l4)

    # ── LAYER 0: ML Model Hard Ceiling & Floor ────────────────────────────────
    # The ML model prediction overrides the rule-based score when it is confident.
    # This prevents the contradition: Model=Scam but Trust Score=83.
    ceiling = 100
    floor = 0
    ml_flags = []
    
    if model_proba is not None and len(model_proba) == 3:
        p_legit, p_phish, p_scam = float(model_proba[0]), float(model_proba[1]), float(model_proba[2])
        result.model_legit_proba = p_legit
        result.model_phish_proba = p_phish
        result.model_scam_proba  = p_scam

        if p_scam >= 0.80:
            ceiling = 25
            ml_flags.append(f"🔴 ML model is {p_scam:.0%} confident this is a SCAM site")
        elif p_scam >= 0.60:
            ceiling = 40
            ml_flags.append(f"🟠 ML model flagged as probable Scam ({p_scam:.0%} confidence)")
        elif p_scam >= 0.40:
            ceiling = 55
            ml_flags.append(f"🟡 ML model shows elevated Scam probability ({p_scam:.0%})")
        elif p_phish >= 0.80:
            ceiling = 30
            ml_flags.append(f"🔴 ML model is {p_phish:.0%} confident this is a PHISHING site")
        elif p_phish >= 0.60:
            ceiling = 45
            ml_flags.append(f"🟠 ML model flagged as probable Phishing ({p_phish:.0%} confidence)")
        elif p_legit >= 0.90:
            floor = 85
            ml_flags.append(f"🟢 ML model highly confident ({p_legit:.0%}) site is legitimate (minor warnings suppressed)")

    # DOMAIN AGE RESCUE: URL-only ML models heavily false-positive on clean root domains (like amazon.com).
    # If the domain is established (> 3 years old) and has no attack flags and no reputation flags, 
    # we override the ML ceiling.
    age = result.domain_age_days
    has_active_attack = (
        uf.get("HasBrandImpersonation", 0) or
        uf.get("HasTyposquatting", 0) or
        uf.get("HasHomographChar", 0) or
        uf.get("HasSuspiciousTLD", 0) or
        uf.get("HasPhishKeyword", 0)
    )
    if age > 1095 and not result.urlhaus_listed and not result.gsb_threat and not has_active_attack:
        if ceiling < 100:
            flags.append(f"ML Model Override: Domain is highly established ({age} days old). Overriding {ceiling}/100 ML ceiling.")
        ceiling = 100
        floor = max(floor, 90)
    else:
        flags.extend(ml_flags)

    result.layer0_model_ceiling = ceiling

    # ── Composite Trust Score ─────────────────────────────────────────────────
    raw_total = (
        result.layer1_url_score +
        result.layer2_whois_score +
        result.layer3_html_score +
        result.layer4_reputation_score
    )

    # ── Evidence Divergence Index (EDI) & Consensus Arbitration (Phase 7) ────
    # Measure the mathematical gap between:
    # 1. Forensic / Ground-Truth Signals (Whois age, TLS, Threat DBs) -> normalized 0 to 1
    # 2. Predictive ML Signal (P(Legitimate)) -> 0 to 1
    forensic_trust_ratio = raw_total / 100.0
    ml_trust_ratio = p_legit if (model_proba is not None and len(model_proba) == 3) else forensic_trust_ratio

    # Absolute divergence between ML and Objective Forensics
    divergence = abs(ml_trust_ratio - forensic_trust_ratio)
    result.divergence_index = round(divergence, 4)
    result.evidence_breakdown = {
        "forensic_trust_score": raw_total,
        "ml_legit_probability": round(ml_trust_ratio * 100, 1),
        "divergence_percentage": round(divergence * 100, 1)
    }

    # SAFETY NET ARBITRATION:
    # If divergence > 0.45 (e.g. ML predicts 90% Scam/Phishing, but Forensics proves 90% Legitimate, OR vice-versa)
    # The system detects conflict, refuses to output a misleading extreme score, and clamps to cautionary review band.
    if divergence >= 0.45 and not result.urlhaus_listed and not result.gsb_threat:
        result.safety_net_triggered = True
        result.consensus_status = "Significant Divergence (Safety Clamped)"
        flags.append(
            f"SAFETY NET TRIGGERED: High divergence ({divergence:.0%}) detected between ML predictions and domain forensics. "
            "Score stabilized to prevent false classification."
        )
        # Pull score toward cautious neutral band (48-52) rather than misleading 10 or 95
        total = int((raw_total * 0.4) + (ml_trust_ratio * 100 * 0.2) + 50 * 0.4)
        total = max(35, min(total, 65))
    else:
        result.safety_net_triggered = False
        result.consensus_status = "High Consensus" if divergence < 0.25 else "Moderate Agreement"
        # Standard bounded resolution
        total = min(raw_total, ceiling)
        total = max(total, floor)

    result.trust_score = total

    if result.safety_net_triggered:
        result.risk_label = "Needs Review (Signal Conflict)"
        result.risk_color = "#eab308"
    elif total >= 80:
        result.risk_label = "Likely Legitimate"
        result.risk_color = "#22c55e"
    elif total >= 55:
        result.risk_label = "Low Risk"
        result.risk_color = "#84cc16"
    elif total >= 30:
        result.risk_label = "Suspicious"
        result.risk_color = "#f97316"
    else:
        result.risk_label = "High Risk"
        result.risk_color = "#ef4444"

    result.flags = flags
    return result

