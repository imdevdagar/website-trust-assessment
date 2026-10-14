import re
import math
import unicodedata
from urllib.parse import urlparse, parse_qs
from collections import Counter


SAFE_TLDS = {
    "com", "org", "net", "edu", "gov", "co", "io", "uk",
    "de", "fr", "jp", "au", "ca", "ru", "br", "in", "cn",
    "nl", "it", "es", "pl", "se", "no", "fi", "dk", "ch",
}

# ── Known major brands for impersonation & typosquatting detection ─────────
_KNOWN_BRANDS = {
    "paypal", "amazon", "google", "facebook", "microsoft", "apple",
    "netflix", "ebay", "walmart", "chase", "wellsfargo", "bankofamerica",
    "instagram", "twitter", "linkedin", "dropbox", "adobe", "yahoo",
    "gmail", "outlook", "office365", "coinbase", "binance", "fedex",
    "dhl", "ups", "usps", "irs", "steam", "roblox", "fortnite",
}

# Official domains for each brand — if domain contains brand name but doesn't
# match any of these, it's likely impersonation.
_BRAND_OFFICIAL_TLDS = {
    "paypal":    {"paypal.com"},
    "amazon":    {"amazon.com"},
    "google":    {"google.com"},
    "facebook":  {"facebook.com"},
    "microsoft": {"microsoft.com"},
    "apple":     {"apple.com"},
    "netflix":   {"netflix.com"},
    "ebay":      {"ebay.com"},
    "chase":     {"chase.com"},
    "instagram": {"instagram.com"},
    "twitter":   {"twitter.com", "x.com"},
    "linkedin":  {"linkedin.com"},
    "gmail":     {"gmail.com", "google.com"},
    "outlook":   {"outlook.com"},
    "coinbase":  {"coinbase.com"},
    "binance":   {"binance.com"},
    "fedex":     {"fedex.com"},
    "dhl":       {"dhl.com"},
    "ups":       {"ups.com"},
    "steam":     {"steampowered.com"},
    "roblox":    {"roblox.com"},
}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    entropy = -sum((c / total) * math.log2(c / total) for c in counts.values())
    return round(entropy, 6)


def _is_ip_address(host: str) -> bool:
    ipv4 = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    return bool(ipv4.match(host))


def _levenshtein(s1: str, s2: str) -> int:
    """Fast Levenshtein (edit) distance."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[len(s2)]


def _has_brand_impersonation(host: str) -> int:
    """
    1 if host contains a known brand name in a deceptive manner, but is NOT the brand's official domain.
    Correctly recognizes international ccTLDs (e.g. amazon.in, google.co.uk, paypal.ca) as official brand domains.
    """
    h = host.lower().replace("www.", "").split(":")[0]
    parts = h.split(".")
    
    # If the domain is exactly brand.tld or brand.co.tld (e.g. amazon.in, google.co.uk),
    # this is an authentic regional brand domain, not impersonation.
    if len(parts) >= 2:
        sld = parts[-2]
        tld = parts[-1]
        # Handle compound country codes (e.g. .co.in, .co.uk)
        if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov", "edu"):
            sld = parts[-3]
            tld = f"{parts[-2]}.{parts[-1]}"
            
        if sld in _KNOWN_BRANDS and (tld in SAFE_TLDS or any(tld.endswith("." + st) for st in SAFE_TLDS)):
            return 0

    for brand, official_domains in _BRAND_OFFICIAL_TLDS.items():
        if brand in h:
            # Check if it's explicitly listed in official domains
            if any(h == od or h.endswith("." + od) for od in official_domains):
                return 0
            # If the brand is the exact apex SLD (e.g. paypal.de), it is valid
            if len(parts) >= 2 and parts[-2] == brand:
                return 0
            # Otherwise, the brand is inside a subdomain or compounded name (e.g. paypal-security.xyz or amazon.login-verify.com)
            return 1
    return 0


def _has_typosquatting(host: str) -> int:
    """1 if any subdomain or SLD (or hyphenated token) is within edit distance 2 of a known brand."""
    h = host.lower().replace("www.", "").split(":")[0]
    parts = h.split(".")
    
    # If the domain is an official brand apex or sub-service (e.g. mail.google.com, docs.google.com),
    # check apex SLD first. If apex domain belongs to an official brand, subdomains should not trigger
    # false-positive typosquatting against that same brand or brand services.
    apex_sld = parts[-2] if len(parts) >= 2 else h
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov", "edu"):
        apex_sld = parts[-3]

    candidates = parts[:-1] if len(parts) > 1 else parts  # exclude TLD
    
    # Also split candidates by hyphen so 'paypa1-security-check' inspects 'paypa1'
    all_tokens = list(candidates)
    for c in candidates:
        if "-" in c:
            all_tokens.extend(c.split("-"))

    # Common official utility subdomains that resemble brand names (e.g. mail vs gmail)
    common_subdomain_whitelist = {"mail", "docs", "drive", "cloud", "api", "auth", "login", "pay", "news", "shop", "app", "dev", "support"}

    for sld in all_tokens:
        if len(sld) < 3 or sld in common_subdomain_whitelist:
            continue
        # Don't flag if sld is the official apex brand itself
        if sld == apex_sld and apex_sld in _KNOWN_BRANDS:
            continue
        for brand in _KNOWN_BRANDS:
            # If the candidate token is under the brand's own apex domain, do not flag typosquatting
            if apex_sld == brand:
                continue
            if len(brand) > 3 and abs(len(sld) - len(brand)) <= 2:
                dist = _levenshtein(sld, brand)
                if dist == 1 and sld != brand:
                    return 1
                elif dist == 2 and sld != brand:
                    # For distance 2, distinguish intentional leetspeak (e.g. p4yp4l, amaz0n) or transposed adjacent chars
                    # from completely legitimate distinct root words with compound suffixes (e.g. amizone ending in 'zone')
                    if any(c.isdigit() for c in sld):
                        return 1
                    # Legitimate distinct morphemic endings (e.g. 'amizone', 'gamezone', 'technoland')
                    if any(sld.endswith(suf) for suf in ("zone", "land", "world", "space", "base", "cast", "flow")):
                        continue
                    return 1
    return 0


def _has_homograph_chars(host: str) -> int:
    """1 if host contains Unicode lookalike characters (homograph attack)."""
    for ch in host:
        if ord(ch) > 127:
            try:
                name = unicodedata.name(ch, "")
                if any(w in name for w in ("LATIN", "CYRILLIC", "GREEK")):
                    return 1
            except Exception:
                return 1
    return 0


def _has_compound_tld(host: str) -> int:
    """1 if host uses suspicious compound TLD patterns like .com.co, .net.ru."""
    suspicious = {
        "com.co", "net.ru", "com.ng", "org.ru", "net.in",
        "com.pk", "co.in", "com.vn", "com.br"
    }
    for st in suspicious:
        if host.endswith("." + st):
            return 1
    return 0


def _vowel_consonant_ratio(s: str) -> float:
    """Computes ratio of vowels to consonants in a string (e.g. domain name)."""
    s_alpha = [c.lower() for c in s if c.isalpha()]
    if not s_alpha:
        return 0.0
    vowels = sum(1 for c in s_alpha if c in "aeiou")
    consonants = len(s_alpha) - vowels
    return round(vowels / (consonants + 1e-5), 4)


def _max_consecutive_run(s: str) -> int:
    """Finds the maximum length of repeated consecutive identical characters."""
    if not s:
        return 0
    max_run = 1
    cur_run = 1
    for i in range(1, len(s)):
        if s[i] == s[i - 1]:
            cur_run += 1
            if cur_run > max_run:
                max_run = cur_run
        else:
            cur_run = 1
    return max_run


def extract_url_features(url: str) -> dict:
    """Extract URL-level features from a raw URL string."""
    if not url or not isinstance(url, str):
        return {}
    url = url.strip()
    try:
        parsed = urlparse(url)
        # If netloc is empty (bare domain without scheme), add https:// for
        # structural parsing only. The original url string is still used for
        # length, entropy, and ratio features so those stay accurate.
        if not parsed.netloc:
            parsed = urlparse("https://" + url)
    except Exception:
        return {}

    full_url  = url
    scheme    = parsed.scheme.lower()
    netloc    = parsed.netloc or ""
    path      = parsed.path or ""
    query     = parsed.query or ""
    fragment  = parsed.fragment or ""

    host       = netloc.split(":")[0] if ":" in netloc else netloc
    parts      = host.split(".")
    tld        = parts[-1].lower() if parts else ""
    domain     = ".".join(parts[-2:]) if len(parts) >= 2 else host
    subdomains = parts[:-2] if len(parts) > 2 else []

    query_params = parse_qs(query)

    letters = re.findall(r"[a-zA-Z]", full_url)
    digits  = re.findall(r"[0-9]", full_url)
    special = re.findall(r"[^a-zA-Z0-9]", full_url)
    url_len = len(full_url)

    domain_lower = domain.lower()
    # Use the SLD (second-level domain name without TLD) for digit analysis
    domain_name   = parts[-2].lower() if len(parts) >= 2 else host.lower()
    domain_digits = re.findall(r"[0-9]", domain_name)

    features = {
        # ── Core URL Structure ─────────────────────────────────────────────
        "URLLength":                  url_len,
        "NoOfLettersInURL":           len(letters),
        "LetterRatioInURL":           round(len(letters) / url_len, 6) if url_len > 0 else 0,
        "NoOfDegitsInURL":            len(digits),
        "DegitRatioInURL":            round(len(digits) / url_len, 6) if url_len > 0 else 0,
        "NoOfEqualsInURL":            full_url.count("="),
        "NoOfQMarkInURL":             full_url.count("?"),
        "NoOfAmpersandInURL":         full_url.count("&"),
        "NoOfOtherSpecialCharsInURL": len(re.findall(r"[^a-zA-Z0-9=?&:/.\\-]", full_url)),
        "SpacialCharRatioInURL":      round(len(special) / url_len, 6) if url_len > 0 else 0,
        "HasObfuscation":             1 if ("%" in full_url or "//" in path) else 0,
        "NoOfObfuscatedChar":         full_url.count("%"),
        "ObfuscationRatio":           round(full_url.count("%") / url_len, 6) if url_len > 0 else 0,
        "DomainLength":               len(domain),
        "IsDomainIP":                 1 if _is_ip_address(host) else 0,
        "TLDLength":                  len(tld),
        "NoOfSubDomain":              len(subdomains),
        "IsHTTPS":                    1 if scheme == "https" else 0,
        "URLEntropy":                 _shannon_entropy(full_url),
        "PathLength":                 len(path),
        "QueryLength":                len(query),
        "FragmentLength":             len(fragment),
        "NoOfQueryParams":            len(query_params),
    }

    # ── Semantic Keyword Features ─────────────────────────────────────────
    url_lower = full_url.lower()

    features["HasShopKeyword"]   = 1 if any(w in url_lower for w in
        ["shop", "store", "buy", "sale", "deal", "order", "market", "outlet"]) else 0
    features["HasBrandKeyword"]  = 1 if any(w in url_lower for w in
        ["official", "authentic", "genuine", "original", "brand"]) else 0
    features["HasInvestKeyword"] = 1 if any(w in url_lower for w in
        ["invest", "trade", "trading", "profit", "capital", "forex", "fund"]) else 0
    features["HasCryptoKeyword"] = 1 if any(w in url_lower for w in
        ["crypto", "bitcoin", "btc", "coin", "token", "wallet", "mining", "nft"]) else 0
    features["HasPhishKeyword"]  = 1 if any(w in url_lower for w in
        ["login", "signin", "verify", "secure", "update", "confirm", "account", "password"]) else 0

    # ── Structural Heuristics ─────────────────────────────────────────────
    features["NoOfHyphensInDomain"] = domain_lower.count("-")
    features["HasSuspiciousTLD"]    = 1 if tld in {
        "xyz", "top", "club", "work", "buzz", "tk", "ml", "ga", "cf", "gq",
        "icu", "live", "click", "info", "online", "site", "fun", "space",
        "shop", "store", "vip", "bid", "loan", "win"
    } else 0

    # ── NEW Phase 3: Advanced Scam Detection Features ─────────────────────

    # 1. Brand Impersonation — host contains "paypal", "amazon", etc.
    #    but is NOT the official domain → strong scam/phishing signal
    features["HasBrandImpersonation"] = _has_brand_impersonation(host)

    # 2. Typosquatting — any part of host is ≤ 2 edits from a known brand
    #    e.g. "arnazon.com", "paypa1.com" → catches keyboard-swap attacks
    features["HasTyposquatting"] = _has_typosquatting(host)

    # 3. Homograph Attack — Unicode lookalike chars in domain
    #    e.g. Cyrillic 'а' replacing Latin 'a' — visually identical
    features["HasHomographChar"] = _has_homograph_chars(host)

    # 4. Compound TLD — suspicious double TLDs like .com.co, .net.ru
    #    used to geo-spoof official-looking domains
    features["HasCompoundTLD"] = _has_compound_tld(host)

    # 5. Domain Digit Ratio — high digit density = likely auto-generated domain
    #    e.g. "a3b7x92.shop" vs "amazon.com"
    features["DomainDigitRatio"] = (
        round(len(domain_digits) / len(domain_name), 6) if domain_name else 0
    )

    # 6. Subdomain Depth — many subdomains = likely subdomain abuse
    #    e.g. "secure.paypal.com.evil.xyz" has depth 4
    features["SubdomainDepth"] = len(subdomains)

    # ── Phase 5: Lexical & Entropy Enrichment ────────────────────────────
    # 7. Domain Entropy — high entropy signals DGA (Domain Generation Algorithms)
    features["DomainEntropy"] = _shannon_entropy(domain_name)

    # 8. Path Entropy — high entropy in paths indicates random tokens/session hashes
    features["PathEntropy"] = _shannon_entropy(path)

    # 9. Vowel to Consonant Ratio — abnormal ratios signal auto-generated gibberish
    features["VowelConsonantRatio"] = _vowel_consonant_ratio(domain_name)

    # 10. Max Consecutive Repeated Characters — e.g. "gooogleee", "free-moneyyyyy"
    features["MaxConsecutiveCharRun"] = _max_consecutive_run(full_url)

    return features


def get_live_feature_names() -> list:
    sample = extract_url_features("https://example.com/path?q=1")
    return list(sample.keys())
