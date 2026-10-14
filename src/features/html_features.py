import re
import math
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from difflib import SequenceMatcher

# Add headers to mimic a normal browser request
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
}

def extract_live_html_features(url: str, timeout: int = 5) -> dict:
    """
    Safely fetch the HTML of the URL and extract page-level features.
    If the fetch fails (timeout, 404, connection error), returns None.
    """
    if not url.startswith("http"):
        url = "http://" + url

    try:
        response = requests.get(url, headers=HEADERS, timeout=timeout, allow_redirects=True)
        response.raise_for_status()
    except Exception:
        # Site is offline or blocked us; return None to trigger fallback to URL-only mode
        return None

    html_content = response.text
    soup = BeautifulSoup(html_content, "html.parser")
    parsed_url = urlparse(response.url)
    domain = parsed_url.netloc.lower()

    # Basic HTML Line metrics
    lines = html_content.splitlines()
    line_of_code = len(lines)
    largest_line_length = max((len(line) for line in lines), default=0)

    # Title & Metadata
    title_tag = soup.find("title")
    title_text = title_tag.get_text(strip=True).lower() if title_tag else ""
    has_title = 1 if title_text else 0

    # Domain Title Match Score (approximate logic to match dataset 0-100 score)
    # E.g. domain="paypal.com", title="paypal login" -> high match
    domain_name = domain.replace("www.", "").split(".")[0].lower()
    if has_title and domain_name:
        match_score = SequenceMatcher(None, domain_name, title_text).ratio() * 100
    else:
        match_score = 0.0

    has_favicon = 1 if soup.find("link", rel=lambda r: r and "icon" in r.lower()) else 0
    has_description = 1 if soup.find("meta", attrs={"name": lambda n: n and n.lower() == "description"}) else 0
    robots = 1 if soup.find("meta", attrs={"name": lambda n: n and n.lower() == "robots"}) else 0
    is_responsive = 1 if soup.find("meta", attrs={"name": lambda n: n and n.lower() == "viewport"}) else 0

    # Redirects
    num_redirects = len(response.history)
    no_of_self_redirect = sum(1 for r in response.history if urlparse(r.url).netloc.lower() == domain)

    # Forms & Inputs
    forms = soup.find_all("form")
    has_external_form = 0
    for f in forms:
        action = f.get("action", "").strip()
        if action and not action.startswith("#") and not action.startswith("/"):
            act_domain = urlparse(action).netloc.lower()
            if act_domain and act_domain != domain:
                has_external_form = 1
                break

    has_submit_button = 1 if soup.find(["button", "input"], type=lambda t: t and t.lower() == "submit") else 0
    has_hidden_fields = 1 if soup.find("input", type=lambda t: t and t.lower() == "hidden") else 0
    has_password_field = 1 if soup.find("input", type=lambda t: t and t.lower() == "password") else 0

    # Links (Self, Empty, External)
    a_tags = soup.find_all("a", href=True)
    no_of_self_ref = 0
    no_of_empty_ref = 0
    no_of_external_ref = 0
    social_domains = ["facebook.com", "twitter.com", "instagram.com", "linkedin.com", "youtube.com"]
    has_social_net = 0

    for a in a_tags:
        href = a.get("href", "").strip()
        if href in ["", "#", "javascript:void(0)"]:
            no_of_empty_ref += 1
            continue
        
        href_parsed = urlparse(href)
        href_domain = href_parsed.netloc.lower()
        if not href_domain or href_domain == domain:
            no_of_self_ref += 1
        else:
            no_of_external_ref += 1
            if any(sd in href_domain for sd in social_domains):
                has_social_net = 1

    # Resources
    no_of_image = len(soup.find_all("img"))
    no_of_css = len(soup.find_all("link", rel=lambda r: r and "stylesheet" in (r.lower() if isinstance(r, str) else [x.lower() for x in r]))) + len(soup.find_all("style"))
    no_of_js = len(soup.find_all("script"))
    no_of_iframe = len(soup.find_all("iframe"))

    # Text Analysis (Keywords)
    text_content = soup.get_text(separator=" ").lower()
    bank = 1 if any(w in text_content for w in ["bank", "account", "login", "secure"]) else 0
    pay = 1 if any(w in text_content for w in ["pay", "checkout", "billing", "invoice"]) else 0
    crypto = 1 if any(w in text_content for w in ["crypto", "bitcoin", "wallet", "ethereum"]) else 0
    has_copyright = 1 if ("©" in text_content or "copyright" in text_content) else 0

    # Popups (heuristic: window.open in scripts)
    scripts_content = " ".join(s.string for s in soup.find_all("script") if s.string).lower()
    no_of_popup = scripts_content.count("window.open")

    features = {
        "LineOfCode": line_of_code,
        "LargestLineLength": largest_line_length,
        "HasTitle": has_title,
        "DomainTitleMatchScore": round(match_score, 2),
        "HasFavicon": has_favicon,
        "Robots": robots,
        "IsResponsive": is_responsive,
        "NoOfURLRedirect": num_redirects,
        "NoOfSelfRedirect": no_of_self_redirect,
        "HasDescription": has_description,
        "NoOfPopup": no_of_popup,
        "NoOfiFrame": no_of_iframe,
        "HasExternalFormSubmit": has_external_form,
        "HasSocialNet": has_social_net,
        "HasSubmitButton": has_submit_button,
        "HasHiddenFields": has_hidden_fields,
        "HasPasswordField": has_password_field,
        "Bank": bank,
        "Pay": pay,
        "Crypto": crypto,
        "HasCopyrightInfo": has_copyright,
        "NoOfImage": no_of_image,
        "NoOfCSS": no_of_css,
        "NoOfJS": no_of_js,
        "NoOfSelfRef": no_of_self_ref,
        "NoOfEmptyRef": no_of_empty_ref,
        "NoOfExternalRef": no_of_external_ref,
    }

    return features
