"""
src/features/domain_features.py
Domain-level features requiring Whois lookups.
These are used ONLY during live inference (not during batch training,
as doing Whois on 280k URLs would take days).
"""
import re
import whois
from datetime import datetime, timezone
from urllib.parse import urlparse


def _safe_get_date(d):
    """Handle both single datetime and list of datetimes from whois."""
    if isinstance(d, list):
        d = d[0]
    if isinstance(d, datetime):
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d
    return None


def extract_domain_features(url: str) -> dict:
    """
    Extract domain-level features via Whois lookup.
    Returns a dict with domain age and registration signals.
    Falls back to neutral values if Whois lookup fails.
    """
    default = {
        "DomainAgeDays": -1,       # -1 means unknown
        "IsNewDomain": 0,           # 1 if domain is < 180 days old
        "IsVeryNewDomain": 0,       # 1 if domain is < 30 days old
        "WhoisAvailable": 0,        # 1 if we got valid Whois data
    }

    if not url or not isinstance(url, str):
        return default

    try:
        if not url.startswith("http"):
            url = "http://" + url
        parsed = urlparse(url)
        host = parsed.netloc.split(":")[0].replace("www.", "").lower()

        w = whois.whois(host)
        creation_date = _safe_get_date(w.creation_date)

        if creation_date is None:
            return default

        now = datetime.now(timezone.utc)
        age_days = (now - creation_date).days

        return {
            "DomainAgeDays": age_days,
            "IsNewDomain": 1 if age_days < 180 else 0,
            "IsVeryNewDomain": 1 if age_days < 30 else 0,
            "WhoisAvailable": 1,
        }

    except Exception:
        return default
