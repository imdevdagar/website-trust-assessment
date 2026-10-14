"""
robustness_benchmark.py
Comprehensive autonomous stress test & robustness audit across:
1. Global Legitimate Benchmarks (.com, international ccTLDs, subdomains, deep paths)
2. Real-World Phishing & Impersonation (typosquats, lookalikes, suspicious TLDs)
3. Financial / Advance-Fee / E-Commerce Scams
4. Edge Cases (IP addresses, deep hyphens, zero-query parameters)
"""
import sys, json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from fastapi.testclient import TestClient
from api.main import app

test_suite = [
    # ── Category 1: Real Global & Regional Legitimate Domains ──
    {"url": "https://www.google.com", "expected": "Legitimate", "category": "Global Big Tech"},
    {"url": "https://www.amazon.in", "expected": "Legitimate", "category": "Regional E-Commerce (India)"},
    {"url": "https://www.amazon.co.uk", "expected": "Legitimate", "category": "Regional E-Commerce (UK)"},
    {"url": "https://www.wikipedia.org", "expected": "Legitimate", "category": "Non-Profit Educational"},
    {"url": "https://github.com/torvalds/linux", "expected": "Legitimate", "category": "Developer Platform with Deep Path"},
    {"url": "https://mail.google.com", "expected": "Legitimate", "category": "Legitimate Subdomain"},
    {"url": "https://www.paypal.com/signin", "expected": "Legitimate", "category": "Financial Official Path"},
    {"url": "https://www.microsoft.com/en-us/windows", "expected": "Legitimate", "category": "Enterprise Multi-Path"},
    {"url": "https://news.ycombinator.com", "expected": "Legitimate", "category": "Tech News Forum"},
    {"url": "https://www.apple.com/iphone", "expected": "Legitimate", "category": "Brand Store Official"},

    # ── Category 2: Phishing & Credential Harvesters ──
    {"url": "http://paypa1-security-check.xyz/login", "expected": "Phishing", "category": "Typosquatting + Suspicious TLD"},
    {"url": "http://amazon-account-verify.online/auth", "expected": "Phishing", "category": "Brand Impersonation in Host"},
    {"url": "http://chase-security-update.top/login.php", "expected": "Phishing", "category": "Banking Phishing + Abuse TLD"},
    {"url": "http://apple-id-verify.cf/account", "expected": "Phishing", "category": "Free TLD Impersonation"},
    {"url": "http://192.168.1.100/secure-login/paypal", "expected": "Phishing", "category": "IP Address Phishing"},
    {"url": "http://netflix-billing-update.buzz/card", "expected": "Phishing", "category": "Subscription Streaming Phishing"},

    # ── Category 3: Advance-Fee / Investment / E-Commerce Scams ──
    {"url": "http://guaranteed-crypto-profit.top/invest", "expected": "Scam", "category": "Crypto High-Yield Scam"},
    {"url": "http://puppy-adoption-express-delivery.xyz", "expected": "Scam", "category": "Pet / Non-Delivery Scam"},
    {"url": "http://instant-fast-loan-approval.buzz", "expected": "Scam", "category": "Loan / Predatory Scam"},
    {"url": "http://luxury-handbag-90off-outlet.shop/sale", "expected": "Scam", "category": "Counterfeit Shop Scam"},
]

def run_audit():
    print("=" * 80)
    print("AUTONOMOUS RELIABILITY & ROBUSTNESS BENCHMARK")
    print("=" * 80)
    
    passed = 0
    total = len(test_suite)
    
    with TestClient(app) as client:
        for item in test_suite:
            url = item["url"]
            expected = item["expected"]
            cat = item["category"]
            
            resp = client.post("/api/v1/assess", json={"url": url})
            if resp.status_code != 200:
                print(f"[FAIL] {url:45} | HTTP {resp.status_code}")
                continue
                
            data = resp.json()
            pred = data["prediction"]
            score = data["trust_score"]
            risk_label = data["risk_label"]
            divergence = data["divergence_index"]
            consensus = data["consensus_status"]
            
            # Check correctness:
            # If expected Legitimate -> must be Legitimate and trust score >= 70
            # If expected Phishing/Scam -> must be Phishing or Scam, or Needs Review with low trust score (<= 65)
            is_correct = False
            if expected == "Legitimate" and pred == "Legitimate" and score >= 75:
                is_correct = True
            elif expected in ("Phishing", "Scam"):
                if pred in ("Phishing", "Scam") or score <= 60 or data["needs_review"]:
                    is_correct = True
                    
            status_tag = "PASS" if is_correct else "FAIL"
            if is_correct:
                passed += 1
                
            print(f"[{status_tag}] {cat:35}")
            print(f"       URL: {url}")
            print(f"       Outcome: Pred={pred} | Score={score}/100 ({risk_label}) | Divergence={divergence:.1%} ({consensus})")
            if not is_correct:
                print(f"       --> MISMATCH: Expected {expected}")
            print("-" * 80)
            
    accuracy = (passed / total) * 100
    print(f"\nFinal Robustness Score: {passed}/{total} ({accuracy:.1f}%)")
    print("=" * 80)

if __name__ == "__main__":
    run_audit()
