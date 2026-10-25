from __future__ import annotations

from website_trust_assessment import knowledge


def test_knowledge_files_load() -> None:
    assert len(knowledge.brands()) > 50
    assert len(knowledge.tracker_defs()[0]) > 10
    assert len(knowledge.dark_pattern_defs()) > 5
    assert knowledge.tld_data()["suspicious_tlds"]


def test_payment_processors_cover_all_domains() -> None:
    domains = knowledge.payment_processor_domains()
    assert "stripe.com" in domains
    assert "paypal.com" in domains
    assert len(domains) >= 20
    assert len(domains) == len(set(domains))


def test_trusted_checkout_matches_subdomains_only() -> None:
    assert knowledge.is_trusted_checkout("checkout.stripe.com")
    assert knowledge.is_trusted_checkout("stripe.com")
    assert not knowledge.is_trusted_checkout("stripe.com.example.org")
    assert not knowledge.is_trusted_checkout("notstripe.com")
