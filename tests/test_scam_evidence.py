from __future__ import annotations

import re
from typing import Any

from website_trust_assessment.config import settings
from website_trust_assessment.crawler import CrawlData, FormInfo
from website_trust_assessment.evidence import content
from website_trust_assessment.evidence.base import ScanContext
from website_trust_assessment.evidence.visual import OCR_SIGNALS
from website_trust_assessment.security import url_parts


def _context(
    text: str,
    *,
    domain: str = "scam.example",
    links: list[dict[str, Any]] | None = None,
    forms: list[FormInfo] | None = None,
) -> ScanContext:
    url = f"https://{domain}/"
    page = CrawlData(
        requested_url=url,
        final_url=url,
        domain=domain,
        title="Test page",
        visible_text=text,
        html="<html><body>test</body></html>",
        links=links or [],
        forms=forms or [],
    )
    return ScanContext(url=url, parts=url_parts(url), page=page, settings=settings())


def _codes(context: ScanContext) -> set[str]:
    return {item.code for item in content.extract(context)}


def test_guaranteed_investment_returns_are_flagged() -> None:
    text = (
        "Invest in our plan and earn guaranteed returns of 12% monthly. "
        "Double your money in 30 days."
    )
    assert "guaranteed_return_lure" in _codes(_context(text))


def test_guaranteed_return_signal_does_not_fire_on_official_domain() -> None:
    text = "Our savings plan offers guaranteed returns to eligible customers."
    assert "guaranteed_return_lure" not in _codes(
        _context(text, domain="www.microsoft.com")
    )


def test_advance_fee_is_flagged() -> None:
    text = (
        "Congratulations, you are selected for a work-from-home job. "
        "Pay a registration fee of Rs 2,500 to claim your position."
    )
    assert "advance_fee_lure" in _codes(_context(text))


def test_ordinary_delivery_fee_is_not_an_advance_fee_lure() -> None:
    text = "Delivery fee is calculated at checkout and shown before payment."
    assert "advance_fee_lure" not in _codes(_context(text))


def test_raw_upi_payment_is_flagged() -> None:
    text = "Pay the security deposit via UPI to scammer@oksbi before we release your parcel."
    assert "direct_upi_payment" in _codes(_context(text))


def test_plain_email_address_is_not_treated_as_upi() -> None:
    text = "Email support@example.com for help with your order."
    assert "direct_upi_payment" not in _codes(_context(text))


def test_direct_bank_transfer_with_pressure_is_flagged() -> None:
    text = (
        "Pay the customs clearance fee by NEFT to account number 1234567890, "
        "IFSC ABCD0123456, to release your parcel."
    )
    assert "direct_bank_transfer" in _codes(_context(text))


def test_bank_transfer_without_a_demand_is_not_flagged() -> None:
    text = "We accept bank transfer. Contact support for settlement details."
    assert "direct_bank_transfer" not in _codes(_context(text))


def test_messaging_only_contact_is_flagged() -> None:
    context = _context(
        "Contact us on WhatsApp for orders and support.",
        links=[{"href": "https://wa.me/919999999999", "text": "WhatsApp"}],
    )
    assert "messaging_only_contact" in _codes(context)


def test_messaging_contact_with_a_contact_page_is_not_flagged() -> None:
    context = _context(
        "Contact us on WhatsApp or through our contact page.",
        links=[
            {"href": "https://scam.example/contact", "text": "Contact us"},
            {"href": "https://wa.me/919999999999", "text": "WhatsApp"},
        ],
    )
    assert "messaging_only_contact" not in _codes(context)


def test_messaging_only_contact_fires_alongside_a_payment_form() -> None:
    text = "Contact us on Telegram to complete your order."
    context = _context(
        text,
        links=[{"href": "https://t.me/example", "text": "Telegram"}],
        forms=[FormInfo(has_card=True, has_cvv=True)],
    )
    evidence = {item.code: item for item in content.extract(context)}
    assert evidence["messaging_only_contact"].risk_points == 8.0


def test_new_ocr_signals_match_image_text() -> None:
    signals = {str(item["code"]): item for item in OCR_SIGNALS}
    guaranteed = signals["ocr_guaranteed_return"]["pattern"]
    upi = signals["ocr_upi_payment"]["pattern"]
    assert isinstance(guaranteed, re.Pattern)
    assert isinstance(upi, re.Pattern)
    assert guaranteed.search("Guaranteed 20% monthly returns") is not None
    assert upi.search("Scan the QR code to pay via UPI") is not None
    assert upi.search("Send payment to investor@oksbi") is not None
