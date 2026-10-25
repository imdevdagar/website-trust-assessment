from __future__ import annotations

import asyncio

import pytest

from trustlens.security import (
    UnsafeURLError,
    check_request_url_sync,
    check_url_structure,
    is_public_ip,
    is_same_site,
    normalize_domain_list,
    normalize_url,
    sanitize_text,
    url_parts,
    validate_public_url,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Example.COM", "https://example.com/"),
        ("https://Example.COM:443/a?b=1#fragment", "https://example.com/a?b=1"),
        ("http://example.com:80", "http://example.com/"),
        ("http://example.com:443/", "http://example.com:443/"),
        ("https://BÜCHER.de/", "https://xn--bcher-kva.de/"),
        ("https://example.com./path", "https://example.com/path"),
        ("http://[::1]/", "http://[::1]/"),
        ("https://[2001:4860:4860::8888]:443/x", "https://[2001:4860:4860::8888]/x"),
    ],
)
def test_normalize_url_canonicalises(raw: str, expected: str) -> None:
    assert normalize_url(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "ftp://example.com/file",
        "javascript://example.com/%0aalert(1)",
        "https://user:secret@example.com/",
        "https://example.com:8443/",
        "https://example.com/has space",
        "https://example.com/\x00control",
        "https://example.com/" + "a" * 2048,
        None,
    ],
)
def test_normalize_url_rejects_unsafe_input(raw: object) -> None:
    with pytest.raises(UnsafeURLError):
        normalize_url(raw)  # type: ignore[arg-type]


def test_url_parts_extracts_registrable_domain_and_flags() -> None:
    parts = url_parts("https://login.accounts.example.co.uk/path?x=1")
    assert parts.host == "login.accounts.example.co.uk"
    assert parts.registrable_domain == "example.co.uk"
    assert parts.path == "/path?x=1"
    assert parts.port == 443
    assert parts.is_ip is False
    assert parts.is_punycode is False

    literals = url_parts("https://[2001:4860:4860::8888]/")
    assert literals.is_ip is True
    assert literals.host == "2001:4860:4860::8888"

    punycode = url_parts("https://xn--bcher-kva.de/")
    assert punycode.is_punycode is True
    assert punycode.registrable_domain == "xn--bcher-kva.de"


@pytest.mark.parametrize(
    "raw",
    [
        "http://localhost/",
        "http://localhost.localdomain/",
        "http://printer.local/",
        "http://service.internal/",
        "http://metadata.google.internal/",
        "http://127.0.0.1/",
        "http://10.0.0.5/",
        "http://172.16.4.2/",
        "http://192.168.1.10/",
        "http://169.254.169.254/latest/meta-data/",
        "http://100.64.0.1/",
        "http://198.18.0.1/",
        "http://224.0.0.1/",
        "http://0.0.0.0/",
        "http://[::1]/",
        "http://[fc00::1]/",
        "http://[fe80::1]/",
    ],
)
def test_check_url_structure_blocks_local_targets(raw: str) -> None:
    with pytest.raises(UnsafeURLError):
        check_url_structure(raw)


@pytest.mark.parametrize(
    "address",
    ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888", "[8.8.8.8]"],
)
def test_is_public_ip_accepts_global_addresses(address: str) -> None:
    assert is_public_ip(address) is True


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.1.2.3",
        "192.168.0.1",
        "169.254.169.254",
        "::1",
        "fc00::1",
        "224.0.0.1",
        "not-an-ip",
        "",
    ],
)
def test_is_public_ip_rejects_non_public_values(address: str) -> None:
    assert is_public_ip(address) is False


def test_same_site_uses_registrable_domain() -> None:
    assert is_same_site("https://a.example.co.uk/x", "https://b.example.co.uk/y") is True
    assert is_same_site("https://example.com/", "https://example.org/") is False
    assert is_same_site("javascript:alert(1)", "https://example.com/") is False


def test_registrable_domain_uses_bundled_multilabel_suffixes() -> None:
    assert url_parts("https://www.hdfc.bank.in/").registrable_domain == "hdfc.bank.in"
    assert url_parts("https://www.icici.bank.in/").registrable_domain == "icici.bank.in"
    assert is_same_site("https://hdfc.bank.in/", "https://netbanking.hdfc.bank.in/") is True
    assert is_same_site("https://hdfc.bank.in/", "https://icici.bank.in/") is False


def test_validate_public_url_allows_public_ip_literals() -> None:
    parts = asyncio.run(validate_public_url("https://[2001:4860:4860::8888]/"))
    assert parts.host == "2001:4860:4860::8888"

    with pytest.raises(UnsafeURLError):
        asyncio.run(validate_public_url("http://127.0.0.1/"))


def test_request_guard_checks_scheme_credentials_ports_and_addresses() -> None:
    assert check_request_url_sync("https://8.8.8.8/x") == ("8.8.8.8", "https")

    for raw in (
        "file:///etc/passwd",
        "data:text/html,hello",
        "https://user:pass@8.8.8.8/",
        "https://8.8.8.8:8443/",
        "http://localhost/",
        "http://127.0.0.1/",
        "https://[::1]/",
    ):
        with pytest.raises(UnsafeURLError):
            check_request_url_sync(raw)


def test_sanitize_text_strips_control_characters_and_truncates() -> None:
    cleaned = sanitize_text("a\x00b\t c\n\n\n\nd  ", max_chars=8)
    assert cleaned == "a b c\n\nd"
    assert sanitize_text("", max_chars=10) == ""


def test_normalize_domain_list_deduplicates_and_filters() -> None:
    values = ["Example.com", "example.com.", "bad domain", "", "*.foo.com"]
    assert normalize_domain_list(values) == ["example.com", "*.foo.com"]
