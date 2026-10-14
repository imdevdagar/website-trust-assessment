"""Tests for URL feature extraction."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from src.features.url_features import extract_url_features, get_live_feature_names


def test_basic_https_url():
    feats = extract_url_features("https://example.com/path?q=1")
    assert feats["IsHTTPS"] == 1
    assert feats["URLLength"] > 0
    assert "NoOfQMarkInURL" in feats
    assert feats["NoOfQMarkInURL"] == 1


def test_http_url():
    feats = extract_url_features("http://malicious.example.com/")
    assert feats["IsHTTPS"] == 0
    assert feats["NoOfSubDomain"] >= 1


def test_ip_address_url():
    feats = extract_url_features("http://192.168.1.1/admin")
    assert feats["IsDomainIP"] == 1


def test_empty_url():
    feats = extract_url_features("")
    assert feats == {}


def test_none_url():
    feats = extract_url_features(None)
    assert feats == {}


def test_url_without_scheme():
    feats = extract_url_features("example.com/path")
    assert isinstance(feats, dict)


def test_url_with_ampersand():
    feats = extract_url_features("https://example.com/page?a=1&b=2&c=3")
    assert feats["NoOfAmpersandInURL"] == 2
    assert feats["NoOfEqualsInURL"] == 3


def test_obfuscated_url():
    feats = extract_url_features("http://example.com/%61%64%6d%69%6e")
    assert feats["HasObfuscation"] == 1
    assert feats["NoOfObfuscatedChar"] >= 4


def test_subdomain_count():
    feats = extract_url_features("https://a.b.c.example.com/")
    assert feats["NoOfSubDomain"] == 3


def test_feature_names_consistent():
    names1 = get_live_feature_names()
    names2 = list(extract_url_features("https://test.com").keys())
    assert names1 == names2


def test_entropy_range():
    feats = extract_url_features("https://example.com/")
    assert 0 <= feats["URLEntropy"] <= 8  # bits


def test_letter_ratio_valid():
    feats = extract_url_features("https://example.com/path123")
    assert 0 <= feats["LetterRatioInURL"] <= 1
    assert 0 <= feats["DegitRatioInURL"] <= 1
