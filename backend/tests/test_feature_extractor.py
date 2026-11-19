"""
Unit tests for Feature Extractor (T009)
"""

from backend.app.services.feature_extractor import extract_features, calculate_entropy, FEATURE_COLUMNS


def test_feature_extractor_returns_all_columns():
    url = "https://www.google.com/search?q=security"
    feats = extract_features(url)
    for col in FEATURE_COLUMNS:
        assert col in feats, f"Missing expected feature column: {col}"


def test_ip_address_detection():
    url = "http://192.168.0.1/login.php"
    feats = extract_features(url)
    assert feats["has_ip_address"] == 1


def test_suspicious_tld_detection():
    url = "http://secure-login.tk/auth"
    feats = extract_features(url)
    assert feats["has_suspicious_tld"] == 1


def test_brand_keyword_detection():
    url = "http://paypal-verification-alert.xyz/signin"
    feats = extract_features(url)
    assert feats["has_brand_keyword"] == 1
    assert "paypal" in feats["detected_brands"]


def test_subdomain_counting():
    url = "http://service.auth.account.banking.example.com/login"
    feats = extract_features(url)
    assert feats["num_subdomains"] >= 3


def test_punycode_detection():
    url = "http://xn--apple-qqa.com/login"
    feats = extract_features(url)
    assert feats["has_punycode"] == 1


def test_shannon_entropy_calculation():
    low_entropy = calculate_entropy("aaaaaaa")
    high_entropy = calculate_entropy("x8q9z3w1p")
    assert high_entropy > low_entropy
