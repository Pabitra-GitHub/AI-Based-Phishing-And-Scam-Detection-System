"""
Unit tests for URL parsing parity and edge cases (Phase 3).
Tests:
- URL encoding
- IDN / punycode
- User-info (@ symbol)
- IPv4 and IPv6
- Unusual ports
- Shortened URLs
- Parity between training and inference extractors
"""

import pytest
from backend.app.services.feature_extractor import extract_features as backend_extract, FEATURE_COLUMNS
from ml.training.extract_features import extract_features_from_url as training_extract


SAMPLE_TEST_URLS = [
    # Clean standard URLs
    "https://www.google.com/search?q=cybersecurity",
    "https://apple.com/iphone",
    
    # URL encoding evasion
    "http://%70%61%79%70%61%6c.com/account/login",
    "http://example.com/path%20with%20spaces/test?token=%2e%2e",
    
    # IDN & Punycode
    "http://xn--pypal-4ve.com/account/login",
    "http://рaypal.com/verify",  # Cyrillic 'р'
    
    # User-info (@ symbol)
    "http://admin:password123@phishing-target.com/portal",
    "http://chase.com@evil-attacker-site.com/auth",
    
    # IPv4 and IPv6
    "http://192.168.1.100/admin/login.php",
    "http://45.33.32.156/bankofamerica/secure",
    "http://[2001:db8::1]/index.html",
    "http://[::1]:8080/test",
    
    # Unusual ports
    "http://banking-portal.com:8443/signin",
    "http://evil-server.net:2082/cpanel",
    
    # Shortened URLs
    "http://bit.ly/3xPh1shSecurityLogin",
    "https://tinyurl.com/bank-security-alert",
]


def test_training_and_inference_feature_parity():
    """Verify that training and backend extraction yield 100% identical feature vectors."""
    for url in SAMPLE_TEST_URLS:
        b_feats = backend_extract(url, check_network=False)
        t_feats = training_extract(url)

        for col in FEATURE_COLUMNS:
            assert b_feats[col] == t_feats[col], f"Mismatch on {col} for URL: {url}"


def test_ipv4_and_ipv6_detection():
    """Verify both IPv4 and IPv6 hosts set has_ip_address = 1."""
    ipv4_res = backend_extract("http://192.168.1.1/admin", check_network=False)
    assert ipv4_res["has_ip_address"] == 1

    ipv6_res = backend_extract("http://[2001:db8::1]/path", check_network=False)
    assert ipv6_res["has_ip_address"] == 1

    ipv6_local = backend_extract("http://[::1]:8080/test", check_network=False)
    assert ipv6_local["has_ip_address"] == 1

    normal_res = backend_extract("https://example.com/index.html", check_network=False)
    assert normal_res["has_ip_address"] == 0


def test_punycode_and_raw_idn_detection():
    """Verify punycode prefix (xn--) and raw unicode IDN trigger has_punycode = 1."""
    puny_res = backend_extract("http://xn--apple-43d.com/login", check_network=False)
    assert puny_res["has_punycode"] == 1

    raw_idn_res = backend_extract("http://рaypal.com/verify", check_network=False)
    assert raw_idn_res["has_punycode"] == 1

    clean_res = backend_extract("https://apple.com/store", check_network=False)
    assert clean_res["has_punycode"] == 0


def test_user_info_at_symbol_detection():
    """Verify @ symbol in authority or full URL is accurately extracted."""
    at_res = backend_extract("http://paypal.com@evil-attacker.com/login", check_network=False)
    assert at_res["num_at_symbols"] == 1

    multi_at = backend_extract("http://user:pass@evil.com/path?param=a@b", check_network=False)
    assert multi_at["num_at_symbols"] == 2


def test_url_encoding_brand_detection():
    """Verify URL-encoded brand names like %70%61%79%70%61%6c (paypal) trigger has_brand_keyword."""
    encoded_brand = backend_extract("http://%70%61%79%70%61%6c.com/login", check_network=False)
    assert encoded_brand["has_brand_keyword"] == 1
    assert encoded_brand["num_percent"] >= 1


def test_shortener_domains():
    """Verify known shorteners set is_shortened = 1."""
    bitly = backend_extract("http://bit.ly/urgent-login", check_network=False)
    assert bitly["is_shortened"] == 1

    tinyurl = backend_extract("https://tinyurl.com/update-now", check_network=False)
    assert tinyurl["is_shortened"] == 1

    regular = backend_extract("https://github.com/microsoft/vscode", check_network=False)
    assert regular["is_shortened"] == 0

