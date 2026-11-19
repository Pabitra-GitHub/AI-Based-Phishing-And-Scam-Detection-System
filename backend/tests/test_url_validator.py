"""
Unit tests for URL Validator Service (T008)
"""

from backend.app.services.url_validator import validate_and_normalize_url


def test_valid_https_url():
    valid, norm, err = validate_and_normalize_url("https://example.com/login?ref=1")
    assert valid is True
    assert norm == "https://example.com/login?ref=1"
    assert err is None


def test_schemeless_url_defaults_to_http():
    valid, norm, err = validate_and_normalize_url("paypal-verify.account.tk/signin")
    assert valid is True
    assert norm.startswith("http://")
    assert "paypal-verify.account.tk/signin" in norm


def test_empty_url_rejected():
    valid, norm, err = validate_and_normalize_url("")
    assert valid is False
    assert "empty" in (err or "").lower()


def test_unsupported_protocol_scheme():
    valid, norm, err = validate_and_normalize_url("ftp://files.example.com/archive.zip")
    assert valid is False
    assert "unsupported" in (err or "").lower()


def test_excessive_url_length_rejected():
    long_url = "https://example.com/" + "a" * 2500
    valid, norm, err = validate_and_normalize_url(long_url)
    assert valid is False
    assert "maximum allowed length" in (err or "").lower()


def test_private_ip_warning():
    valid, norm, err = validate_and_normalize_url("http://192.168.1.1/admin")
    assert valid is True
    assert err is not None
    assert "private/internal network" in err.lower()


def test_invalid_domain_structure_rejected():
    invalid_inputs = [
        "notareallink",
        "invalid_host",
        "http://foo..bar.com",
        "https://-invalid.com",
        "http://nodotstld"
    ]
    for inp in invalid_inputs:
        valid, _, err = validate_and_normalize_url(inp)
        assert valid is False, f"Expected {inp} to be rejected"
        assert "invalid domain structure" in (err or "").lower()
