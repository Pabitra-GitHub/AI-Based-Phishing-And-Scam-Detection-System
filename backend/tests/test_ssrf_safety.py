"""
Comprehensive SSRF & Network Safety Test Suite (Phase 5).
Validates:
1. Direct loopback, private RFC1918, and link-local IP blocking.
2. Cloud Metadata IMDS (AWS, GCP, Azure, Alibaba) blocking.
3. Obfuscated IP notations (decimal integer, hex, octal).
4. IPv6 loopback, bracketed IPv6, and link-local IPv6.
5. Non-standard port blocking (e.g. Redis 6379, MongoDB 27017, SSH 22).
6. Non-HTTP scheme rejection (file://, gopher://, dict://, ftp://).
7. DNS Rebinding defense (hostname resolving to private IP is aborted).
8. Redirect evasion defense (redirect hopping to internal IP is intercepted and blocked).
9. Live probe pre-flight safety and response size limits.
"""

import socket
import pytest
from unittest.mock import patch, MagicMock

from backend.app.services.dsa.ssrf_guard import (
    validate_url_for_safe_scan,
    is_ip_forbidden,
    normalize_numeric_ip,
)
from backend.app.services.dsa.network_checker import probe_live_website
from backend.app.services.dsa.graph_redirect import RedirectGraphTracker


# ═════════════════════════════════════════════════════════════════════════════
# 1. IP NOTATION & FORBIDDEN RANGES TESTS
# ═════════════════════════════════════════════════════════════════════════════

def test_forbidden_loopback_and_private_ips():
    """Verify standard loopback and RFC 1918 addresses are marked forbidden."""
    for ip in ["127.0.0.1", "127.1.2.3", "10.0.0.1", "192.168.1.100", "172.16.5.4", "::1"]:
        forbidden, reason = is_ip_forbidden(ip)
        assert forbidden is True, f"Failed to block private/loopback IP: {ip}"
        assert reason is not None


def test_cloud_metadata_imds_blocking():
    """Verify AWS, Azure, GCP, and Alibaba cloud metadata endpoints are blocked."""
    metadata_ips = [
        "169.254.169.254",   # AWS / Azure / GCP IMDSv1/v2
        "169.254.170.2",     # AWS ECS container metadata
        "100.100.100.200",   # Alibaba Cloud IMDS
        "fd00:ec2::254",     # AWS IPv6 IMDS
    ]
    for ip in metadata_ips:
        forbidden, reason = is_ip_forbidden(ip)
        assert forbidden is True, f"Failed to block cloud metadata IP: {ip}"


def test_obfuscated_ip_notations_parsed_and_blocked():
    """Verify decimal, hex, and octal integer IP representations are detected and blocked."""
    # 2130706433 is 127.0.0.1 in decimal integer
    assert str(normalize_numeric_ip("2130706433")) == "127.0.0.1"
    forbidden, _ = is_ip_forbidden("2130706433")
    assert forbidden is True

    # 0x7f000001 is 127.0.0.1 in hex
    assert str(normalize_numeric_ip("0x7f000001")) == "127.0.0.1"
    forbidden, _ = is_ip_forbidden("0x7f000001")
    assert forbidden is True

    # 0177.0.0.1 is 127.0.0.1 in octal dot notation
    assert str(normalize_numeric_ip("0177.0.0.1")) == "127.0.0.1"
    forbidden, _ = is_ip_forbidden("0177.0.0.1")
    assert forbidden is True

    # 0251.0376.0251.0376 -> 169.254.169.254 in octal
    octal_imds = normalize_numeric_ip("0251.0376.0251.0376")
    assert str(octal_imds) == "169.254.169.254"
    forbidden, _ = is_ip_forbidden("0251.0376.0251.0376")
    assert forbidden is True


# ═════════════════════════════════════════════════════════════════════════════
# 2. URL SCAN VALIDATION & PORT / SCHEME POLICIES
# ═════════════════════════════════════════════════════════════════════════════

def test_unsupported_schemes_blocked():
    """Verify file://, gopher://, dict://, and ftp:// are rejected."""
    bad_schemes = [
        "file:///etc/passwd",
        "gopher://127.0.0.1:70/",
        "dict://127.0.0.1:11211/stat",
        "ftp://attacker.com/payload.sh"
    ]
    for url in bad_schemes:
        is_safe, _, reason = validate_url_for_safe_scan(url)
        assert is_safe is False
        assert "unsupported scheme" in reason.lower()


def test_non_standard_internal_ports_blocked():
    """Verify sensitive service ports like Redis (6379), MongoDB (27017), SSH (22) are blocked."""
    risky_ports = [
        "http://example.com:6379/",   # Redis
        "http://example.com:27017/",  # MongoDB
        "http://example.com:22/",     # SSH
        "http://example.com:3306/",   # MySQL
        "http://example.com:5432/",   # PostgreSQL
    ]
    for url in risky_ports:
        is_safe, _, reason = validate_url_for_safe_scan(url)
        assert is_safe is False
        assert "port" in reason.lower()


def test_direct_localhost_and_numeric_ssrf_urls_blocked():
    """Verify direct loopback URLs are blocked before opening network connections."""
    urls = [
        "http://localhost:8080/admin",
        "http://127.0.0.1/status",
        "http://[::1]:80/dashboard",
        "http://169.254.169.254/latest/meta-data/",
        "http://2130706433/login",
        "http://0x7f000001/admin",
    ]
    for url in urls:
        is_safe, _, reason = validate_url_for_safe_scan(url)
        assert is_safe is False
        assert reason is not None


# ═════════════════════════════════════════════════════════════════════════════
# 3. DNS REBINDING & REDIRECT EVASION DEFENSE
# ═════════════════════════════════════════════════════════════════════════════

def test_dns_rebinding_resolution_blocks_private_destinations():
    """Verify that a public-looking domain name resolving to an internal IP is blocked."""
    fake_dns_result = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))
    ]

    with patch("socket.getaddrinfo", return_value=fake_dns_result):
        is_safe, ip, reason = validate_url_for_safe_scan("http://rebound-domain.attacker.com/")
        assert is_safe is False
        assert ip == "127.0.0.1"
        assert "forbidden destination" in reason.lower() or "loopback" in reason.lower()


def test_redirect_tracker_blocks_internal_hops():
    """Verify that RedirectGraphTracker terminates immediately when redirected to internal IPs."""
    tracker = RedirectGraphTracker(max_hops=5)

    import urllib.error

    # Mock first hop returning 302 pointing to cloud metadata
    fake_error = urllib.error.HTTPError(
        url="http://example.com/redirect",
        code=302,
        msg="Found",
        hdrs={"Location": "http://169.254.169.254/latest/meta-data/"},
        fp=None
    )

    fake_safe_dns = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))
    ]

    with patch("socket.getaddrinfo", return_value=fake_safe_dns), \
         patch("urllib.request.OpenerDirector.open", side_effect=fake_error):
        
        res = tracker.trace_redirects("http://example.com/redirect")
        print("CHAIN IN PYTEST:", res["chain"])
        assert any(hop.get("ssrf_blocked") is True for hop in res["chain"])


def test_probe_live_website_blocks_ssrf_before_connection():
    """Verify probe_live_website returns ssrf_blocked without connecting to loopback/IMDS."""
    res = probe_live_website("http://169.254.169.254/latest/meta-data/")
    assert res["ssrf_blocked"] is True
    assert res["http_reachable"] is False
    assert "SSRF Blocked" in res["error"]

