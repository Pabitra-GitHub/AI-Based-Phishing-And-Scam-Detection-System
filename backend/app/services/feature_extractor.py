"""
PhishGuard AI - Feature Extractor Service
Extracts lexical, structural, and host-based indicators for ML and rule evaluation.
"""

import math
import re
import urllib.parse
from typing import Dict, Any, List
from backend.app.services.url_validator import (
    check_dns_resolution,
    inspect_ssl_certificate,
    inspect_http_endpoint,
)

SUSPICIOUS_TLDS = {
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "top",
    "xyz",
    "click",
    "buzz",
    "fit",
    "surf",
    "rest",
    "bid",
    "work",
    "date",
    "faith",
    "men",
    "loan",
    "stream",
    "download",
    "racing",
    "review",
    "accountant",
    "science",
    "party",
    "gdn",
    "icu",
    "cam",
}

BRAND_KEYWORDS = [
    "paypal",
    "apple",
    "google",
    "microsoft",
    "amazon",
    "netflix",
    "facebook",
    "instagram",
    "whatsapp",
    "bank",
    "secure",
    "login",
    "account",
    "verify",
    "update",
    "signin",
    "support",
    "wallet",
    "service",
    "chase",
    "wellsfargo",
    "coinbase",
    "binance",
    "metamask",
    "security",
    "recovery",
    "password",
    "credential",
    "billing",
    "authorize",
    "validation",
]

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "buff.ly",
    "ow.ly",
    "cutt.ly",
    "bitly.com",
    "shorturl.at",
    "tiny.cc",
    "rebrand.ly",
    "tr.im",
}

IPV4_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

FEATURE_COLUMNS: List[str] = [
    "url_length",
    "domain_length",
    "path_length",
    "query_length",
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_slashes",
    "num_question_marks",
    "num_equals",
    "num_at_symbols",
    "num_percent",
    "num_ampersands",
    "num_digits",
    "num_subdomains",
    "has_ip_address",
    "is_https",
    "has_suspicious_tld",
    "has_brand_keyword",
    "has_punycode",
    "is_shortened",
    "domain_entropy",
]


def calculate_entropy(text: str) -> float:
    """Calculate the Shannon entropy of a given string."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return round(entropy, 4)


def extract_features(url: str, check_network: bool = True) -> Dict[str, Any]:
    """
    Extracts all 22 deterministic features from a URL string and performs
    live host verification including DNS lookup, SSL certificate check, and HTTP security header analysis.
    """
    url = url.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        parsed = urllib.parse.urlparse("http://" + url)
    else:
        parsed = urllib.parse.urlparse(url)

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    scheme = parsed.scheme.lower()
    is_https = 1 if scheme == "https" else 0

    # Subdomains calculation
    domain_parts = hostname.split(".")
    if len(domain_parts) > 2:
        num_subdomains = len(domain_parts) - 2
    else:
        num_subdomains = 0

    # TLD check
    tld = domain_parts[-1] if domain_parts else ""
    has_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    # IP address check (IPv4 or IPv6)
    try:
        import ipaddress
        ipaddress.ip_address(hostname.strip("[]"))
        has_ip = 1
    except Exception:
        has_ip = 1 if IPV4_PATTERN.match(hostname) else 0

    # Brand keywords in domain or path
    full_url_lower = url.lower()
    found_brands = [b for b in BRAND_KEYWORDS if b in full_url_lower]
    has_brand = 1 if found_brands else 0

    # Punycode / IDN (ASCII encoded xn-- prefix or raw Unicode non-ASCII)
    has_punycode = 1 if ("xn--" in hostname or any(ord(c) > 127 for c in hostname)) else 0

    # Shortener check
    is_shortened = 1 if hostname in SHORTENER_DOMAINS else 0

    # Domain entropy
    entropy = calculate_entropy(hostname)

    # Digit count across full URL
    num_digits = sum(1 for c in url if c.isdigit())

    # 1. Live DNS resolution check
    dns_resolvable = 1
    resolved_ip = None
    if check_network and hostname:
        is_res, ip = check_dns_resolution(hostname)
        dns_resolvable = 1 if is_res else 0
        resolved_ip = ip

    # 2. Live SSL certificate inspection (for HTTPS or resolvable hosts)
    ssl_valid = 1 if is_https else 0
    ssl_version = None
    ssl_issuer = None
    ssl_days_left = None
    ssl_error = None
    if check_network and hostname and is_https and dns_resolvable:
        ssl_info = inspect_ssl_certificate(hostname)
        ssl_valid = 1 if ssl_info["ssl_valid"] else 0
        ssl_version = ssl_info["ssl_version"]
        ssl_issuer = ssl_info["ssl_issuer"]
        ssl_days_left = ssl_info["ssl_days_left"]
        ssl_error = ssl_info["ssl_error"]

    # 3. Live HTTP endpoint & Security Header inspection
    http_status = None
    final_url = url
    is_redirected = 0
    is_cross_domain_redirect = 0
    has_hsts = 0
    has_x_frame_options = 0
    has_csp = 0
    has_x_content_type_options = 0
    server_banner = "Protected / Hidden"

    if check_network and hostname and dns_resolvable:
        http_info = inspect_http_endpoint(url)
        http_status = http_info.get("http_status")
        final_url = http_info.get("final_url", url)
        is_redirected = 1 if http_info.get("is_redirected") else 0
        is_cross_domain_redirect = 1 if http_info.get("is_cross_domain_redirect") else 0
        has_hsts = 1 if http_info.get("has_hsts") else 0
        has_x_frame_options = 1 if http_info.get("has_x_frame_options") else 0
        has_csp = 1 if http_info.get("has_csp") else 0
        has_x_content_type_options = (
            1 if http_info.get("has_x_content_type_options") else 0
        )
        server_banner = http_info.get("server_banner", "Protected / Hidden")

    features = {
        "url_length": len(url),
        "domain_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_underscores": url.count("_"),
        "num_slashes": url.count("/"),
        "num_question_marks": url.count("?"),
        "num_equals": url.count("="),
        "num_at_symbols": url.count("@"),
        "num_percent": url.count("%"),
        "num_ampersands": url.count("&"),
        "num_digits": num_digits,
        "num_subdomains": num_subdomains,
        "has_ip_address": has_ip,
        "is_https": is_https,
        "has_suspicious_tld": has_suspicious_tld,
        "has_brand_keyword": has_brand,
        "has_punycode": has_punycode,
        "is_shortened": is_shortened,
        "domain_entropy": entropy,
        # Deep inspection metadata extras
        "dns_resolvable": dns_resolvable,
        "resolved_ip": resolved_ip,
        "ssl_valid": ssl_valid,
        "ssl_version": ssl_version,
        "ssl_issuer": ssl_issuer,
        "ssl_days_left": ssl_days_left,
        "ssl_error": ssl_error,
        "http_status": http_status,
        "final_url": final_url,
        "is_redirected": is_redirected,
        "is_cross_domain_redirect": is_cross_domain_redirect,
        "has_hsts": has_hsts,
        "has_x_frame_options": has_x_frame_options,
        "has_csp": has_csp,
        "has_x_content_type_options": has_x_content_type_options,
        "server_banner": server_banner,
        "detected_brands": found_brands,
        "detected_tld": tld,
        "hostname": hostname,
    }
    return features


def get_feature_vector(features: Dict[str, Any]) -> List[float]:
    """Convert feature dictionary to ordered numerical vector."""
    return [float(features.get(col, 0.0)) for col in FEATURE_COLUMNS]
