"""
PhishGuard AI - URL Validator Service
Provides robust static validation, normalization, and SSRF-safety checks.
"""

import ipaddress
import re
import socket
import ssl
import urllib.parse
from urllib.parse import urlparse
from typing import Tuple, Optional, Dict, Any


MAX_URL_LENGTH = 2048
PRIVATE_IP_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

# Standard domain name pattern: labels separated by dots, with a valid TLD (>=2 characters or punycode)
DOMAIN_NAME_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9-]{2,}$"
)


def is_valid_host_structure(hostname: str) -> bool:
    """
    Validates whether a hostname is a syntactically valid domain name,
    valid IPv4/IPv6 address, or localhost.
    """
    if not hostname or not isinstance(hostname, str):
        return False

    hostname = hostname.strip().lower()

    if hostname in ("localhost", "loopback"):
        return True

    # Check if it is a valid IP address
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass

    # Convert IDN / Punycode to ascii for validation
    try:
        ascii_host = hostname.encode("idna").decode("ascii")
    except Exception:
        return False

    parts = ascii_host.split(".")
    if len(parts) < 2:
        return False

    tld = parts[-1]
    # TLD must be at least 2 characters, not all digits, and contain only valid chars
    if len(tld) < 2 or tld.isdigit() or not re.match(r"^[a-zA-Z0-9-]+$", tld):
        return False

    return bool(DOMAIN_NAME_PATTERN.match(ascii_host))


def check_dns_resolution(hostname: str, timeout: float = 1.5) -> Tuple[bool, Optional[str]]:
    """
    Performs a fast DNS lookup to check whether the destination host actually exists.
    Returns:
        (is_resolvable: bool, resolved_ip: Optional[str])
    """
    if not hostname:
        return False, None

    clean_host = hostname.strip().lower()

    if clean_host in ("localhost", "loopback"):
        return True, "127.0.0.1"

    try:
        ipaddress.ip_address(clean_host)
        return True, clean_host
    except ValueError:
        pass

    try:
        original_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            addr_info = socket.getaddrinfo(clean_host, 80, socket.AF_UNSPEC, socket.SOCK_STREAM)
            if addr_info:
                ip = str(addr_info[0][4][0])
                return True, ip
        finally:
            socket.setdefaulttimeout(original_timeout)
    except (socket.gaierror, socket.herror, socket.timeout, OSError, Exception):
        return False, None

    return False, None


def inspect_ssl_certificate(hostname: str, port: int = 443, timeout: float = 1.8) -> Dict[str, Any]:
    """
    Performs active SSL/TLS handshake to inspect certificate validity, issuer, and expiration.
    """
    if not hostname or hostname.lower() in ("localhost", "127.0.0.1", "0.0.0.0"):
        return {
            "ssl_valid": True,
            "ssl_version": "TLS (Localhost)",
            "ssl_issuer": "Local Development",
            "ssl_days_left": 365,
            "ssl_error": None
        }

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                raw_cert = ssock.getpeercert()
                if not isinstance(raw_cert, dict):
                    raise ssl.SSLError("Peer did not provide a certificate.")
                cert: Dict[str, Any] = raw_cert
                version = ssock.version()

                # Calculate expiration
                not_after_str = cert.get("notAfter")
                days_left = None
                if isinstance(not_after_str, str):
                    try:
                        from datetime import datetime, timezone
                        expires = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        days_left = (expires - datetime.now(timezone.utc)).days
                    except Exception:
                        pass

                # Parse issuer
                issuer_dict = _certificate_name_fields(cert.get("issuer"))
                issuer = (
                    issuer_dict.get("organizationName")
                    or issuer_dict.get("commonName")
                    or "Trusted Certificate Authority"
                )

                return {
                    "ssl_valid": True,
                    "ssl_version": version,
                    "ssl_issuer": issuer,
                    "ssl_days_left": days_left,
                    "ssl_error": None
                }
    except Exception as e:
        return {
            "ssl_valid": False,
            "ssl_version": None,
            "ssl_issuer": None,
            "ssl_days_left": None,
            "ssl_error": str(e)
        }


def _certificate_name_fields(name: Any) -> Dict[str, str]:
    """Extract string-valued fields from the nested structure returned by ssl."""
    fields: Dict[str, str] = {}
    if not isinstance(name, (list, tuple)):
        return fields
    for relative_name in name:
        if not isinstance(relative_name, (list, tuple)):
            continue
        for attribute in relative_name:
            if (
                isinstance(attribute, (list, tuple))
                and len(attribute) == 2
                and isinstance(attribute[0], str)
                and isinstance(attribute[1], str)
            ):
                fields[attribute[0]] = attribute[1]
    return fields


def inspect_http_endpoint(url: str, timeout: float = 2.0) -> Dict[str, Any]:
    """
    Performs live HTTP endpoint inspection checking status code, redirect chains, and security headers.
    """
    import urllib.request

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishGuardAI-ThreatScanner/1.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = resp.headers
            status_code = resp.status
            final_url = resp.geturl()
            server_hdr = headers.get("Server", "")

            # Security headers check
            has_hsts = "Strict-Transport-Security" in headers
            has_x_frame = "X-Frame-Options" in headers
            has_csp = "Content-Security-Policy" in headers
            has_x_content_type = "X-Content-Type-Options" in headers

            # Check if redirected to different domain
            orig_host = urlparse(url).hostname or ""
            final_host = urlparse(final_url).hostname or ""
            is_cross_domain_redirect = (
                bool(orig_host and final_host) and
                orig_host.lower().lstrip("www.") != final_host.lower().lstrip("www.")
            )

            return {
                "http_status": status_code,
                "final_url": final_url,
                "is_redirected": final_url.rstrip("/") != url.rstrip("/"),
                "is_cross_domain_redirect": is_cross_domain_redirect,
                "has_hsts": has_hsts,
                "has_x_frame_options": has_x_frame,
                "has_csp": has_csp,
                "has_x_content_type_options": has_x_content_type,
                "server_banner": server_hdr[:40] if server_hdr else "Protected / Hidden",
                "http_accessible": True,
                "http_error": None
            }
    except Exception as e:
        return {
            "http_status": None,
            "final_url": url,
            "is_redirected": False,
            "is_cross_domain_redirect": False,
            "has_hsts": False,
            "has_x_frame_options": False,
            "has_csp": False,
            "has_x_content_type_options": False,
            "server_banner": "N/A",
            "http_accessible": False,
            "http_error": str(e)
        }


def validate_and_normalize_url(raw_url: str) -> Tuple[bool, str, Optional[str]]:
    """
    Validates and normalizes user-submitted URL string.
    Returns:
        (is_valid: bool, normalized_url: str, error_message: Optional[str])
    """
    if not raw_url or not isinstance(raw_url, str):
        return False, "", "URL cannot be empty."

    url = raw_url.strip().strip("\"'<>`")

    # Normalize defanged indicators commonly used in security writeups
    url = re.sub(r"^hxxps://", "https://", url, flags=re.IGNORECASE)
    url = re.sub(r"^hxxp://", "http://", url, flags=re.IGNORECASE)
    url = url.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")

    if len(url) > MAX_URL_LENGTH:
        return False, "", f"URL exceeds maximum allowed length of {MAX_URL_LENGTH} characters."

    # Check if scheme is specified
    if "://" in url:
        scheme_part = url.split("://", 1)[0].lower()
        if scheme_part not in ("http", "https"):
            return False, "", f"Unsupported protocol scheme '{scheme_part}'. Only HTTP and HTTPS are supported."
    else:
        # Prepend scheme if missing for uniform parsing
        if url.startswith("//"):
            url = "http:" + url
        else:
            url = "http://" + url

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False, "", "Malformed URL structure."

    if parsed.scheme.lower() not in ("http", "https"):
        return False, "", f"Unsupported protocol scheme '{parsed.scheme}'. Only HTTP and HTTPS are supported."

    hostname = parsed.hostname
    if not hostname:
        return False, "", "URL must contain a valid domain name or IP address."

    # Validate host syntax (must be a valid domain structure with TLD, or valid IP / localhost)
    if not is_valid_host_structure(hostname):
        return False, "", "Invalid domain structure. URL must contain a valid domain name (e.g., example.com) or IP address."

    # Validate IDN / Punycode decoding
    try:
        decoded_host = hostname.encode("utf-8").decode("idna")
    except Exception:
        pass

    # Check for SSRF localhost / internal targets
    try:
        ip = ipaddress.ip_address(hostname)
        for net in PRIVATE_IP_RANGES:
            if ip in net:
                return True, url, "Warning: Destination is a private/internal network IP address."
    except ValueError:
        if hostname.lower() in ("localhost", "127.0.0.1", "0.0.0.0", "loopback"):
            return True, url, "Warning: Destination points to localhost loopback."

    # Reconstruct normalized canonical URL
    normalized = urllib.parse.urlunparse((
        parsed.scheme.lower(),
        hostname.lower() + (f":{parsed.port}" if parsed.port else ""),
        parsed.path or "/",
        parsed.params,
        parsed.query,
        parsed.fragment
    ))

    return True, normalized, None
