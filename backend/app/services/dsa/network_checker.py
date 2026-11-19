"""
PhishGuard AI - DSA Module: Network & Cryptographic Verification
Performs fast, non-blocking network verification:
  - DNS resolution check
  - Active SSL/TLS certificate inspection (expiry, self-signed, issuer)
  - Security header checks (HSTS, CSP, X-Frame-Options)
"""

import ipaddress
import socket
import ssl
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple

from backend.app.services.dsa.ssrf_guard import validate_url_for_safe_scan, is_ip_forbidden


def check_dns_resolvability(hostname: str, timeout: float = 1.5) -> Tuple[bool, Optional[str]]:
    """
    Performs safe DNS resolution.
    Returns: (is_resolvable, resolved_ip)
    """
    if not hostname:
        return False, None

    clean_host = hostname.strip().lower()

    if clean_host in ("localhost", "loopback"):
        return True, "127.0.0.1"

    # If it is already an IP address
    try:
        ipaddress.ip_address(clean_host)
        return True, clean_host
    except ValueError:
        pass

    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            addr_info = socket.getaddrinfo(clean_host, 80, socket.AF_UNSPEC, socket.SOCK_STREAM)
            if addr_info:
                ip = str(addr_info[0][4][0])
                return True, ip
        finally:
            socket.setdefaulttimeout(old_timeout)
    except Exception:
        return False, None

    return False, None


def inspect_ssl_tls(hostname: str, port: int = 443, timeout: float = 1.8) -> Dict[str, Any]:
    """
    Performs an active SSL/TLS handshake to inspect certificate validity,
    issuer, expiration date, and self-signed status.
    """
    if not hostname or hostname.lower() in ("localhost", "127.0.0.1", "0.0.0.0"):
        return {
            "ssl_valid": True,
            "ssl_issuer": "Localhost Development",
            "ssl_version": "TLS",
            "days_left": 365,
            "is_self_signed": False,
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

                # Parse expiration
                not_after = cert.get("notAfter")
                days_left = None
                if isinstance(not_after, str):
                    try:
                        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
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

                # Check self-signed (issuer subject matches certificate subject)
                subject_dict = _certificate_name_fields(cert.get("subject"))
                is_self_signed = (issuer_dict == subject_dict and len(issuer_dict) > 0)

                return {
                    "ssl_valid": True,
                    "ssl_issuer": issuer,
                    "ssl_version": version,
                    "days_left": days_left,
                    "is_self_signed": is_self_signed,
                    "ssl_error": None
                }
    except ssl.SSLCertVerificationError as e:
        return {
            "ssl_valid": False,
            "ssl_issuer": None,
            "ssl_version": None,
            "days_left": None,
            "is_self_signed": "self-signed" in str(e).lower(),
            "ssl_error": f"Certificate Verification Failed: {str(e)[:100]}"
        }
    except Exception as e:
        return {
            "ssl_valid": False,
            "ssl_issuer": None,
            "ssl_version": None,
            "days_left": None,
            "is_self_signed": False,
            "ssl_error": str(e)[:100]
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


def check_security_headers(headers: Dict[str, str]) -> Dict[str, bool]:
    """Inspects response HTTP headers for defensive security directives."""
    lower_headers = {k.lower(): v for k, v in headers.items()}
    return {
        "has_hsts": "strict-transport-security" in lower_headers,
        "has_csp": "content-security-policy" in lower_headers,
        "has_x_frame_options": "x-frame-options" in lower_headers,
        "has_x_content_type_options": "x-content-type-options" in lower_headers
    }


def probe_live_website(url: str, timeout: float = 2.5) -> Dict[str, Any]:
    """
    Safely probes the destination website to inspect responsiveness,
    HTTP status code, HTML title, presence of password inputs, and server banner.
    """
    import re
    import urllib.request
    import urllib.error

    result = {
        "http_reachable": False,
        "http_status": None,
        "page_title": None,
        "has_password_input": False,
        "has_login_form": False,
        "server_banner": None,
        "content_type": None,
        "ssrf_blocked": False,
        "error": None
    }

    # SSRF Pre-flight verification (DNS rebinding, private ranges, cloud metadata)
    is_safe, resolved_ip, block_reason = validate_url_for_safe_scan(url, timeout=timeout)
    if not is_safe:
        result["ssrf_blocked"] = True
        result["error"] = f"SSRF Blocked: {block_reason}"
        return result

    try:
        class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        opener = urllib.request.build_opener(NoRedirectHandler)
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 PhishGuard/2.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            }
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # Probe even if self-signed to inspect title and harvest lures

        with opener.open(req, timeout=timeout) as resp:
            result["http_reachable"] = True
            result["http_status"] = resp.status
            result["server_banner"] = resp.headers.get("Server")
            result["content_type"] = resp.headers.get("Content-Type", "")

            # Read first 16KB to extract title and form fields safely
            raw_chunk = resp.read(16384)
            html_sample = raw_chunk.decode("utf-8", errors="ignore")

            # Extract title
            title_match = re.search(r"<title[^>]*>(.*?)</title>", html_sample, flags=re.IGNORECASE | re.DOTALL)
            if title_match:
                clean_title = re.sub(r"\s+", " ", title_match.group(1)).strip()
                result["page_title"] = clean_title[:120]

            # Detect password inputs & login forms
            lower_html = html_sample.lower()
            if 'type="password"' in lower_html or "type='password'" in lower_html:
                result["has_password_input"] = True
            if "<form" in lower_html and ("login" in lower_html or "signin" in lower_html or "password" in lower_html):
                result["has_login_form"] = True

    except urllib.error.HTTPError as e:
        result["http_reachable"] = True
        result["http_status"] = e.code
        result["error"] = f"HTTP {e.code}"
    except Exception as e:
        result["error"] = str(e)[:100]

    return result
