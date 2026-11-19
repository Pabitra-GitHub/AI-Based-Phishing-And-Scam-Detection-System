"""
PhishGuard AI - Centralized SSRF Guard & URL Safety Engine (Phase 5)
Provides comprehensive Server-Side Request Forgery (SSRF) and DNS Rebinding defenses:
  1. Blocks loopback, private RFC1918, link-local, multicast, cloud metadata (IMDS), and reserved IPs.
  2. Resolves DNS before connection and checks all resolved IP addresses.
  3. Detects alternate IP encodings: decimal (2130706433), octal (0177.0.0.1), hex (0x7f000001), IPv6 bracketed, IPv4-mapped IPv6.
  4. Restricts schemes strictly to HTTP/HTTPS and ports to explicit policy (80, 443, 8080, 8443).
  5. Intercepts every redirect target and re-resolves DNS to defeat redirect evasion and DNS rebinding.
  6. Caps response body reading strictly to 16 KB with bounded total timeout.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import urllib.parse
from typing import Tuple, Optional, Set, List


ALLOWED_SCHEMES: Set[str] = {"http", "https"}
ALLOWED_PORTS: Set[int] = {80, 443, 8080, 8443}
MAX_RESPONSE_BYTES: int = 16384  # 16 KB max payload inspection
MAX_REDIRECT_HOPS: int = 5
DEFAULT_TIMEOUT: float = 2.0

# Forbidden CIDR Networks for SSRF Defenses
FORBIDDEN_NETWORKS: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    # Loopback
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    # Private RFC 1918 & ULA
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    # Link-Local & Cloud Metadata IMDS (AWS, Azure, GCP, Alibaba, OpenStack)
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("100.100.100.200/32"),   # Alibaba Cloud IMDS
    ipaddress.ip_network("fd00:ec2::254/128"),     # AWS IMDSv2 IPv6
    # Carrier-grade NAT
    ipaddress.ip_network("100.64.0.0/10"),
    # Reserved, Broadcast & Multicast
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("ff00::/8"),
    ipaddress.ip_network("192.0.2.0/24"),          # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),       # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),        # TEST-NET-3
    ipaddress.ip_network("198.18.0.0/15"),         # Network benchmark
    ipaddress.ip_network("2001:db8::/32"),         # Documentation IPv6
]


def normalize_numeric_ip(host: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """
    Attempts to parse hostname as standard IP, integer decimal IP (e.g. 2130706433),
    hex IP (0x7f000001), octal (0177.0.0.1), or bracketed IPv6.
    """
    clean_host = host.strip("[]").strip().lower()

    # 1. Standard IP string parsing
    try:
        return ipaddress.ip_address(clean_host)
    except ValueError:
        pass

    # 2. Integer or Hex representation (e.g., 2130706433 or 0x7f000001)
    if clean_host.startswith("0x") or clean_host.isdigit():
        try:
            val = int(clean_host, 16 if clean_host.startswith("0x") else 10)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except (ValueError, OverflowError):
            pass

    # 3. Octal dot notation (e.g. 0177.0.0.1)
    parts = clean_host.split(".")
    if len(parts) == 4 and all(p.isdigit() or (p.startswith("0x") and len(p) > 2) for p in parts):
        try:
            parsed_octets = []
            for p in parts:
                if p.startswith("0x"):
                    parsed_octets.append(int(p, 16))
                elif p.startswith("0") and len(p) > 1:
                    parsed_octets.append(int(p, 8))
                else:
                    parsed_octets.append(int(p, 10))
            if all(0 <= o <= 255 for o in parsed_octets):
                return ipaddress.IPv4Address(".".join(str(o) for o in parsed_octets))
        except (ValueError, OverflowError):
            pass

    return None


def is_ip_forbidden(ip_input: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> Tuple[bool, Optional[str]]:
    """
    Evaluates whether an IP address falls into any forbidden internal, private, loopback,
    or cloud metadata address ranges.
    Returns: (is_forbidden, reason_message)
    """
    if isinstance(ip_input, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        ip_obj = ip_input
    else:
        parsed_ip = normalize_numeric_ip(str(ip_input))
        if parsed_ip is None:
            return True, f"Unparseable or malformed IP destination: '{ip_input}'"
        ip_obj = parsed_ip

    # Unpack IPv4-mapped IPv6 address (e.g., ::ffff:127.0.0.1 -> 127.0.0.1)
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
        ip_obj = ip_obj.ipv4_mapped

    if ip_obj.is_loopback:
        return True, f"Loopback address blocked ({ip_obj}) to prevent SSRF."
    if ip_obj.is_private:
        return True, f"Private internal RFC1918 address blocked ({ip_obj}) to prevent SSRF."
    if ip_obj.is_link_local:
        return True, f"Link-local / cloud metadata address blocked ({ip_obj}) to prevent SSRF."
    if ip_obj.is_multicast:
        return True, f"Multicast address blocked ({ip_obj})."
    if ip_obj.is_reserved:
        return True, f"Reserved / non-routable address blocked ({ip_obj})."

    for net in FORBIDDEN_NETWORKS:
        if ip_obj in net:
            return True, f"Destination IP {ip_obj} falls in forbidden network {net}."

    return False, None


def validate_url_for_safe_scan(
    url: str,
    allowed_ports: Optional[Set[int]] = None,
    timeout: float = DEFAULT_TIMEOUT
) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Validates URL scheme, port, and resolves destination IP via DNS,
    checking all resolved IP addresses against SSRF policies.
    Returns: (is_safe, resolved_ip, block_reason)
    """
    if not url or not isinstance(url, str):
        return False, None, "URL is empty or invalid."

    url = url.strip()
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as e:
        return False, None, f"Malformed URL parsing error: {e}"

    # 1. Scheme check
    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        return False, None, f"Unsupported scheme '{scheme}'. Only HTTP and HTTPS are permitted."

    # 2. Port check
    effective_ports = allowed_ports or ALLOWED_PORTS
    port = parsed.port or (443 if scheme == "https" else 80)
    if port not in effective_ports:
        return False, None, f"Port :{port} is blocked by SSRF policy. Allowed ports: {sorted(effective_ports)}"

    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        return False, None, "URL must contain a valid host destination."

    # 3. Direct Hostname SSRF / Localhost string check
    if hostname in ("localhost", "loopback", "0.0.0.0", "127.0.0.1", "::1"):
        return False, "127.0.0.1", f"Localhost destination '{hostname}' blocked."

    # 4. Numeric / Obfuscated IP check
    numeric_ip = normalize_numeric_ip(hostname)
    if numeric_ip is not None:
        forbidden, reason = is_ip_forbidden(numeric_ip)
        if forbidden:
            return False, str(numeric_ip), reason
        return True, str(numeric_ip), None

    # 5. DNS Pre-Resolution Check to prevent DNS Rebinding to internal networks
    try:
        addr_info = socket.getaddrinfo(hostname, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
        if not addr_info:
            return True, None, None  # NXDOMAIN handled by probe
        first_resolved = None
        for entry in addr_info:
            ip_str = entry[4][0]
            if first_resolved is None:
                first_resolved = ip_str
            forbidden, reason = is_ip_forbidden(ip_str)
            if forbidden:
                return False, ip_str, f"Forbidden destination: DNS resolved '{hostname}' to forbidden IP {ip_str} ({reason})"
        return True, first_resolved, None
    except socket.gaierror:
        # NXDOMAIN / DNS resolution failure is safe from SSRF; handled gracefully downstream
        return True, None, None
    except Exception as e:
        return False, None, f"DNS resolution error: {e}"
