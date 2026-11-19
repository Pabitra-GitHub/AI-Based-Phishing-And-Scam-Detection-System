"""
PhishGuard AI - Master DSA Security Scanner
Coordinates all Data Structures & Algorithms (DSA) checks:
  1. Lexical & Evasion: Defanging, IP notations, SSRF/Private CIDRs, Cloud Metadata
  2. Credential Stuffing & Obfuscation: @ symbol, non-standard ports, double-encoding
  3. Trie Matching: Sovereign whitelist, suspicious TLDs, phishing keywords, exploit paths
  4. Dynamic Programming: Levenshtein distance typosquatting & Homoglyphs
  5. Information Theory: Shannon entropy & DGA detection
  6. Graph Analysis: Redirect chain traversal, cycle/loop detection, cross-domain jumps
  7. Cryptographic & Network: DNS resolution, active SSL/TLS handshake & cert audit
  8. Decision Accumulator: Weighted risk score (0-100), classification, and safety advice
"""

import ipaddress
import math
import re
import time
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple

from backend.app.services.dsa.trie import (
    TRUSTED_DOMAIN_TRIE,
    SUSPICIOUS_TLD_TRIE,
    PHISHING_KEYWORD_TRIE,
    PHISHING_PATHS_TRIE
)
from backend.app.services.dsa.levenshtein import detect_typosquatting
from backend.app.services.dsa.entropy import analyze_lexical_randomness
from backend.app.services.dsa.graph_redirect import RedirectGraphTracker
from backend.app.services.dsa.network_checker import check_dns_resolvability, inspect_ssl_tls, probe_live_website


PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

CLOUD_METADATA_IPS = {"169.254.169.254"}

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".apk", ".vbs", ".iso", ".dmg", ".sh",
    ".cmd", ".ps1", ".jar", ".hta", ".wsf", ".msi"
}

SUSPICIOUS_QUERY_PARAMS = {
    "password", "passwd", "pwd", "token", "access_token", "session",
    "session_id", "apikey", "secret", "cvv", "card_number", "ssn"
}

NON_STANDARD_PORTS = {8080, 8443, 8888, 21, 22, 23, 25, 4444, 6667, 31337}

# Top brands where even a dist=2 typosquat is CRITICAL (extremely high-value targets)
TOP_CRITICAL_BRANDS = {
    "google", "microsoft", "apple", "paypal", "amazon", "facebook",
    "instagram", "whatsapp", "netflix", "sbi", "hdfc", "icici",
    "paytm", "phonepe", "binance", "coinbase"
}

# Platform-specific paths that are only legitimate on specific domains
PLATFORM_PATH_SIGNATURES = [
    ("/search", {"google", "bing", "yahoo", "duckduckgo", "youtube"}),
    ("/maps", {"google", "apple"}),
    ("/mail", {"google", "yahoo", "outlook", "proton"}),
    ("/account", {"google", "microsoft", "apple", "amazon", "paypal"}),
    ("/signin", {"google", "microsoft", "apple", "amazon", "paypal"}),
    ("/login", {"google", "microsoft", "apple", "amazon", "paypal", "facebook"}),
    ("/profile", {"facebook", "instagram", "twitter", "linkedin"}),
    ("/wallet", {"paypal", "paytm", "phonepe", "binance", "coinbase"}),
    ("/upi", {"paytm", "phonepe", "bhim", "npci"}),
    ("/netbanking", {"sbi", "hdfc", "icici", "axis", "pnb"}),
]


class SecurityFinding:
    """Represents an individual safety check finding."""
    def __init__(self, rule_id: str, title: str, reason: str, severity: str, weight: int, layer: str = "DSA"):
        self.rule_id = rule_id
        self.title = title
        self.reason = reason
        self.severity = severity  # LOW, MEDIUM, HIGH, CRITICAL
        self.weight = weight
        self.source = "DSA_SECURITY_ENGINE"
        self.layer = layer

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "reason": self.reason,
            "severity": self.severity,
            "weight": self.weight,
            "source": self.source,
            "layer": self.layer
        }


def _calculate_entropy(text: str) -> float:
    """Local Shannon entropy helper for query param analysis."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def scan_url_dsa(url: str, check_network: bool = True) -> Dict[str, Any]:
    """
    Executes comprehensive DSA safety inspection on a URL.
    Returns complete security verdict, score (0-100), classification, and evidence.
    """
    start_time = time.time()
    findings: List[SecurityFinding] = []

    # 1. Defanging & Clean Normalization
    raw_url = url.strip().strip("\"'<>`")
    cleaned_url = re.sub(r"^hxxps://", "https://", raw_url, flags=re.IGNORECASE)
    cleaned_url = re.sub(r"^hxxp://", "http://", cleaned_url, flags=re.IGNORECASE)
    cleaned_url = cleaned_url.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")

    if not (cleaned_url.startswith("http://") or cleaned_url.startswith("https://")):
        cleaned_url = "http://" + cleaned_url

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 0: Dangerous scheme injection (data: / javascript:)
    # ─────────────────────────────────────────────────────────────────────────
    raw_lower = raw_url.lower()
    if raw_lower.startswith("data:") or raw_lower.startswith("javascript:") or raw_lower.startswith("vbscript:"):
        findings.append(SecurityFinding(
            rule_id="DANGEROUS_SCHEME_INJECTION",
            title="Dangerous URI Scheme Injection",
            reason=f"URL uses a dangerous non-HTTP scheme (data:, javascript:, or vbscript:) which can execute code in the browser.",
            severity="CRITICAL",
            weight=70,
            layer="L1_LEXICAL"
        ))

    # Null-byte injection detection
    if "%00" in cleaned_url or "\x00" in cleaned_url:
        findings.append(SecurityFinding(
            rule_id="NULL_BYTE_INJECTION",
            title="Null-Byte Injection Attempt",
            reason="URL contains a null-byte character (%00) used to truncate server-side path validation and bypass security filters.",
            severity="CRITICAL",
            weight=55,
            layer="L1_LEXICAL"
        ))

    parsed = urllib.parse.urlparse(cleaned_url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or "/"
    query = parsed.query or ""
    scheme = parsed.scheme.lower()

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 1: Official Sovereign & Whitelist Check (Trie Lookup)
    # ─────────────────────────────────────────────────────────────────────────
    trusted_suffix_match = TRUSTED_DOMAIN_TRIE.find_suffix_match(hostname)
    trusted_exact_match = TRUSTED_DOMAIN_TRIE.search_exact(hostname)

    is_sovereign_gov = False
    is_trusted_platform = False

    if trusted_suffix_match:
        if trusted_suffix_match.get("type") == "GOVERNMENT":
            is_sovereign_gov = True
    if trusted_exact_match:
        if trusted_exact_match.get("type") == "GOVERNMENT":
            is_sovereign_gov = True
        elif trusted_exact_match.get("type") == "TRUSTED_PLATFORM":
            is_trusted_platform = True

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 2: SSRF & IP Evasion Detection
    # ─────────────────────────────────────────────────────────────────────────
    is_ip_host = False
    try:
        ip_obj = ipaddress.ip_address(hostname)
        is_ip_host = True

        # Check Cloud Metadata (AWS/GCP/Azure IMDS)
        if str(ip_obj) in CLOUD_METADATA_IPS:
            findings.append(SecurityFinding(
                rule_id="SSRF_CLOUD_METADATA",
                title="Critical Cloud Metadata SSRF Target",
                reason=f"URL targets sensitive cloud instance metadata service ({ip_obj}) used to harvest IAM keys and cloud credentials.",
                severity="CRITICAL",
                weight=60,
                layer="L1_LEXICAL"
            ))

        # Check Private / Localhost CIDRs
        is_private = any(ip_obj in net for net in PRIVATE_NETWORKS)
        if is_private or ip_obj.is_loopback or ip_obj.is_private:
            findings.append(SecurityFinding(
                rule_id="SSRF_PRIVATE_NETWORK",
                title="Private / Internal Network Address",
                reason=f"URL points to a private internal network IP ({ip_obj}) or localhost loopback, posing an SSRF risk.",
                severity="HIGH",
                weight=50,
                layer="L1_LEXICAL"
            ))
        else:
            findings.append(SecurityFinding(
                rule_id="RAW_IP_HOSTNAME",
                title="Raw IP Address Hostname",
                reason=f"URL uses a raw IP address ({ip_obj}) instead of a standard registered domain name.",
                severity="HIGH",
                weight=35,
                layer="L1_LEXICAL"
            ))
    except ValueError:
        if hostname in ("localhost", "127.0.0.1", "0.0.0.0", "loopback"):
            findings.append(SecurityFinding(
                rule_id="SSRF_LOCALHOST",
                title="Localhost Loopback Target",
                reason="URL points to localhost or loopback interface.",
                severity="HIGH",
                weight=50,
                layer="L1_LEXICAL"
            ))

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 3: Credential Obfuscation & Evasion Symbols (@ in URL)
    # ─────────────────────────────────────────────────────────────────────────
    if "@" in parsed.netloc:
        findings.append(SecurityFinding(
            rule_id="CREDENTIAL_OBFUSCATION_AT",
            title="Credential Obfuscation Pattern (@ Symbol)",
            reason="URL uses an '@' character in the authority component to deceive users about the true destination host.",
            severity="CRITICAL",
            weight=50,
            layer="L1_LEXICAL"
        ))

    # Check non-standard ports
    if parsed.port and parsed.port in NON_STANDARD_PORTS:
        findings.append(SecurityFinding(
            rule_id="NON_STANDARD_PORT",
            title="Non-Standard High-Risk Port",
            reason=f"URL connects over non-standard port :{parsed.port}, frequently used by phishing kits or rogue proxies.",
            severity="MEDIUM",
            weight=20,
            layer="L1_LEXICAL"
        ))

    # Check double-encoding and path traversal
    if "%25" in path or "%2e%2e" in path.lower() or ".." in path:
        findings.append(SecurityFinding(
            rule_id="PATH_TRAVERSAL_ENCODING",
            title="Double-Encoding / Path Traversal Pattern",
            reason="URL contains double URL-encoding or directory traversal characters ('..').",
            severity="HIGH",
            weight=30,
            layer="L1_LEXICAL"
        ))

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 3b: Excessive Subdomain Chain Abuse
    # ─────────────────────────────────────────────────────────────────────────
    if not is_ip_host and hostname:
        subdomain_parts = hostname.split(".")
        if len(subdomain_parts) > 4:
            findings.append(SecurityFinding(
                rule_id="EXCESSIVE_SUBDOMAINS",
                title="Excessive Subdomain Chain Abuse",
                reason=f"Domain '{hostname}' contains {len(subdomain_parts) - 2} subdomain levels, a technique used to hide the true malicious root domain.",
                severity="MEDIUM",
                weight=20,
                layer="L1_LEXICAL"
            ))

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 4: Dangerous Executable & Script Downloads
    # ─────────────────────────────────────────────────────────────────────────
    path_lower = path.lower()
    for ext in DANGEROUS_EXTENSIONS:
        if path_lower.endswith(ext) or f"{ext}?" in cleaned_url.lower():
            findings.append(SecurityFinding(
                rule_id="DANGEROUS_FILE_DOWNLOAD",
                title=f"Executable / Script Payload ({ext})",
                reason=f"URL directly delivers or downloads a dangerous executable or script file ({ext}).",
                severity="CRITICAL",
                weight=45,
                layer="L1_LEXICAL"
            ))
            break

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 5: Cleartext Credential Leaks in Query String
    # ─────────────────────────────────────────────────────────────────────────
    if query:
        query_params = urllib.parse.parse_qs(query)
        detected_sensitive = [p for p in query_params.keys() if p.lower() in SUSPICIOUS_QUERY_PARAMS]
        if detected_sensitive:
            findings.append(SecurityFinding(
                rule_id="SENSITIVE_PARAM_IN_URL",
                title="Sensitive Credential in URL Query String",
                reason=f"URL exposes sensitive authentication parameters ({', '.join(detected_sensitive)}) in plaintext.",
                severity="HIGH",
                weight=30,
                layer="L1_LEXICAL"
            ))

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 6: DSA Dynamic Programming - Levenshtein Typosquatting & Homoglyphs
    # ─────────────────────────────────────────────────────────────────────────
    typo_match = detect_typosquatting(hostname)
    if typo_match and not is_sovereign_gov and not is_trusted_platform:
        brand = typo_match.get("detected_brand")
        m_type = typo_match.get("match_type")
        dist = typo_match.get("edit_distance", 0)
        sim = typo_match.get("similarity", 0.0)

        if m_type in ("TYPOSQUATTING", "TOKEN_TYPOSQUAT") and isinstance(brand, str):
            findings.append(SecurityFinding(
                rule_id="TYPOSQUATTING_DETECTED",
                title=f"Brand Typosquatting Impersonation ({brand.capitalize()})",
                reason=f"Domain '{hostname}' is a deceptive typosquatting mimic of '{brand}' (Levenshtein Distance = {dist}, Similarity = {int(sim*100)}%). Attackers register near-identical domains to intercept users who mistype.",
                severity="CRITICAL" if (dist == 1 or brand in TOP_CRITICAL_BRANDS) else "HIGH",
                weight=50 if dist == 1 else 42,
                layer="L2_TYPOSQUAT"
            ))

        elif m_type == "EMBEDDED_BRAND_SPOOF" and isinstance(brand, str):
            findings.append(SecurityFinding(
                rule_id="EMBEDDED_BRAND_SPOOF",
                title=f"Deceptive Brand Spoofing ({brand.capitalize()})",
                reason=f"URL domain embeds the brand name '{brand}' outside of its genuine authenticated platform.",
                severity="HIGH",
                weight=30,
                layer="L2_TYPOSQUAT"
            ))
        elif m_type == "HOMOGLYPH_DECEPTION":
            findings.append(SecurityFinding(
                rule_id="HOMOGLYPH_DECEPTION",
                title="Homoglyph / Punycode Visual Deception",
                reason="Domain utilizes deceptive Unicode homoglyph characters or Punycode ('xn--') to visually impersonate legitimate websites.",
                severity="HIGH",
                weight=35,
                layer="L2_TYPOSQUAT"
            ))

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 7: Trie Lookups - Phishing Keywords, Suspicious TLDs, Phishing Paths
    # ─────────────────────────────────────────────────────────────────────────
    # Suspicious TLD check
    tld_match = SUSPICIOUS_TLD_TRIE.find_suffix_match(hostname)
    if tld_match and not is_sovereign_gov:
        tld_name = tld_match.get("tld", "unknown")
        findings.append(SecurityFinding(
            rule_id="SUSPICIOUS_TLD",
            title="High-Abuse Top-Level Domain",
            reason=f"Domain uses high-abuse top-level extension (.{tld_name}) frequently registered for spam and scams.",
            severity="MEDIUM",
            weight=20,
            layer="L3_TRIE"
        ))

    # Phishing Keywords Trie scan across URL
    keywords_found = PHISHING_KEYWORD_TRIE.find_keywords_in_text(cleaned_url)
    if keywords_found and not is_sovereign_gov and not is_trusted_platform:
        # Exclude keyword matches that are part of legitimate domain names
        suspicious_words = [kw["word"] for kw in keywords_found if kw["word"] not in hostname or "." in hostname]
        if suspicious_words:
            unique_words = list(dict.fromkeys(suspicious_words))[:4]
            findings.append(SecurityFinding(
                rule_id="PHISHING_KEYWORDS_DETECTED",
                title="Phishing & Urgency Trigger Keywords",
                reason=f"URL includes high-risk security / authentication keywords: {', '.join(unique_words)}.",
                severity="MEDIUM",
                weight=min(len(unique_words) * 10, 25),
                layer="L3_TRIE"
            ))

    # Phishing Paths Trie scan (comprehensive path matching)
    path_matches = PHISHING_PATHS_TRIE.find_keywords_in_text(path_lower)
    if path_matches and not is_sovereign_gov:
        top_match = sorted(path_matches, key=lambda x: x.get("severity", "LOW"), reverse=True)[0]
        sev = top_match.get("severity", "MEDIUM")
        desc = top_match.get("description", "Phishing kit path")
        weight_map = {"CRITICAL": 40, "HIGH": 30, "MEDIUM": 20, "LOW": 10}
        findings.append(SecurityFinding(
            rule_id="KNOWN_PHISHING_PATH",
            title="Known Phishing / Exploit Path Detected",
            reason=f"URL path matches known phishing kit or exploit structure: '{top_match.get('word', path_lower)}'. {desc}.",
            severity=sev,
            weight=weight_map.get(sev, 20),
            layer="L3_TRIE"
        ))

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 7b: Platform-Specific Path Spoofing
    # e.g. /search on a non-Google domain, /netbanking on a non-bank domain
    # ─────────────────────────────────────────────────────────────────────────
    if not is_sovereign_gov and not is_trusted_platform and typo_match:
        # Check if path mimics a platform-specific endpoint
        hostname_root = hostname.lstrip("www.").split(".")[0] if hostname else ""
        for platform_path, legitimate_brands in PLATFORM_PATH_SIGNATURES:
            if path_lower.startswith(platform_path):
                # This path is suspicious if the domain is NOT one of the legitimate brand roots
                if not any(brand in hostname for brand in legitimate_brands):
                    findings.append(SecurityFinding(
                        rule_id="PLATFORM_PATH_SPOOF",
                        title=f"Platform Path Spoofing ('{platform_path}')",
                        reason=f"URL uses platform-specific path '{platform_path}' (typical of {', '.join(list(legitimate_brands)[:3])}) on an unverified domain '{hostname}'. This is a common phishing technique to simulate legitimate interfaces.",
                        severity="HIGH",
                        weight=30,
                        layer="L3_TRIE"
                    ))
                    break

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 7c: High-Entropy / Garbage Query String Detection
    # e.g. ?q=esryrtuydrtuyit&gie=UTF-87473436 (random junk params)
    # ─────────────────────────────────────────────────────────────────────────
    if query and not is_sovereign_gov and not is_trusted_platform:
        # Compute entropy of the full query string
        query_entropy = _calculate_entropy(query)
        # Detect individual params with very high-entropy values (garbage strings)
        garbage_params = []
        for param_pair in query.split("&"):
            if "=" in param_pair:
                param_key, _, param_val = param_pair.partition("=")
                # Decode percent-encoded characters
                try:
                    decoded_val = urllib.parse.unquote_plus(param_val)
                except Exception:
                    decoded_val = param_val
                val_entropy = _calculate_entropy(decoded_val)
                # Flag if value has very high entropy (random string) or contains digit-heavy junk
                digits_in_val = sum(1 for c in decoded_val if c.isdigit())
                digit_ratio = digits_in_val / max(len(decoded_val), 1)
                if len(decoded_val) > 6 and (val_entropy > 3.5 or (digit_ratio > 0.4 and len(decoded_val) > 5)):
                    garbage_params.append(param_key)
        if garbage_params:
            findings.append(SecurityFinding(
                rule_id="HIGH_ENTROPY_QUERY_PARAMS",
                title="Suspicious Random / Garbage Query Parameters",
                reason=f"URL query parameter(s) '{', '.join(garbage_params[:3])}' contain high-entropy random or numeric-junk values, a common obfuscation pattern in phishing and tracking URLs.",
                severity="MEDIUM",
                weight=18,
                layer="L4_ENTROPY"
            ))
        elif query_entropy > 4.2 and len(query) > 20:
            findings.append(SecurityFinding(
                rule_id="HIGH_ENTROPY_QUERY_STRING",
                title="High-Entropy Query String",
                reason=f"Overall URL query string has very high randomness (entropy={query_entropy:.2f}), suggesting obfuscated payload, tracking abuse, or generated phishing URL.",
                severity="MEDIUM",
                weight=15,
                layer="L4_ENTROPY"
            ))

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 8: Shannon Information Entropy & Lexical Randomness
    # ─────────────────────────────────────────────────────────────────────────
    entropy_info = analyze_lexical_randomness(hostname, path)
    if entropy_info.get("is_dga_suspected") and not is_sovereign_gov and not is_trusted_platform:
        dga_reasons = entropy_info.get("reasons", ["High entropy hostname detected."])
        findings.append(SecurityFinding(
            rule_id="HIGH_ENTROPY_DGA",
            title="Algorithmic / DGA Random Hostname",
            reason="; ".join(dga_reasons),
            severity="MEDIUM",
            weight=20,
            layer="L4_ENTROPY"
        ))

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 9: Network & Cryptographic Verification (DNS & SSL/TLS)
    # ─────────────────────────────────────────────────────────────────────────
    dns_resolvable = True
    resolved_ip = None
    ssl_info: Dict[str, Any] = {}
    live_probe: Dict[str, Any] = {}

    if check_network:
        # Fast DNS Check
        dns_resolvable, resolved_ip = check_dns_resolvability(hostname)
        if not dns_resolvable:
            findings.append(SecurityFinding(
                rule_id="DNS_UNRESOLVABLE",
                title="Unresolvable Host (Non-Existent DNS)",
                reason=f"Host '{hostname}' could not be resolved via DNS. It may be an abandoned, blocked, or inactive phishing link.",
                severity="HIGH",
                weight=30,
                layer="L5_NETWORK"
            ))

        # SSL/TLS Handshake Check
        if scheme == "https" and dns_resolvable:
            ssl_info = inspect_ssl_tls(hostname)
            if not ssl_info.get("ssl_valid", False):
                if is_sovereign_gov:
                    findings.append(SecurityFinding(
                        rule_id="SOVEREIGN_CA_UNVERIFIED",
                        title="National / Sovereign Certificate Authority Notice",
                        reason=f"Certificate not in standard commercial browser store: {ssl_info.get('ssl_error', '')}. Official government portals frequently utilize domestic sovereign root CAs (e.g., NIC CA / CCA India).",
                        severity="LOW",
                        weight=0,
                        layer="L5_NETWORK"
                    ))
                else:
                    findings.append(SecurityFinding(
                        rule_id="INVALID_SSL_CERTIFICATE",
                        title="Invalid / Untrusted SSL/TLS Certificate",
                        reason=ssl_info.get("ssl_error") or "SSL certificate verification failed. Traffic is vulnerable to interception.",
                        severity="CRITICAL",
                        weight=50,
                        layer="L5_NETWORK"
                    ))
            elif ssl_info.get("is_self_signed", False):
                findings.append(SecurityFinding(
                    rule_id="SELF_SIGNED_SSL",
                    title="Self-Signed SSL Certificate",
                    reason="Server certificate is self-signed and not issued by a recognized root Certificate Authority.",
                    severity="HIGH",
                    weight=35,
                    layer="L5_NETWORK"
                ))
        elif scheme == "http" and not is_sovereign_gov:
            findings.append(SecurityFinding(
                rule_id="INSECURE_PLAINTEXT_HTTP",
                title="Insecure Plaintext HTTP Protocol",
                reason="Website transmits data unencrypted over HTTP. Login credentials and personal data travel in cleartext.",
                severity="MEDIUM",
                weight=20,
                layer="L5_NETWORK"
            ))

        # Live Website Probing (inspects responsiveness, page title, and password form lures)
        if dns_resolvable and not is_ip_host:
            try:
                live_probe = probe_live_website(cleaned_url, timeout=2.0)
                if live_probe.get("has_password_input") and (typo_match or tld_match or scheme == "http"):
                    findings.append(SecurityFinding(
                        rule_id="LIVE_CREDENTIAL_FORM",
                        title="Active Password / Credential Harvester Form",
                        reason="Live inspection detected password input fields on an unverified, deceptive, or unencrypted destination.",
                        severity="CRITICAL",
                        weight=50,
                        layer="L5_NETWORK"
                    ))
                elif live_probe.get("has_login_form") and (typo_match or tld_match):
                    findings.append(SecurityFinding(
                        rule_id="LIVE_LOGIN_LURE",
                        title="Active Phishing Login Lure",
                        reason=f"Live inspection detected a login form on an unverified domain (Page Title: '{live_probe.get('page_title', 'Unknown')}').",
                        severity="HIGH",
                        weight=35,
                        layer="L5_NETWORK"
                    ))
            except Exception:
                pass

    # ─────────────────────────────────────────────────────────────────────────
    # CHECK 10: Graph Redirect Traversal & Cycle Detection
    # ─────────────────────────────────────────────────────────────────────────
    redirect_chain = []
    has_redirect_loop = False
    is_shortener = False
    is_cross_domain = False

    if check_network and dns_resolvable:
        try:
            tracker = RedirectGraphTracker(max_hops=5, timeout=2.0)
            graph_res = tracker.trace_redirects(cleaned_url)
            redirect_chain = graph_res.get("chain", [])
            has_redirect_loop = graph_res.get("has_redirect_loop", False)
            is_shortener = graph_res.get("is_url_shortener", False)
            is_cross_domain = graph_res.get("is_cross_domain", False)

            if has_redirect_loop:
                findings.append(SecurityFinding(
                    rule_id="REDIRECT_LOOP_DETECTED",
                    title="Redirect Loop / Graph Cycle Detected",
                    reason="Redirection chain contains a cyclic loop, commonly used in bot evasion and browser locking.",
                    severity="HIGH",
                    weight=30,
                    layer="L6_GRAPH"
                ))
            if is_cross_domain:
                findings.append(SecurityFinding(
                    rule_id="CROSS_DOMAIN_REDIRECT",
                    title="Cross-Domain Redirection Hop",
                    reason="URL redirects across different root domains, commonly used in phishing relays and cloaking.",
                    severity="MEDIUM",
                    weight=15,
                    layer="L6_GRAPH"
                ))
            if is_shortener:
                findings.append(SecurityFinding(
                    rule_id="URL_SHORTENER_OBSCURITY",
                    title="URL Shortener Obscurity",
                    reason="URL utilizes a shortening service which masks the actual target destination.",
                    severity="LOW",
                    weight=10,
                    layer="L6_GRAPH"
                ))
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    # RISK SCORE COMPUTATION & CLASSIFICATION
    # ─────────────────────────────────────────────────────────────────────────
    # Guaranteed protection for official sovereign / verified platforms
    if is_sovereign_gov:
        risk_score = 0
        classification = "SAFE"
        recommendation = "Verified Official Government / Sovereign Portal. Authentic and safe to navigate."
        findings.insert(0, SecurityFinding(
            rule_id="VERIFIED_GOV_PORTAL",
            title="Official Government Portal",
            reason="Authenticated official government or public administration domain.",
            severity="LOW",
            weight=0,
            layer="WHITELIST"
        ))
    elif is_trusted_platform and len([f for f in findings if f.severity in ("CRITICAL", "HIGH")]) == 0:
        risk_score = 0
        classification = "SAFE"
        recommendation = "Verified Authentic Global Platform. Domain integrity and digital security verified."
    else:
        # Sum weighted penalties
        raw_score = sum(f.weight for f in findings)

        # Critical overrides
        has_critical = any(f.severity == "CRITICAL" for f in findings)
        has_high = any(f.severity == "HIGH" for f in findings)
        has_typosquat = any(f.rule_id in ("TYPOSQUATTING_DETECTED", "EMBEDDED_BRAND_SPOOF", "HOMOGLYPH_DECEPTION") for f in findings)

        if has_critical:
            raw_score = max(raw_score, 85)
        elif has_high and len(findings) >= 2:
            raw_score = max(raw_score, 70)
        elif has_high and has_typosquat:
            # Single typosquat finding must always be at least HIGH RISK (not just SUSPICIOUS)
            raw_score = max(raw_score, 62)
        elif has_high:
            raw_score = max(raw_score, 50)
        elif not dns_resolvable:
            raw_score = max(raw_score, 60)
        elif scheme == "http" and raw_score < 40:
            raw_score = max(raw_score, 35)

        # Cap score between 0 and 100
        risk_score = min(max(raw_score, 0), 100)

        # Determine Classification
        if risk_score <= 29:
            classification = "SAFE"
            recommendation = "This URL exhibits verified encryption and authentic structural indicators. Safe to browse, maintain standard cyber awareness."
        elif risk_score <= 59:
            classification = "SUSPICIOUS"
            recommendation = "Security anomalies or unencrypted communications detected. Proceed with caution and do not input passwords unless verified."
        elif risk_score <= 84:
            classification = "HIGH RISK"
            recommendation = "Strong indicators of deceptive brand impersonation or malicious hosting. Do NOT enter passwords, OTPs, or financial information."
        else:
            classification = "CRITICAL"
            recommendation = "CRITICAL SECURITY THREAT: Deceptive credential harvester, malware deliverer, or active threat infrastructure. Do NOT open this site!"

    duration_ms = int((time.time() - start_time) * 1000)

    # Format structured layer results for API/DB backwards compatibility
    layers_executed_list = ["L1", "L2", "L3", "L4", "L5", "L6"]
    layer_results = [
        {
            "layer_id": "L1",
            "layer_name": "Lexical & SSRF Analysis",
            "executed": True,
            "findings_count": len([f for f in findings if f.layer in ("L1", "L1_LEXICAL")]),
            "findings": [f.to_dict() for f in findings if f.layer in ("L1", "L1_LEXICAL")],
            "metadata": {"hostname": hostname, "is_ip_host": is_ip_host}
        },
        {
            "layer_id": "L2",
            "layer_name": "Levenshtein Typosquatting (DP)",
            "executed": True,
            "findings_count": len([f for f in findings if f.layer in ("L2", "L2_TYPOSQUAT")]),
            "findings": [f.to_dict() for f in findings if f.layer in ("L2", "L2_TYPOSQUAT")],
            "metadata": typo_match or {"typosquatting_detected": False}
        },
        {
            "layer_id": "L3",
            "layer_name": "Trie Keyword & TLD Search",
            "executed": True,
            "findings_count": len([f for f in findings if f.layer in ("L3", "L3_TRIE")]),
            "findings": [f.to_dict() for f in findings if f.layer in ("L3", "L3_TRIE")],
            "metadata": {"keywords_count": len(keywords_found)}
        },
        {
            "layer_id": "L4",
            "layer_name": "Shannon Entropy Analysis",
            "executed": True,
            "findings_count": len([f for f in findings if f.layer in ("L4", "L4_ENTROPY")]),
            "findings": [f.to_dict() for f in findings if f.layer in ("L4", "L4_ENTROPY")],
            "metadata": entropy_info
        },
        {
            "layer_id": "L5",
            "layer_name": "Network & Crypto Verification",
            "executed": check_network,
            "findings_count": len([f for f in findings if f.layer in ("L5", "L5_NETWORK")]),
            "findings": [f.to_dict() for f in findings if f.layer in ("L5", "L5_NETWORK")],
            "metadata": {"dns_resolvable": dns_resolvable, "resolved_ip": resolved_ip, "ssl": ssl_info}
        },
        {
            "layer_id": "L6",
            "layer_name": "Redirect Graph Traversal",
            "executed": bool(redirect_chain),
            "findings_count": len([f for f in findings if f.layer in ("L6", "L6_GRAPH")]),
            "findings": [f.to_dict() for f in findings if f.layer in ("L6", "L6_GRAPH")],
            "metadata": {"hops": len(redirect_chain), "has_loop": has_redirect_loop}
        }
    ]

    return {
        "url": cleaned_url,
        "hostname": hostname,
        "risk_score": risk_score,
        "rule_score": risk_score,
        "classification": classification,
        "ml_probability": round(risk_score / 100.0, 4),
        "model_version": "v2.0.0-dsa-engine",
        "recommendation": recommendation,
        "detection_reasons": [f.to_dict() for f in findings],
        "layer_results": layer_results,
        "redirect_chain": redirect_chain,
        "features": {
            "url_length": len(cleaned_url),
            "domain_length": len(hostname),
            "domain_entropy": entropy_info.get("domain_entropy", 0.0),
            "is_https": 1 if scheme == "https" else 0,
            "has_ip_address": 1 if is_ip_host else 0,
            "has_typosquatting": 1 if typo_match else 0,
            "has_suspicious_tld": 1 if tld_match else 0,
            "keywords_found_count": len(keywords_found),
            "dns_resolvable": 1 if dns_resolvable else 0,
            "resolved_ip": resolved_ip,
            "ssl_valid": 1 if (ssl_info.get("ssl_valid") or (is_sovereign_gov and scheme == "https")) else 0,
            "is_government_domain": 1 if is_sovereign_gov else 0,
            "government_entity": (trusted_suffix_match or trusted_exact_match or {}).get("entity") if is_sovereign_gov else None,
            "is_authentic_brand": 1 if is_trusted_platform else 0,
            "authentic_brand_name": (trusted_exact_match or {}).get("brand") if is_trusted_platform else None,
            "is_cross_domain_redirect": 1 if is_cross_domain else 0,
            "http_status": live_probe.get("http_status"),
            "page_title": live_probe.get("page_title"),
            "has_password_input": 1 if live_probe.get("has_password_input") else 0,
            "server_banner": live_probe.get("server_banner")
        },
        "scan_duration_ms": duration_ms,
        "layers_executed": layers_executed_list
    }
