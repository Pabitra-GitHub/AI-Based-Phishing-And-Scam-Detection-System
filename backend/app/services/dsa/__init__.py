"""
PhishGuard AI - Data Structures & Algorithms (DSA) Security Package
"""

from backend.app.services.dsa.trie import (
    Trie,
    TRUSTED_DOMAIN_TRIE,
    SUSPICIOUS_TLD_TRIE,
    PHISHING_KEYWORD_TRIE,
    PHISHING_PATHS_TRIE
)
from backend.app.services.dsa.levenshtein import (
    levenshtein_distance,
    calculate_similarity_ratio,
    detect_typosquatting,
    normalize_homoglyphs
)
from backend.app.services.dsa.entropy import (
    calculate_shannon_entropy,
    analyze_lexical_randomness
)
from backend.app.services.dsa.graph_redirect import RedirectGraphTracker
from backend.app.services.dsa.network_checker import (
    check_dns_resolvability,
    inspect_ssl_tls,
    check_security_headers
)
from backend.app.services.dsa.dsa_scanner import scan_url_dsa, SecurityFinding

__all__ = [
    "Trie",
    "TRUSTED_DOMAIN_TRIE",
    "SUSPICIOUS_TLD_TRIE",
    "PHISHING_KEYWORD_TRIE",
    "PHISHING_PATHS_TRIE",
    "levenshtein_distance",
    "calculate_similarity_ratio",
    "detect_typosquatting",
    "normalize_homoglyphs",
    "calculate_shannon_entropy",
    "analyze_lexical_randomness",
    "RedirectGraphTracker",
    "check_dns_resolvability",
    "inspect_ssl_tls",
    "check_security_headers",
    "scan_url_dsa",
    "SecurityFinding"
]
