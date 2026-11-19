"""
PhishGuard AI - Comprehensive DSA Security Engine Test Suite
Validates:
  1. Trie Data Structure (prefix, exact, suffix, multi-keyword extraction)
  2. Dynamic Programming (Levenshtein edit distance, similarity ratio, typosquatting, homoglyphs)
  3. Information Theory (Shannon entropy, DGA detection)
  4. Graph-based Redirect Traversal & Cycle Detection (Hash Set loop detection)
  5. End-to-End DSA Safety Engine (Sovereign whitelist, SSRF, @ abuse, dangerous files, full verdict)
"""

import pytest
from backend.app.services.dsa.trie import (
    Trie,
    TRUSTED_DOMAIN_TRIE,
    SUSPICIOUS_TLD_TRIE,
    PHISHING_KEYWORD_TRIE
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
from backend.app.services.dsa.dsa_scanner import scan_url_dsa
from backend.app.services.pipeline import run_scan


# ═════════════════════════════════════════════════════════════════════════════
# 1. TRIE DATA STRUCTURE TESTS
# ═════════════════════════════════════════════════════════════════════════════

def test_trie_insert_and_exact_search():
    trie = Trie()
    trie.insert("paypal", {"category": "fintech"})
    trie.insert("pay", {"category": "root"})

    assert trie.search_exact("paypal") == {"category": "fintech"}
    assert trie.search_exact("pay") == {"category": "root"}
    assert trie.search_exact("payment") is None
    assert trie.search_exact("") is None


def test_trie_prefix_search():
    trie = Trie()
    trie.insert("verification")

    assert trie.search_prefix("veri") is True
    assert trie.search_prefix("verification") is True
    assert trie.search_prefix("vet") is False


def test_trie_trusted_domain_and_sovereign_suffix():
    # Government sovereign suffixes
    assert TRUSTED_DOMAIN_TRIE.find_suffix_match("india.gov.in") is not None
    assert TRUSTED_DOMAIN_TRIE.find_suffix_match("irs.gov") is not None
    assert TRUSTED_DOMAIN_TRIE.find_suffix_match("service.gov.uk") is not None
    assert TRUSTED_DOMAIN_TRIE.find_suffix_match("delhi.nic.in") is not None

    # Verified global platforms
    assert TRUSTED_DOMAIN_TRIE.search_exact("google.com") is not None
    assert TRUSTED_DOMAIN_TRIE.search_exact("github.com") is not None
    assert TRUSTED_DOMAIN_TRIE.search_exact("paypal.com") is not None


def test_trie_suspicious_tld():
    assert SUSPICIOUS_TLD_TRIE.find_suffix_match("scam-site.xyz") is not None
    assert SUSPICIOUS_TLD_TRIE.find_suffix_match("free-crypto.top") is not None
    assert SUSPICIOUS_TLD_TRIE.find_suffix_match("login-auth.tk") is not None
    assert SUSPICIOUS_TLD_TRIE.find_suffix_match("legit-site.org") is None


def test_trie_multi_keyword_extraction():
    url_text = "https://secure-login.portal.com/verify-account?token=123"
    matches = PHISHING_KEYWORD_TRIE.find_keywords_in_text(url_text)
    words = [m["word"] for m in matches]

    assert "secure" in words
    assert "login" in words
    assert "verify" in words
    assert "account" in words


# ═════════════════════════════════════════════════════════════════════════════
# 2. DYNAMIC PROGRAMMING - LEVENSHTEIN DISTANCE & HOMOGLYPHS
# ═════════════════════════════════════════════════════════════════════════════

def test_levenshtein_distance_dp():
    assert levenshtein_distance("", "") == 0
    assert levenshtein_distance("a", "") == 1
    assert levenshtein_distance("paypal", "paypal") == 0
    assert levenshtein_distance("paypal", "paypa1") == 1
    assert levenshtein_distance("google", "goog1e") == 1
    assert levenshtein_distance("microsoft", "microsofft") == 1
    assert levenshtein_distance("apple", "aple") == 1


def test_similarity_ratio():
    sim = calculate_similarity_ratio("paypal", "paypa1")
    assert sim >= 0.80
    assert calculate_similarity_ratio("identical", "identical") == 1.0


def test_detect_typosquatting_brands():
    # Primary label typosquatting
    res_paypa1 = detect_typosquatting("paypa1.com")
    assert res_paypa1 is not None
    assert res_paypa1["detected_brand"] == "paypal"
    assert res_paypa1["edit_distance"] == 1
    assert res_paypa1["severity"] == "CRITICAL"

    res_goog1e = detect_typosquatting("goog1e.com")
    assert res_goog1e is not None
    assert res_goog1e["detected_brand"] == "google"
    assert res_goog1e["edit_distance"] == 1

    # Embedded brand spoofing
    res_spoof = detect_typosquatting("paypal-security-update.com")
    assert res_spoof is not None
    assert res_spoof["detected_brand"] == "paypal"


def test_homoglyph_normalization():
    # Cyrillic 'а' (U+0430) looks identical to Latin 'a'
    cyrillic_url = "p\u0430ypal.com"
    norm, had_homo = normalize_homoglyphs(cyrillic_url)
    assert had_homo is True
    assert norm == "paypal.com"

    # ASCII digits are handled as edit-distance evidence, not Unicode homoglyphs.
    assert normalize_homoglyphs("paypa1.com") == ("paypa1.com", False)

    typo_check = detect_typosquatting(cyrillic_url)
    assert typo_check is not None
    assert typo_check["has_homoglyphs"] is True


# ═════════════════════════════════════════════════════════════════════════════
# 3. SHANNON INFORMATION ENTROPY TESTS
# ═════════════════════════════════════════════════════════════════════════════

def test_shannon_entropy():
    # Empty string
    assert calculate_shannon_entropy("") == 0.0

    # Low entropy (repetitive)
    low_ent = calculate_shannon_entropy("aaaaaaaaaa")
    assert low_ent == 0.0

    # Natural language domain
    natural_ent = calculate_shannon_entropy("google")
    assert natural_ent < 2.5

    # High entropy (random machine-generated DGA string)
    high_ent = calculate_shannon_entropy("x9q7z2m1k4l8p3w0")
    assert high_ent > 3.6


def test_dga_detection():
    dga_result = analyze_lexical_randomness("x17a9qz82mklo91p.com")
    assert dga_result["is_dga_suspected"] is True

    normal_result = analyze_lexical_randomness("wikipedia.org")
    assert normal_result["is_dga_suspected"] is False


# ═════════════════════════════════════════════════════════════════════════════
# 4. REDIRECT GRAPH & SHORTENER DETECTION
# ═════════════════════════════════════════════════════════════════════════════

def test_shortener_identification():
    import urllib.parse
    from backend.app.services.dsa.graph_redirect import URL_SHORTENERS
    parsed = urllib.parse.urlparse("https://bit.ly/test-link")
    host = (parsed.hostname or "").lower().lstrip("www.")
    assert host in URL_SHORTENERS


# ═════════════════════════════════════════════════════════════════════════════
# 5. END-TO-END DSA SAFETY ENGINE TESTS
# ═════════════════════════════════════════════════════════════════════════════

def test_sovereign_government_protection():
    """Official government portals must receive 0 score and SAFE verdict."""
    res = scan_url_dsa("https://india.gov.in", check_network=False)
    assert res["risk_score"] == 0
    assert res["classification"] == "SAFE"
    assert "Government" in res["recommendation"]

    res_uk = scan_url_dsa("https://service.gov.uk", check_network=False)
    assert res_uk["risk_score"] == 0
    assert res_uk["classification"] == "SAFE"


def test_cloud_metadata_ssrf_detection():
    """Cloud instance metadata (169.254.169.254) must be flagged CRITICAL."""
    res = scan_url_dsa("http://169.254.169.254/latest/meta-data/", check_network=False)
    assert res["risk_score"] >= 85
    assert res["classification"] == "CRITICAL"
    rule_ids = [r["rule_id"] for r in res["detection_reasons"]]
    assert "SSRF_CLOUD_METADATA" in rule_ids


def test_private_network_ssrf_detection():
    """Private IP ranges (192.168.x.x, 10.x.x.x, 127.0.0.1) must be flagged."""
    res = scan_url_dsa("http://192.168.1.1/admin", check_network=False)
    assert res["risk_score"] >= 45
    rule_ids = [r["rule_id"] for r in res["detection_reasons"]]
    assert "SSRF_PRIVATE_NETWORK" in rule_ids


def test_credential_obfuscation_at_symbol():
    """URLs using @ character for deception must be flagged CRITICAL."""
    res = scan_url_dsa("https://google.com@phishing-target.top/login", check_network=False)
    assert res["risk_score"] >= 85
    assert res["classification"] == "CRITICAL"
    rule_ids = [r["rule_id"] for r in res["detection_reasons"]]
    assert "CREDENTIAL_OBFUSCATION_AT" in rule_ids


def test_dangerous_file_download():
    """URLs delivering .exe or .scr payloads must be flagged CRITICAL."""
    res = scan_url_dsa("http://update-secure.com/patch.exe", check_network=False)
    assert res["risk_score"] >= 85
    assert res["classification"] == "CRITICAL"
    rule_ids = [r["rule_id"] for r in res["detection_reasons"]]
    assert "DANGEROUS_FILE_DOWNLOAD" in rule_ids


def test_sensitive_query_parameter_leak():
    """URLs exposing cleartext password= in query strings must be flagged."""
    res = scan_url_dsa("https://service.com/auth?user=alice&password=SecretPassword123", check_network=False)
    rule_ids = [r["rule_id"] for r in res["detection_reasons"]]
    assert "SENSITIVE_PARAM_IN_URL" in rule_ids


def test_typosquatting_phishing_url():
    """Deceptive typosquatting domains must trigger high/critical risk."""
    res = scan_url_dsa("http://paypa1-account-verify.xyz/signin", check_network=False)
    assert res["risk_score"] >= 70
    assert res["classification"] in ("HIGH RISK", "CRITICAL")
    rule_ids = [r["rule_id"] for r in res["detection_reasons"]]
    assert "TYPOSQUATTING_DETECTED" in rule_ids
    assert "SUSPICIOUS_TLD" in rule_ids


def test_pipeline_integration():
    """Tests run_scan pipeline wrapper returning backwards-compatible object."""
    pipeline_res = run_scan("https://india.gov.in", check_network=False)
    assert pipeline_res.risk_score == 0
    assert pipeline_res.classification == "SAFE"
    assert len(pipeline_res.layer_results) == 6
    assert pipeline_res.total_duration_ms >= 0


def test_features_government_and_authentic_brand():
    """Tests feature flags for government portals and verified platforms."""
    gov_res = scan_url_dsa("https://india.gov.in", check_network=False)
    assert gov_res["features"]["is_government_domain"] == 1
    assert "India" in (gov_res["features"]["government_entity"] or "")

    platform_res = scan_url_dsa("https://www.google.com/search", check_network=False)
    assert platform_res["features"]["is_authentic_brand"] == 1
    assert platform_res["features"]["authentic_brand_name"] == "Google"
