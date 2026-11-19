"""
PhishGuard AI - DSA Module: Levenshtein Distance & Homoglyph Engine
Implements Dynamic Programming (Levenshtein Edit Distance) and Homoglyph mapping
to detect typosquatting, visual mimicry, and brand impersonation.
"""

from typing import Dict, Any, List, Optional, Tuple


# Common Unicode Homoglyphs (Cyrillic / Greek / Armenian visually identical to Latin)
HOMOGLYPH_MAP: Dict[str, str] = {
    # Cyrillic lookalikes
    "\u0430": "a", "\u0410": "A",
    "\u0441": "c", "\u0421": "C",
    "\u0435": "e", "\u0415": "E",
    "\u0456": "i", "\u0406": "I",
    "\u0458": "j", "\u0408": "J",
    "\u043e": "o", "\u041e": "O",
    "\u0440": "p", "\u0420": "P",
    "\u0455": "s", "\u0405": "S",
    "\u0445": "x", "\u0425": "X",
    "\u0443": "y", "\u0423": "Y",
    "\u0432": "b", "\u0412": "B",
    "\u043c": "m", "\u041c": "M",
    "\u043d": "h", "\u041d": "H",
    "\u0442": "t", "\u0422": "T",
    "\u0434": "d", "\u0414": "D",
    "\u043a": "k", "\u041a": "K",
    "\u043b": "l",
    "\u0437": "3",
    # Greek lookalikes
    "\u03b1": "a", "\u0391": "A",
    "\u03b2": "b", "\u0392": "B",
    "\u03b5": "e", "\u0395": "E",
    "\u03bf": "o", "\u039f": "O",
    "\u03c1": "p", "\u03a1": "P",
    "\u03bd": "v", "\u039d": "N",
    "\u03ba": "k", "\u039a": "K",
    "\u03bc": "m", "\u039c": "M",
    "\u03c4": "t", "\u03a4": "T",
    "\u03c7": "x", "\u03a7": "X",
    "\u03b7": "n", "\u0397": "H",
    # Armenian lookalikes
    "\u0585": "o",
    "\u0578": "u",
}

# Top 100+ Targeted Brands and Financial Platforms
POPULAR_BRANDS: List[str] = [
    # Global Tech
    "google", "microsoft", "apple", "amazon", "netflix", "facebook", "instagram",
    "whatsapp", "twitter", "linkedin", "tiktok", "youtube", "dropbox", "github",
    "adobe", "spotify", "yahoo", "telegram", "zoom", "salesforce", "oracle",
    "discord", "reddit", "twitch", "cloudflare", "shopify",
    # Global Financial & Banking
    "paypal", "chase", "wellsfargo", "bankofamerica", "citibank", "capitalone",
    "barclays", "hsbc", "santander", "usbank", "pnc", "fidelity", "schwab",
    "americanexpress", "discover", "mastercard", "visa", "venmo", "cashapp",
    "stripe", "revolut", "wise", "westernunion",
    # Indian Banks & Fintech
    "icici", "icicibank", "hdfc", "hdfcbank", "sbi", "axisbank",
    "kotakbank", "pnb", "yesbank", "indusind", "federalbank", "idfcfirst",
    "paytm", "phonepe", "gpay", "razorpay", "mobikwik", "freecharge",
    "bharatpe", "cred", "slice", "jupiter", "niyo", "fi",
    # Indian Portals & Services
    "irctc", "flipkart", "myntra", "meesho", "nykaa", "snapdeal",
    "zomato", "swiggy", "ola", "uber", "makemytrip", "goibibo", "yatra",
    "policybazaar", "lenskart", "bigbasket", "grofers",
    # Crypto & Web3
    "binance", "coinbase", "metamask", "kraken", "kucoin", "bybit", "okx",
    "gemini", "blockchain", "trustwallet", "ledger", "trezor",
    "wazirx", "coindcx", "zebpay",
    # E-commerce & Logistics
    "ebay", "walmart", "aliexpress", "target", "dhl", "fedex", "ups", "usps",
    "amazon", "alibaba",
]


def normalize_homoglyphs(text: str) -> Tuple[str, bool]:
    """
    Replaces visual homoglyphs with their standard Latin ASCII equivalents.
    Returns: (normalized_text, had_homoglyphs)
    """
    has_homoglyphs = False
    chars = []
    for ch in text:
        if ch in HOMOGLYPH_MAP:
            chars.append(HOMOGLYPH_MAP[ch])
            has_homoglyphs = True
        else:
            chars.append(ch)
    return "".join(chars), has_homoglyphs


def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Dynamic Programming algorithm to compute Levenshtein Edit Distance.
    Time Complexity: O(len(s1) * len(s2))
    Space Complexity: O(min(len(s1), len(s2))) (Space-optimized row array)
    """
    if len(s1) < len(s2):
        s1, s2 = s2, s1

    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))

    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def calculate_similarity_ratio(s1: str, s2: str) -> float:
    """Computes similarity ratio (0.0 to 1.0) using Levenshtein distance."""
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0
    dist = levenshtein_distance(s1, s2)
    return round(1.0 - (dist / max_len), 4)


def detect_typosquatting(domain: str) -> Optional[Dict[str, Any]]:
    """
    Analyzes a domain name to detect typosquatting against known brands.
    Checks:
      1. Homoglyphs / Punycode
      2. Levenshtein edit distance = 1 or 2 with high similarity (>= 0.75)
      3. Brand name embedded with hyphens (e.g., paypal-security, google-verify)
    """
    if not domain:
        return None

    clean_domain = domain.lower().strip()
    # Strip common prefixes
    if clean_domain.startswith("www."):
        clean_domain = clean_domain[4:]

    # Check Punycode
    has_punycode = clean_domain.startswith("xn--") or ".xn--" in clean_domain

    # Normalize homoglyphs
    normalized_domain, has_homoglyphs = normalize_homoglyphs(clean_domain)

    # Extract primary label (second-level domain)
    labels = normalized_domain.split(".")
    # For domains like paypa1.com -> primary label is paypa1
    # For domains like login.paypa1.co.uk -> primary label is paypa1
    primary_label = labels[0] if len(labels) == 1 else labels[-2] if len(labels) >= 2 and len(labels[-1]) <= 3 and len(labels[-2]) <= 3 and len(labels) >= 3 else labels[-2] if len(labels) >= 2 else labels[0]

    # Also extract tokens by splitting on '-' and '.'
    tokens = [t for t in normalized_domain.replace(".", "-").split("-") if len(t) >= 3]

    best_match: Optional[Dict[str, Any]] = None
    min_dist = 999

    for brand in POPULAR_BRANDS:
        # 1. Exact match test: if the domain is legitimately that brand's exact domain, skip
        if clean_domain == f"{brand}.com" or clean_domain == f"{brand}.org" or clean_domain == f"{brand}.net":
            continue

        # 2. Check primary label typosquatting (edit distance 1 or 2)
        dist = levenshtein_distance(primary_label, brand)
        sim = calculate_similarity_ratio(primary_label, brand)

        if 0 < dist <= 2 and sim >= 0.75:
            if dist < min_dist:
                min_dist = dist
                best_match = {
                    "detected_brand": brand,
                    "target_label": primary_label,
                    "edit_distance": dist,
                    "similarity": sim,
                    "match_type": "TYPOSQUATTING",
                    "has_homoglyphs": has_homoglyphs,
                    "has_punycode": has_punycode,
                    "severity": "CRITICAL" if dist == 1 else "HIGH"
                }

        # 3. Check tokens for embedded brand spoofing (e.g., "paypal-security" or "account-google")
        for token in tokens:
            token_dist = levenshtein_distance(token, brand)
            if token_dist == 0:
                # Brand is explicitly present in a non-brand domain
                if not (clean_domain == f"{brand}.com" or clean_domain.endswith(f".{brand}.com")):
                    if best_match is None or best_match.get("severity") != "CRITICAL":
                        best_match = {
                            "detected_brand": brand,
                            "target_label": token,
                            "edit_distance": 0,
                            "similarity": 1.0,
                            "match_type": "EMBEDDED_BRAND_SPOOF",
                            "has_homoglyphs": has_homoglyphs,
                            "has_punycode": has_punycode,
                            "severity": "HIGH"
                        }
            elif token_dist == 1 and len(brand) >= 5:
                if best_match is None or best_match.get("edit_distance", 999) > 1:
                    best_match = {
                        "detected_brand": brand,
                        "target_label": token,
                        "edit_distance": 1,
                        "similarity": calculate_similarity_ratio(token, brand),
                        "match_type": "TOKEN_TYPOSQUAT",
                        "has_homoglyphs": has_homoglyphs,
                        "has_punycode": has_punycode,
                        "severity": "HIGH"
                    }

    if best_match:
        return best_match

    # If no brand match, but homoglyphs or punycode were present
    if has_homoglyphs or has_punycode:
        return {
            "detected_brand": None,
            "target_label": primary_label,
            "edit_distance": 0,
            "similarity": 0.0,
            "match_type": "HOMOGLYPH_DECEPTION",
            "has_homoglyphs": has_homoglyphs,
            "has_punycode": has_punycode,
            "severity": "HIGH"
        }

    return None
