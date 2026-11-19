"""
PhishGuard AI - DSA Module: Shannon Information Entropy & Lexical Randomness
Calculates mathematical entropy and character distribution statistics
to detect Algorithmically Generated Domains (DGA), randomized subdomains,
and obfuscated URL payloads.
"""

import math
from typing import Dict, Any


def calculate_shannon_entropy(text: str) -> float:
    """
    Computes the Shannon entropy of a string: H(X) = -sum(P(x) * log2(P(x))).
    Higher entropy indicates higher randomness (e.g., machine-generated hashes or DGA).
    Standard English text/words typically have entropy between 1.5 and 3.2.
    Random hex/DGA strings typically have entropy > 3.8.
    """
    if not text:
        return 0.0

    length = len(text)
    frequency: Dict[str, int] = {}
    for char in text:
        frequency[char] = frequency.get(char, 0) + 1

    entropy = 0.0
    for count in frequency.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def analyze_lexical_randomness(domain: str, path: str = "") -> Dict[str, Any]:
    """
    Analyzes domain and path strings for signs of algorithmic generation (DGA)
    and structural obfuscation.
    """
    clean_domain = domain.lower().strip()
    if clean_domain.startswith("www."):
        clean_domain = clean_domain[4:]

    parts = clean_domain.split(".")
    primary_label = parts[0] if parts else ""
    subdomains = parts[:-2] if len(parts) > 2 else []

    domain_entropy = calculate_shannon_entropy(primary_label)
    path_entropy = calculate_shannon_entropy(path)

    # Calculate digit ratio in domain
    digits_count = sum(1 for c in clean_domain if c.isdigit())
    digit_ratio = round(digits_count / max(len(clean_domain), 1), 4)

    # Calculate consecutive consonant count
    vowels = set("aeiou")
    max_consecutive_consonants = 0
    current_consonants = 0
    for c in primary_label:
        if c.isalpha() and c not in vowels:
            current_consonants += 1
            if current_consonants > max_consecutive_consonants:
                max_consecutive_consonants = current_consonants
        else:
            current_consonants = 0

    # DGA Detection Heuristics:
    # High entropy (>= 3.5 for labels >= 6 chars) or 4+ consecutive consonants or excessive digit ratio
    is_dga_suspected = False
    reasons = []

    if len(primary_label) >= 6 and domain_entropy >= 3.5:
        is_dga_suspected = True
        reasons.append(f"High domain entropy ({domain_entropy}) indicates algorithmic/machine-generated hostname.")

    if max_consecutive_consonants >= 4 and len(primary_label) >= 6:
        is_dga_suspected = True
        reasons.append(f"Unusual consonant cluster ({max_consecutive_consonants} consecutive consonants) detected in domain, inconsistent with natural language patterns.")

    if digit_ratio >= 0.40 and len(clean_domain) >= 6:
        reasons.append(f"High numeric density ({int(digit_ratio * 100)}% digits) in domain name.")

    return {
        "domain_entropy": domain_entropy,
        "path_entropy": path_entropy,
        "digit_ratio": digit_ratio,
        "max_consecutive_consonants": max_consecutive_consonants,
        "is_dga_suspected": is_dga_suspected,
        "reasons": reasons
    }
