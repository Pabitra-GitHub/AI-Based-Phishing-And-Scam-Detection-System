"""
PhishGuard AI - URL Feature Extraction Module
Extracts lexical, structural, and host-based features from raw URLs for ML classification.
Guarantees 100% identical parsing and feature representation between training and inference.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, Any, List

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.services.feature_extractor import (
    FEATURE_COLUMNS,
    extract_features as _backend_extract_features,
    calculate_entropy,
    get_feature_vector,
    SUSPICIOUS_TLDS,
    BRAND_KEYWORDS,
    SHORTENER_DOMAINS,
    IPV4_PATTERN,
)


def extract_features_from_url(url: str) -> Dict[str, Any]:
    """
    Extract a dictionary of numerical/boolean features from a given URL string.
    Ensures 100% parity with live inference extraction.
    """
    return _backend_extract_features(url, check_network=False)


def features_to_vector(features: Dict[str, Any]) -> List[float]:
    """Convert feature dict to an ordered feature list matching FEATURE_COLUMNS."""
    return get_feature_vector(features)

