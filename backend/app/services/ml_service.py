"""
PhishGuard AI - ML Inference Service
Loads serialized Scikit-learn model and provides fast, resilient probability inference.
"""

import os
import json
import logging
from typing import Dict, Any, Tuple, Optional
import joblib
import numpy as np

from backend.app.services.feature_extractor import FEATURE_COLUMNS, get_feature_vector

logger = logging.getLogger(__name__)

DEFAULT_MODEL_PATH = "ml/models/phishing_model.joblib"
DEFAULT_METADATA_PATH = "ml/models/model_metadata.json"


class MLInferenceService:
    def __init__(self, model_path: Optional[str] = None, metadata_path: Optional[str] = None):
        self.model_path = model_path or DEFAULT_MODEL_PATH
        self.metadata_path = metadata_path or DEFAULT_METADATA_PATH
        self.model = None
        self.metadata = {}
        self.model_version = "v1.0.0-heuristic-fallback"
        self.load_model()

    def load_model(self) -> bool:
        """Load serialized model and metadata from disk."""
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                logger.info(f"Loaded ML model successfully from {self.model_path}")
            except Exception as e:
                logger.error(f"Error loading ML model from {self.model_path}: {e}")
                self.model = None

        if os.path.exists(self.metadata_path):
            try:
                with open(self.metadata_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
                    self.model_version = self.metadata.get("model_version", "v1.0.0")
            except Exception as e:
                logger.warning(f"Error reading model metadata: {e}")

        return self.model is not None

    def predict_probability(self, features: Dict[str, Any]) -> Tuple[float, str]:
        """
        Calculates raw phishing probability (0.0 to 1.0) and returns (probability, model_version).
        """
        if self.model is not None:
            try:
                vector = np.array([get_feature_vector(features)], dtype=np.float64)
                # Model is a pipeline with standard scaler
                proba = float(self.model.predict_proba(vector)[0][1])
                return round(proba, 4), self.model_version
            except Exception as e:
                logger.error(f"Inference exception, using heuristic calculation: {e}")

        # Graceful fallback heuristic calculation if model not present
        score = 0.0
        if features.get("has_brand_keyword", 0):
            score += 0.35
        if features.get("has_suspicious_tld", 0):
            score += 0.30
        if features.get("has_ip_address", 0):
            score += 0.40
        if features.get("num_subdomains", 0) >= 2:
            score += 0.20
        if not features.get("is_https", 1):
            score += 0.15
        if features.get("has_punycode", 0):
            score += 0.35
        if features.get("num_at_symbols", 0) > 0:
            score += 0.45

        fallback_prob = min(max(score, 0.02), 0.98)
        return round(fallback_prob, 4), "v1.0.0-fallback"


# Global singleton instance
ml_service = MLInferenceService()
