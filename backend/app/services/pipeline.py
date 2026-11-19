"""
PhishGuard AI - Unified Pipeline Orchestrator (DSA-Powered)
Coordinates the Data Structures & Algorithms (DSA) security engine:
  - Trie Keyword & TLD matching
  - Levenshtein Typosquatting & Homoglyphs
  - Shannon Information Entropy (DGA)
  - Graph Redirect Cycle Detection
  - Safe DNS & SSL/TLS Verification
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

from backend.app.services.dsa import scan_url_dsa
from backend.app.services.feature_extractor import extract_features
from backend.app.services.ml_service import ml_service

logger = logging.getLogger("phishguard.pipeline")


@dataclass
class LayerFinding:
    """A single security finding produced by a security check."""

    rule_id: str
    title: str
    reason: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    weight: int
    source: str = "DSA_SECURITY_ENGINE"
    layer: str = "L1"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "reason": self.reason,
            "severity": self.severity,
            "weight": self.weight,
            "source": self.source,
            "layer": self.layer,
        }


@dataclass
class LayerResult:
    """Aggregated result for an individual DSA check module."""

    layer_id: str  # L1 - L6
    layer_name: str
    executed: bool = True
    skipped_reason: Optional[str] = None
    score: float = 0.0
    findings: List[LayerFinding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    duration_ms: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "layer_id": self.layer_id,
            "layer_name": self.layer_name,
            "executed": self.executed,
            "skipped_reason": self.skipped_reason,
            "score": round(self.score, 4),
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "metadata": self.metadata,
            "duration_ms": self.duration_ms,
        }


@dataclass
class ScanPipelineResult:
    """Aggregated pipeline scan result for API & database persistence."""

    url: str
    layer_results: List[LayerResult] = field(default_factory=list)
    all_findings: List[LayerFinding] = field(default_factory=list)
    features: Dict[str, Any] = field(default_factory=dict)
    redirect_chain: List[Dict[str, Any]] = field(default_factory=list)
    screenshot_path: Optional[str] = None
    total_duration_ms: int = 0
    layers_executed: List[str] = field(default_factory=list)

    risk_score: int = 0
    rule_score: int = 0
    classification: str = "SAFE"
    ml_probability: float = 0.0
    model_version: str = "v2.0.0"
    model_type: str = "LogisticRegression"
    recommendation: str = ""
    reasons: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "layer_results": [lr.to_dict() for lr in self.layer_results],
            "redirect_chain": self.redirect_chain,
            "screenshot_path": self.screenshot_path,
            "total_duration_ms": self.total_duration_ms,
            "layers_executed": self.layers_executed,
            "risk_score": self.risk_score,
            "rule_score": self.rule_score,
            "classification": self.classification,
            "ml_probability": self.ml_probability,
            "model_version": self.model_version,
            "model_type": self.model_type,
            "recommendation": self.recommendation,
        }


def run_scan(url: str, check_network: bool = True) -> ScanPipelineResult:
    """
    Executes the comprehensive DSA-based and ML-powered phishing detection pipeline.
    Combines deterministic rule findings and calibrated ML inference into an ensemble verdict.
    """
    pipeline_start = time.time()
    logger.info(f"[Ensemble Pipeline] Starting security analysis for: {url}")

    # 1. Run master DSA security checks
    dsa_result = scan_url_dsa(url, check_network=check_network)
    rule_score = int(dsa_result.get("rule_score", dsa_result.get("risk_score", 0)))

    # 2. Extract full feature set for statistical ML inference
    features = extract_features(url, check_network=False)
    features.update(dsa_result.get("features", {}))

    # 3. Run real statistical ML model inference
    ml_prob, model_version = ml_service.predict_probability(features)
    model_type = ml_service.metadata.get("model_type", "LogisticRegression")

    # 4. Calculate Composite Risk Score (Option A: Composite Ensemble Fusion)
    # Check whitelist override
    is_gov = features.get("is_government_domain") == 1
    is_brand_auth = features.get("is_authentic_brand") == 1
    has_critical = any(
        r.get("severity") == "CRITICAL" for r in dsa_result.get("detection_reasons", [])
    )

    if is_gov or (is_brand_auth and not has_critical):
        composite_score = 0
        final_classification = "SAFE"
        recommendation = dsa_result["recommendation"]
    elif has_critical:
        # Critical deterministic signature override
        composite_score = max(rule_score, 85)
        final_classification = "CRITICAL"
        recommendation = dsa_result["recommendation"]
    else:
        # 50% Rule Evidence + 50% ML Model Probability
        ml_score = int(round(ml_prob * 100))
        composite_score = int(round(0.50 * rule_score + 0.50 * ml_score))

        # Agreement escalation
        if rule_score >= 60 and ml_prob >= 0.60:
            composite_score = max(composite_score, 75)
        elif ml_prob >= 0.88:
            composite_score = max(composite_score, 65)
        elif rule_score <= 15 and ml_prob <= 0.10:
            composite_score = min(composite_score, 15)

        composite_score = min(max(composite_score, 0), 100)

        if composite_score >= 80:
            final_classification = "CRITICAL"
            recommendation = "Do NOT visit or interact with this URL. High-probability phishing threat detected."
        elif composite_score >= 60:
            final_classification = "HIGH RISK"
            recommendation = "Strong phishing indicators detected. Avoid entering credentials or personal info."
        elif composite_score >= 35:
            final_classification = "SUSPICIOUS"
            recommendation = (
                "Suspicious attributes detected. Exercise caution before proceeding."
            )
        else:
            final_classification = "SAFE"
            recommendation = "No strong malicious signatures detected. Proceed with standard security caution."

    pipeline = ScanPipelineResult(url=url)
    pipeline.risk_score = composite_score
    pipeline.rule_score = rule_score
    pipeline.classification = final_classification
    pipeline.ml_probability = ml_prob
    pipeline.model_version = model_version
    pipeline.model_type = model_type
    pipeline.recommendation = recommendation
    pipeline.features = features
    pipeline.redirect_chain = dsa_result["redirect_chain"]
    pipeline.layers_executed = ["L1", "L2", "L3", "L4", "L5", "L6"]
    pipeline.reasons = list(dsa_result["detection_reasons"])

    # Map findings into LayerFinding dataclasses
    for r in dsa_result["detection_reasons"]:
        raw_layer = r.get("layer", "L1")
        clean_layer = raw_layer[:2] if raw_layer.startswith("L") else "L1"
        finding = LayerFinding(
            rule_id=r.get("rule_id", "DSA_RULE"),
            title=r.get("title", "Security Finding"),
            reason=r.get("reason", ""),
            severity=r.get("severity", "MEDIUM"),
            weight=r.get("weight", 10),
            source=r.get("source", "DSA_SECURITY_ENGINE"),
            layer=clean_layer,
        )
        pipeline.all_findings.append(finding)

    # If ML detected high likelihood, add ML finding (suppressed on verified sovereign government domains)
    if ml_prob >= 0.50 and not is_gov:
        ml_finding = LayerFinding(
            rule_id="ML_STATISTICAL_ANOMALY",
            title="Statistical Phishing Anomaly Detected",
            reason=f"Statistical ML Classifier ({model_type} {model_version}) detected phishing patterns with {round(ml_prob * 100, 1)}% confidence.",
            severity="CRITICAL" if ml_prob >= 0.85 else "HIGH",
            weight=int(round(ml_prob * 35)),
            source="ML_INFERENCE_ENGINE",
            layer="L4",
        )
        pipeline.all_findings.append(ml_finding)
        pipeline.reasons.append(ml_finding.to_dict())

    # Build LayerResult objects
    for lr_data in dsa_result["layer_results"]:
        findings_objs = [
            LayerFinding(
                rule_id=f.get("rule_id", "DSA_RULE"),
                title=f.get("title", "Security Finding"),
                reason=f.get("reason", ""),
                severity=f.get("severity", "MEDIUM"),
                weight=f.get("weight", 10),
                source=f.get("source", "DSA_SECURITY_ENGINE"),
                layer=f.get("layer", lr_data["layer_id"]),
            )
            for f in lr_data.get("findings", [])
        ]
        # Attach ML finding to L4 if applicable
        if lr_data["layer_id"] == "L4" and ml_prob >= 0.50 and not is_gov:
            findings_objs.append(
                LayerFinding(
                    rule_id="ML_STATISTICAL_ANOMALY",
                    title="Statistical Phishing Anomaly Detected",
                    reason=f"ML Classifier ({model_type} {model_version}) detected phishing patterns with {round(ml_prob * 100, 1)}% confidence.",
                    severity="CRITICAL" if ml_prob >= 0.85 else "HIGH",
                    weight=int(round(ml_prob * 35)),
                    source="ML_INFERENCE_ENGINE",
                    layer="L4",
                )
            )

        layer_res = LayerResult(
            layer_id=lr_data["layer_id"],
            layer_name=lr_data["layer_name"],
            executed=lr_data.get("executed", True),
            findings=findings_objs,
            metadata=lr_data.get("metadata", {}),
            duration_ms=dsa_result["scan_duration_ms"] // 6,
        )
        pipeline.layer_results.append(layer_res)

    pipeline.total_duration_ms = int((time.time() - pipeline_start) * 1000)

    logger.info(
        f"[Ensemble Scan Complete] {url} -> Composite: {pipeline.risk_score}/100 "
        f"(Rules: {rule_score}, ML: {ml_prob:.4f}, Verdict: {pipeline.classification}) in {pipeline.total_duration_ms}ms"
    )

    return pipeline
