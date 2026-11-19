from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict, field_serializer


class ScanRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048, description="URL to be analyzed")


class DetectionReasonSchema(BaseModel):
    id: Optional[str] = None
    title: Optional[str] = None
    reason: str
    severity: str # LOW, MEDIUM, HIGH, CRITICAL
    source: str # RULE, ML, VISION, NLP, CANARY, THREAT_INTEL
    layer: Optional[str] = None  # L1, L2, L3, L4, L5, L6

    model_config = ConfigDict(from_attributes=True)


class LayerResultSchema(BaseModel):
    """Schema for individual layer analysis results."""
    layer_id: str
    layer_name: str
    executed: bool = True
    skipped_reason: Optional[str] = None
    score: float = 0.0
    findings_count: int = 0
    findings: List[Dict[str, Any]] = []
    metadata: Dict[str, Any] = {}
    duration_ms: int = 0


class ScanResponse(BaseModel):
    id: str
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    input_type: str
    input_value: str
    risk_score: int
    rule_score: Optional[int] = 0
    classification: str # SAFE, SUSPICIOUS, HIGH RISK, CRITICAL
    ml_probability: float
    model_version: str
    recommendation: Optional[str] = None
    created_at: datetime
    detection_reasons: List[DetectionReasonSchema] = []
    features: Optional[Dict[str, Any]] = None

    # ── 6-Layer Pipeline Fields ──
    layer_results: Optional[List[LayerResultSchema]] = None
    redirect_chain: Optional[List[Dict[str, Any]]] = None
    screenshot_url: Optional[str] = None
    scan_duration_ms: Optional[int] = None
    layers_executed: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

    @field_serializer("created_at")
    def serialize_created_at(self, dt: datetime, _info):
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()


class PaginatedScansResponse(BaseModel):
    items: List[ScanResponse]
    total: int
    page: int
    page_size: int
    total_pages: int

