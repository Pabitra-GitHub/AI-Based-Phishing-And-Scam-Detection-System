from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, ConfigDict, field_serializer
from backend.app.schemas.scan import ScanResponse


class DashboardSummaryResponse(BaseModel):
    total_scans: int
    safe_scans: int
    suspicious_scans: int
    high_risk_scans: int
    critical_scans: int
    average_risk_score: float
    threat_detection_rate: float
    recent_scans: List[ScanResponse]
    risk_distribution: Dict[str, int]


class AuditLogResponse(BaseModel):
    id: str
    user_id: Optional[str] = None
    user_email: Optional[str] = None
    action: str
    ip_address: Optional[str] = None
    details: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

    @field_serializer("created_at")
    def serialize_created_at(self, dt: datetime, _info):
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()


class AdminStatsResponse(BaseModel):
    total_users: int
    active_users: int
    total_system_scans: int
    threats_prevented: int
    model_version: str
    system_health: str
    model_metrics: Optional[Dict[str, Any]] = None
