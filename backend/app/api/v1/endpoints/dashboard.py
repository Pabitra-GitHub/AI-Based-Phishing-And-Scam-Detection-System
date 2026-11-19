"""
PhishGuard AI - Dashboard Endpoints
Provides statistical summaries and activity metrics for the authenticated user.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.app.core.database import get_db
from backend.app.models.user import User
from backend.app.models.scan import Scan
from backend.app.schemas.dashboard import DashboardSummaryResponse
from backend.app.schemas.scan import ScanResponse, DetectionReasonSchema
from backend.app.api.v1.deps import get_current_user

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/summary", response_model=DashboardSummaryResponse)
def get_user_dashboard_summary(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve statistical scan metrics, risk distribution, and recent scans for current user."""
    scans = (
        db.query(Scan)
        .filter(Scan.user_id == current_user.id)
        .order_by(desc(Scan.created_at))
        .all()
    )

    total_scans = len(scans)
    safe_scans = sum(1 for s in scans if s.classification == "SAFE")
    suspicious_scans = sum(1 for s in scans if s.classification == "SUSPICIOUS")
    high_risk_scans = sum(1 for s in scans if s.classification == "HIGH RISK")
    critical_scans = sum(1 for s in scans if s.classification == "CRITICAL")

    threat_count = suspicious_scans + high_risk_scans + critical_scans
    threat_detection_rate = round((threat_count / total_scans * 100.0), 1) if total_scans > 0 else 0.0

    avg_score = round(sum(s.risk_score for s in scans) / total_scans, 1) if total_scans > 0 else 0.0

    recent_items = [
        ScanResponse(
            id=s.id,
            user_id=s.user_id,
            input_type=s.input_type,
            input_value=s.input_value,
            risk_score=s.risk_score,
            classification=s.classification,
            ml_probability=s.ml_probability,
            model_version=s.model_version,
            recommendation=s.recommendation,
            created_at=s.created_at,
            detection_reasons=[
                DetectionReasonSchema(
                    id=r.id,
                    title=r.title,
                    reason=r.reason,
                    severity=r.severity,
                    source=r.source
                )
                for r in s.detection_reasons
            ]
        )
        for s in scans[:5]
    ]

    return DashboardSummaryResponse(
        total_scans=total_scans,
        safe_scans=safe_scans,
        suspicious_scans=suspicious_scans,
        high_risk_scans=high_risk_scans,
        critical_scans=critical_scans,
        average_risk_score=avg_score,
        threat_detection_rate=threat_detection_rate,
        recent_scans=recent_items,
        risk_distribution={
            "SAFE": safe_scans,
            "SUSPICIOUS": suspicious_scans,
            "HIGH_RISK": high_risk_scans,
            "CRITICAL": critical_scans
        }
    )
