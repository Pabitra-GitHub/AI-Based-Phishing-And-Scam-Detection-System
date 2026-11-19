"""
PhishGuard AI - Comprehensive Health & Diagnostics Endpoint (Phase 8)
"""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.services.ml_service import ml_service
from backend.app.services.threat_intelligence import threat_intel_service

router = APIRouter()


@router.get("/health", tags=["Health"])
def health_check(response: Response, db: Session = Depends(get_db)):
    """Comprehensive service health and dependency diagnostics check."""
    checks = {}
    is_overall_healthy = True

    # 1. Database Connectivity Check
    try:
        db.execute(text("SELECT 1"))
        checks["database"] = {
            "status": "healthy",
            "dialect": db.bind.dialect.name if db.bind else "unknown",
            "message": "Connected and responsive"
        }
    except Exception as e:
        is_overall_healthy = False
        checks["database"] = {
            "status": "unhealthy",
            "error": str(e)[:100]
        }

    # 2. ML Model Engine Check
    model_loaded = ml_service.model is not None
    if model_loaded:
        checks["machine_learning"] = {
            "status": "healthy",
            "model_version": ml_service.model_version,
            "feature_count": len(ml_service.metadata.get("features", [])) or 18,
            "model_type": ml_service.metadata.get("model_type", "LogisticRegression")
        }
    else:
        is_overall_healthy = False
        checks["machine_learning"] = {
            "status": "unhealthy",
            "message": "ML model failed to load into memory"
        }

    # 3. Optional Threat Intelligence Feeds Check
    configured_feeds = []
    if settings.VIRUSTOTAL_API_KEY:
        configured_feeds.append("VirusTotal")
    if settings.GOOGLE_SAFE_BROWSING_KEY:
        configured_feeds.append("GoogleSafeBrowsing")
    if settings.ABUSEIPDB_API_KEY:
        configured_feeds.append("AbuseIPDB")

    checks["threat_intelligence"] = {
        "status": "operational",
        "configured_feeds": configured_feeds,
        "cache_ttl_seconds": threat_intel_service.cache_ttl
    }

    if not is_overall_healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "healthy" if is_overall_healthy else "unhealthy",
        "app_name": settings.APP_NAME,
        "environment": settings.APP_ENV,
        "checks": checks,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
