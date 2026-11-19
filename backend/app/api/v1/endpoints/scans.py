"""
PhishGuard AI - Scans Endpoints
Handles URL scanning via the 6-layer pipeline, history, and inspection.
"""

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.app.core.database import get_db
from backend.app.core.config import settings
from backend.app.core.security import rate_limiter
from backend.app.models.user import User
from backend.app.models.scan import Scan
from backend.app.models.detection_reason import DetectionReason
from backend.app.schemas.scan import (
    ScanRequest,
    ScanResponse,
    DetectionReasonSchema,
    LayerResultSchema,
    PaginatedScansResponse
)
from backend.app.services.url_validator import validate_and_normalize_url
from backend.app.services.pipeline import run_scan
from backend.app.services.dsa import scan_url_dsa
from backend.app.services.audit_service import record_audit_log
from backend.app.api.v1.deps import get_current_user, get_current_user_optional

router = APIRouter(prefix="/scans", tags=["Scans"])


HISTORY_RETENTION_HOURS = 2


def purge_expired_scans(db: Session) -> None:
    """Remove scan history older than the two-hour retention window."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=HISTORY_RETENTION_HOURS)
    db.query(Scan).filter(Scan.created_at < cutoff).delete(synchronize_session=False)
    db.commit()


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def create_url_scan(
    request: Request,
    payload: ScanRequest,
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: Session = Depends(get_db)
):
    """
    6-Layer URL Analysis Pipeline:
    L1: Pre-Fetch Domain & URL Analytics
    L2: Network Transport & Anti-Evasion Engine
    L3: Headless Sandbox & Dynamic DOM Analysis
    L4: Multi-Modal AI (Vision + NLP)
    L5: Canary Fuzzing & Behavioral Analysis
    L6: Unified Ensemble Risk Scoring
    """
    client_ip = request.client.host if request.client else "unknown"
    purge_expired_scans(db)

    # Rate limiting on scan endpoint
    user_key = f"scan:{current_user.id}" if current_user else f"scan_ip:{client_ip}"
    if not rate_limiter.check_rate_limit(user_key, max_requests=settings.RATE_LIMIT_SCAN_PER_MINUTE, window_seconds=60):
        record_audit_log(
            db=db,
            action="RATE_LIMIT_SCAN_EXCEEDED",
            user_id=current_user.id if current_user else None,
            ip_address=client_ip,
            details=f"Rate limit exceeded for URL {payload.url[:50]}"
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Scan rate limit reached. Please wait a few seconds before scanning another URL."
        )

    # 1. URL Validation & Normalization
    is_valid, normalized_url, error_msg = validate_and_normalize_url(payload.url)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=error_msg or "Invalid URL format provided."
        )

    # Extract or generate session identifier for guest isolation (Phase 6)
    session_id = request.headers.get("X-Session-ID") or request.cookies.get("phishguard_session_id")
    if not current_user and not session_id:
        session_id = str(uuid.uuid4())

    # 2. Execute 6-Layer Pipeline
    pipeline_result = run_scan(normalized_url)

    # 3. Database Persistence
    scan = Scan(
        user_id=current_user.id if current_user else None,
        session_id=session_id if not current_user else None,
        input_type="URL",
        input_value=normalized_url,
        risk_score=pipeline_result.risk_score,
        rule_score=pipeline_result.rule_score,
        classification=pipeline_result.classification,
        ml_probability=pipeline_result.ml_probability,
        model_version=pipeline_result.model_version,
        recommendation=pipeline_result.recommendation,
        layer_results=json.dumps([lr.to_dict() for lr in pipeline_result.layer_results]),
        redirect_chain=json.dumps(pipeline_result.redirect_chain) if pipeline_result.redirect_chain else None,
        screenshot_path=pipeline_result.screenshot_path,
        scan_duration_ms=pipeline_result.total_duration_ms,
        layers_executed=",".join(pipeline_result.layers_executed)
    )
    db.add(scan)
    db.flush()  # obtain scan.id

    # Persist Detection Reasons from all layers
    for r in pipeline_result.reasons:
        reason_obj = DetectionReason(
            scan_id=scan.id,
            title=r.get("title", "Security Finding"),
            reason=r["reason"],
            severity=r["severity"],
            source=r["source"],
            layer=r.get("layer")
        )
        db.add(reason_obj)

    db.commit()
    db.refresh(scan)

    # 4. Audit Log
    record_audit_log(
        db=db,
        action="SCAN_COMPLETED",
        user_id=current_user.id if current_user else None,
        ip_address=client_ip,
        details=f"Scanned URL: {normalized_url} -> Score: {scan.risk_score} (Rules: {scan.rule_score}, ML: {scan.ml_probability}) "
                f"[{','.join(pipeline_result.layers_executed)}] in {pipeline_result.total_duration_ms}ms"
    )

    # 5. Build response
    layer_results_schemas = [
        LayerResultSchema(**lr.to_dict()) for lr in pipeline_result.layer_results
    ]

    return ScanResponse(
        id=scan.id,
        user_id=scan.user_id,
        session_id=scan.session_id,
        input_type=scan.input_type,
        input_value=scan.input_value,
        risk_score=scan.risk_score,
        rule_score=scan.rule_score or 0,
        classification=scan.classification,
        ml_probability=scan.ml_probability,
        model_version=scan.model_version,
        recommendation=scan.recommendation,
        created_at=scan.created_at,
        detection_reasons=[
            DetectionReasonSchema(
                id=r.id,
                title=r.title,
                reason=r.reason,
                severity=r.severity,
                source=r.source,
                layer=r.layer
            )
            for r in scan.detection_reasons
        ],
        features=pipeline_result.features,
        layer_results=layer_results_schemas,
        redirect_chain=pipeline_result.redirect_chain,
        screenshot_url=pipeline_result.screenshot_path,
        scan_duration_ms=pipeline_result.total_duration_ms,
        layers_executed=",".join(pipeline_result.layers_executed)
    )


@router.get("", response_model=PaginatedScansResponse)
def get_user_scans(
    request: Request,
    page: int = Query(1, ge=1, le=10000, description="Page number"),
    page_size: int = Query(10, ge=1, le=100, description="Items per page"),
    classification: Optional[str] = Query(None, description="Filter by SAFE, SUSPICIOUS, HIGH RISK, CRITICAL"),
    search: Optional[str] = Query(None, description="Search by URL"),
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: Session = Depends(get_db)
):
    """
    Return paginated list of scans.
    Strict Ownership Enforcement (Phase 6):
    - Authenticated users access only their own scans (or all if ADMIN).
    - Guest users access only scans created with their active session ID (X-Session-ID or cookie).
    - Unauthenticated callers without session ID receive an empty list to prevent cross-user data leakage.
    """
    purge_expired_scans(db)
    session_id = request.headers.get("X-Session-ID") or request.cookies.get("phishguard_session_id")

    query = db.query(Scan)
    if current_user:
        if current_user.role != "ADMIN":
            query = query.filter(Scan.user_id == current_user.id)
    elif session_id:
        query = query.filter(Scan.session_id == session_id, Scan.user_id.is_(None))
    else:
        # Prevent unfiltered exposure of other users' scans
        return PaginatedScansResponse(
            items=[],
            total=0,
            page=page,
            page_size=page_size,
            total_pages=1
        )

    if classification and classification.upper() != "ALL":
        query = query.filter(Scan.classification == classification.upper())

    if search:
        query = query.filter(Scan.input_value.ilike(f"%{search.strip()}%"))

    total = query.count()
    items = (
        query.order_by(desc(Scan.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    total_pages = (total + page_size - 1) // page_size if total > 0 else 1

    return PaginatedScansResponse(
        items=[
            ScanResponse(
                id=s.id,
                user_id=s.user_id,
                session_id=s.session_id,
                input_type=s.input_type,
                input_value=s.input_value,
                risk_score=s.risk_score,
                rule_score=s.rule_score or 0,
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
                        source=r.source,
                        layer=r.layer
                    )
                    for r in s.detection_reasons
                ],
                layers_executed=s.layers_executed,
                scan_duration_ms=s.scan_duration_ms
            )
            for s in items
        ],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages
    )


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan_by_id(
    scan_id: str,
    request: Request,
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: Session = Depends(get_db)
):
    """Retrieve detailed scan record and feature breakdown by ID."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan record not found."
        )

    # Sanitize user_id if viewer is not the scan owner or admin
    is_owner = bool(current_user and (current_user.id == scan.user_id or current_user.role == "ADMIN"))
    exposed_user_id = scan.user_id if is_owner else None
    exposed_session_id = scan.session_id if is_owner else None

    # Extract dynamic features for inspection breakdown
    features = scan_url_dsa(scan.input_value, check_network=False).get("features", {})

    # Parse JSON serialized pipeline fields
    layer_results = []
    if scan.layer_results:
        try:
            raw_layers = json.loads(scan.layer_results)
            layer_results = [LayerResultSchema(**l) for l in raw_layers]
        except Exception:
            layer_results = []

    redirect_chain = []
    if scan.redirect_chain:
        try:
            redirect_chain = json.loads(scan.redirect_chain)
        except Exception:
            redirect_chain = []

    return ScanResponse(
        id=scan.id,
        user_id=exposed_user_id,
        session_id=exposed_session_id,
        input_type=scan.input_type,
        input_value=scan.input_value,
        risk_score=scan.risk_score,
        rule_score=scan.rule_score or 0,
        classification=scan.classification,
        ml_probability=scan.ml_probability,
        model_version=scan.model_version,
        recommendation=scan.recommendation,
        created_at=scan.created_at,
        detection_reasons=[
            DetectionReasonSchema(
                id=r.id,
                title=r.title,
                reason=r.reason,
                severity=r.severity,
                source=r.source,
                layer=r.layer
            )
            for r in scan.detection_reasons
        ],
        features=features,
        layer_results=layer_results,
        redirect_chain=redirect_chain,
        screenshot_url=scan.screenshot_path,
        scan_duration_ms=scan.scan_duration_ms,
        layers_executed=scan.layers_executed
    )


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(
    scan_id: str,
    request: Request,
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: Session = Depends(get_db)
):
    """
    Delete a scan owned by the user (or as ADMIN, or matching guest session).
    Strict Ownership Enforcement (Phase 6):
    - Authenticated user can delete only their own scans (or ADMIN can delete any).
    - Guest can delete only guest scans matching their session (X-Session-ID).
    - Guests cannot delete authenticated users' scans.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan record not found."
        )

    session_id = request.headers.get("X-Session-ID") or request.cookies.get("phishguard_session_id")

    if current_user:
        if current_user.role != "ADMIN" and scan.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to delete this scan."
            )
    else:
        # Caller is guest
        if scan.user_id is not None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Authentication required to modify this user scan."
            )
        if not session_id or scan.session_id != session_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to delete this scan."
            )

    db.delete(scan)
    db.commit()
    return None
