"""
PhishGuard AI - Admin Endpoints
Privileged management endpoints restricted to users with ADMIN role.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.app.core.database import get_db
from backend.app.models.user import User
from backend.app.models.scan import Scan
from backend.app.models.audit_log import AuditLog
from backend.app.schemas.user import UserResponse
from backend.app.schemas.dashboard import AuditLogResponse, AdminStatsResponse
from backend.app.services.ml_service import ml_service
from backend.app.services.audit_service import record_audit_log
from backend.app.api.v1.deps import get_current_admin_user

router = APIRouter(prefix="/admin", tags=["Admin"])


@router.get("/stats", response_model=AdminStatsResponse)
def get_admin_system_stats(
    admin_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Retrieve global system analytics and model metrics."""
    total_users = db.query(User).count()
    active_users = db.query(User).filter(User.is_active == True).count()
    total_scans = db.query(Scan).count()
    threats = db.query(Scan).filter(Scan.classification.in_(["SUSPICIOUS", "HIGH RISK", "CRITICAL"])).count()

    return AdminStatsResponse(
        total_users=total_users,
        active_users=active_users,
        total_system_scans=total_scans,
        threats_prevented=threats,
        model_version=ml_service.model_version,
        system_health="Operational",
        model_metrics=ml_service.metadata.get("metrics")
    )


@router.get("/users", response_model=List[UserResponse])
def list_system_users(
    admin_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """List all registered user accounts."""
    users = db.query(User).order_by(desc(User.created_at)).all()
    return [UserResponse.model_validate(u) for u in users]


@router.patch("/users/{user_id}/status", response_model=UserResponse)
def toggle_user_active_status(
    user_id: str,
    admin_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Toggle a user's active/deactivated state."""
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target user not found."
        )

    if target_user.id == admin_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate your own administrator account."
        )

    target_user.is_active = not target_user.is_active
    db.commit()
    db.refresh(target_user)

    record_audit_log(
        db=db,
        action="USER_STATUS_UPDATED",
        user_id=admin_user.id,
        details=f"Admin {admin_user.email} updated status of {target_user.email} to is_active={target_user.is_active}"
    )

    return UserResponse.model_validate(target_user)


@router.get("/audit-logs", response_model=List[AuditLogResponse])
def get_audit_trail(
    limit: int = Query(50, ge=1, le=200),
    admin_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """View recent system security audit logs."""
    logs = (
        db.query(AuditLog)
        .order_by(desc(AuditLog.created_at))
        .limit(limit)
        .all()
    )

    result = []
    for log in logs:
        user_email = log.user.email if log.user else None
        result.append(
            AuditLogResponse(
                id=log.id,
                user_id=log.user_id,
                user_email=user_email,
                action=log.action,
                ip_address=log.ip_address,
                details=log.details,
                created_at=log.created_at
            )
        )
    return result


@router.post("/reload-model")
def reload_machine_learning_model(
    admin_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Hot-reload serialized ML model artifact from disk."""
    success = ml_service.load_model()
    record_audit_log(
        db=db,
        action="MODEL_RELOADED",
        user_id=admin_user.id,
        details=f"ML Model reload triggered (Success: {success}, Version: {ml_service.model_version})"
    )
    return {
        "status": "success" if success else "warning",
        "message": "Model reloaded successfully." if success else "Model artifact not found; fallback active.",
        "model_version": ml_service.model_version
    }
