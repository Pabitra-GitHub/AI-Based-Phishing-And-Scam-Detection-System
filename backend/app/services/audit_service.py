"""
PhishGuard AI - Audit Logging Service
Records system actions, logins, scans, and administration changes.
"""

from typing import Optional
from sqlalchemy.orm import Session
from backend.app.models.audit_log import AuditLog


def record_audit_log(
    db: Session,
    action: str,
    user_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    details: Optional[str] = None
) -> AuditLog:
    """Record an audit entry in the database."""
    log = AuditLog(
        user_id=user_id,
        action=action,
        ip_address=ip_address,
        details=details
    )
    db.add(log)
    try:
        db.commit()
        db.refresh(log)
    except Exception:
        db.rollback()
    return log
