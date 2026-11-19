"""
PhishGuard AI - User Model
Defines the User entity with UUID, role (USER/ADMIN), authentication attributes, and relationships.
"""

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from sqlalchemy import String, Boolean, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.core.database import Base

if TYPE_CHECKING:
    from backend.app.models.audit_log import AuditLog
    from backend.app.models.scan import Scan


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(20), default="USER", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )

    # Relationships
    scans: Mapped[list["Scan"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        order_by="desc(Scan.created_at)",
    )
    audit_logs: Mapped[list["AuditLog"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )
