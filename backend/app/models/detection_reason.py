"""
PhishGuard AI - DetectionReason Model
Defines individual detection reasons, heuristic rules, or ML insights tied to a Scan.
"""

import uuid
from typing import TYPE_CHECKING
from sqlalchemy import String, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.core.database import Base

if TYPE_CHECKING:
    from backend.app.models.scan import Scan


class DetectionReason(Base):
    __tablename__ = "detection_reasons"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str | None] = mapped_column(String(100), nullable=True)
    reason: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="MEDIUM", nullable=False)
    source: Mapped[str] = mapped_column(String(20), default="RULE", nullable=False)
    layer: Mapped[str | None] = mapped_column(String(10), nullable=True)

    # Relationships
    scan: Mapped["Scan"] = relationship(back_populates="detection_reasons")
