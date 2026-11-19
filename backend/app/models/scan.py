"""
PhishGuard AI - Scan Model
Defines the Scan entity representing URL scan analyses, scores, and classifications.
"""

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from sqlalchemy import String, Integer, Float, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.core.database import Base

if TYPE_CHECKING:
    from backend.app.models.detection_reason import DetectionReason
    from backend.app.models.user import User


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True
    )
    user_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    session_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    input_type: Mapped[str] = mapped_column(String(20), default="URL", nullable=False)
    input_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    rule_score: Mapped[int | None] = mapped_column(Integer, nullable=True, default=0)
    classification: Mapped[str] = mapped_column(String(30), nullable=False)
    ml_probability: Mapped[float] = mapped_column(Float, nullable=False)
    model_version: Mapped[str] = mapped_column(
        String(50), default="v2.0.0", nullable=False
    )
    recommendation: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )

    # ── 6-Layer Pipeline Columns ──
    layer_results: Mapped[str | None] = mapped_column(Text, nullable=True)
    redirect_chain: Mapped[str | None] = mapped_column(Text, nullable=True)
    screenshot_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    scan_duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    layers_executed: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Relationships
    user: Mapped["User | None"] = relationship(back_populates="scans")
    detection_reasons: Mapped[list["DetectionReason"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", lazy="joined"
    )
