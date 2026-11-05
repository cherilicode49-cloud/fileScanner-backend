import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, JSON
from sqlalchemy.orm import relationship
from app.database import Base


class ScanHistory(Base):
    __tablename__ = "scan_histories"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(36), unique=True, index=True, default=lambda: str(uuid.uuid4()))
    scan_type = Column(String(20), nullable=False)  # FILE, ZIP, URL
    target_name = Column(String(255), nullable=True)
    target_url = Column(Text, nullable=True)
    overall_status = Column(String(30), nullable=False, default="SCANNING")
    scanner_status = Column(JSON, nullable=True, default=dict)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    files = relationship("ScanFile", back_populates="scan_history", cascade="all, delete-orphan")
    threats = relationship("ThreatDetection", back_populates="scan_history", cascade="all, delete-orphan")
    reports = relationship("ScanReport", back_populates="scan_history", cascade="all, delete-orphan")
