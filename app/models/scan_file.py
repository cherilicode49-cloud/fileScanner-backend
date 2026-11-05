from datetime import datetime, timezone
from sqlalchemy import Column, Integer, BigInteger, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


class ScanFile(Base):
    __tablename__ = "scan_files"

    id = Column(Integer, primary_key=True, index=True)
    scan_history_id = Column(Integer, ForeignKey("scan_histories.id", ondelete="CASCADE"), nullable=False)
    original_filename = Column(String(255), nullable=False)
    stored_filename = Column(String(255), nullable=False)
    file_extension = Column(String(50), nullable=True)
    mime_type = Column(String(100), nullable=True)
    file_size = Column(BigInteger, nullable=False, default=0)
    sha256_hash = Column(String(64), nullable=False, index=True)
    scan_status = Column(String(30), nullable=False, default="SCANNING")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    scan_history = relationship("ScanHistory", back_populates="files")
    threats = relationship("ThreatDetection", back_populates="scan_file", cascade="all, delete-orphan")
