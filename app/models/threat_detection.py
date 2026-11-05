from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


class ThreatDetection(Base):
    __tablename__ = "threat_detections"

    id = Column(Integer, primary_key=True, index=True)
    scan_history_id = Column(Integer, ForeignKey("scan_histories.id", ondelete="CASCADE"), nullable=False)
    scan_file_id = Column(Integer, ForeignKey("scan_files.id", ondelete="CASCADE"), nullable=True)
    scanner_name = Column(String(50), nullable=False)  # clamav, yara, url_analyzer
    threat_name = Column(String(255), nullable=False)
    threat_category = Column(String(100), nullable=False)  # malware, heuristic, phishing, etc.
    severity = Column(String(50), nullable=False, default="HIGH")  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    scan_history = relationship("ScanHistory", back_populates="threats")
    scan_file = relationship("ScanFile", back_populates="threats")
