from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.database import Base


class ScanReport(Base):
    __tablename__ = "scan_reports"

    id = Column(Integer, primary_key=True, index=True)
    scan_history_id = Column(Integer, ForeignKey("scan_histories.id", ondelete="CASCADE"), nullable=False)
    report_json = Column(JSON, nullable=False)
    report_path = Column(String(255), nullable=True)  # path to PDF report
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    scan_history = relationship("ScanHistory", back_populates="reports")
