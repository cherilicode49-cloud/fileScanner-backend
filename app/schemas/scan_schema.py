from datetime import datetime
from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class ScanStatus(str, Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    SCANNING = "SCANNING"
    ERROR = "ERROR"
    UNABLE_TO_SCAN = "UNABLE_TO_SCAN"


class ScanType(str, Enum):
    FILE = "FILE"
    ZIP = "ZIP"
    URL = "URL"


class ThreatDetail(BaseModel):
    scanner_name: str
    threat_name: str
    threat_category: str
    severity: str
    description: Optional[str] = None


class ScannerDetail(BaseModel):
    status: str
    threats: List[Dict[str, Any]] = Field(default_factory=list)
    matched_rules: Optional[List[Dict[str, Any]]] = None
    error: Optional[str] = None


class ScanSubmissionData(BaseModel):
    scan_id: str
    scan_status: str
    scan_type: str


class FileScanResultData(BaseModel):
    scan_id: str
    scan_type: str = "FILE"
    file_name: Optional[str] = None
    file_size: Optional[int] = None
    file_hash: Optional[str] = None
    mime_type: Optional[str] = None
    scan_status: str
    scanner_results: Dict[str, Any] = Field(default_factory=dict)
    detected_threats: List[Dict[str, Any]] = Field(default_factory=list)
    completed_at: Optional[datetime] = None


class ZipScanResultData(BaseModel):
    scan_id: str
    scan_type: str = "ZIP"
    archive_name: Optional[str] = None
    archive_size: Optional[int] = None
    archive_hash: Optional[str] = None
    total_files: int = 0
    scanned_files_count: int = 0
    scan_status: str
    files: List[Dict[str, Any]] = Field(default_factory=list)
    scanner_results: Dict[str, Any] = Field(default_factory=dict)
    detected_threats: List[Dict[str, Any]] = Field(default_factory=list)
    completed_at: Optional[datetime] = None


class URLScanResultData(BaseModel):
    scan_id: str
    scan_type: str = "URL"
    url: str
    final_url: Optional[str] = None
    scan_status: str
    https_supported: bool = False
    redirect_count: int = 0
    redirect_chain: List[str] = Field(default_factory=list)
    security_indicators: Dict[str, Any] = Field(default_factory=dict)
    scanner_results: Dict[str, Any] = Field(default_factory=dict)
    detected_threats: List[Dict[str, Any]] = Field(default_factory=list)
    completed_at: Optional[datetime] = None


class ScanHistoryItem(BaseModel):
    scan_id: str
    scan_type: str
    target_name: Optional[str] = None
    target_url: Optional[str] = None
    overall_status: str
    scanner_status: Optional[Dict[str, Any]] = None
    created_at: datetime
    completed_at: Optional[datetime] = None


class ScanHistoryPagination(BaseModel):
    total: int
    page: int
    page_size: int
    total_pages: int
    items: List[ScanHistoryItem]

