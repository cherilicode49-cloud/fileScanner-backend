from typing import Optional, List, Dict, Any
from pydantic import BaseModel


class FileScanUploadInfo(BaseModel):
    original_filename: str
    stored_filename: str
    mime_type: str
    file_size: int
    sha256_hash: str


class ExtractedFileInfo(BaseModel):
    path: str
    file_size: int
    sha256_hash: str
    mime_type: str
    scan_status: str
    threats: List[Dict[str, Any]] = []

