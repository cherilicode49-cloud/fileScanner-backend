import os
import re
import uuid
import mimetypes
from pathlib import Path
from typing import Tuple, Optional, BinaryIO
import filetype
from app.config import settings

# Known magic bytes / signatures for formats where filetype might return generic stream or for scripts
SIGNATURES = [
    (b"%PDF-", "application/pdf", ".pdf"),
    (b"PK\x03\x04", "application/zip", ".zip"),
    (b"Rar!\x1a\x07", "application/x-rar-compressed", ".rar"),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed", ".7z"),
    (b"MZ", "application/x-dosexec", ".exe"),
    (b"\x7fELF", "application/x-executable", ".elf"),
    (b"\x89PNG\r\n\x1a\n", "image/png", ".png"),
    (b"\xff\xd8\xff", "image/jpeg", ".jpg"),
    (b"GIF87a", "image/gif", ".gif"),
    (b"GIF89a", "image/gif", ".gif"),
    (b"BM", "image/bmp", ".bmp"),
    (b"RIFF", "image/webp", ".webp"),
    (b"<?xml", "application/xml", ".xml"),
    (b"<?php", "application/x-php", ".php"),
    (b"<!DOCTYPE html", "text/html", ".html"),
    (b"<html", "text/html", ".html"),
]


def sanitize_filename(filename: str) -> str:
    """Strip dangerous characters and directory traversal elements."""
    filename = Path(filename).name  # extracts basename, strips paths
    # Replace non-alphanumeric except dots, dashes, underscores
    sanitized = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
    # Ensure it's not empty or just dots
    if not sanitized or sanitized.replace('.', '') == '':
        sanitized = f"upload_{uuid.uuid4().hex[:8]}.bin"
    return sanitized


def generate_stored_filename(original_filename: str) -> Tuple[str, str]:
    """
    Generates a unique server-side filename.
    Returns (stored_filename, safe_extension).
    """
    safe_name = sanitize_filename(original_filename)
    ext = Path(safe_name).suffix.lower()
    if len(ext) > 10:
        ext = ext[:10]
    unique_id = uuid.uuid4().hex
    stored_name = f"{unique_id}{ext}"
    return stored_name, ext


def inspect_file(file_path: Path) -> Tuple[str, str, int]:
    """
    Inspects a file to determine:
    1. MIME type (based on content inspection, not just extension)
    2. Suggested extension
    3. File size in bytes
    """
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    size = file_path.stat().st_size
    if size == 0:
        return "application/x-empty", "", 0

    # Read header bytes for signature inspection
    with open(file_path, "rb") as f:
        header = f.read(2048)

    # 1. Use filetype library
    kind = filetype.guess(header)
    if kind:
        mime = kind.mime
        ext = f".{kind.extension}"
        return mime, ext, size

    # 2. Check explicit signature table
    for magic, m_type, m_ext in SIGNATURES:
        if header.startswith(magic):
            return m_type, m_ext, size

    # Check for text/script patterns
    try:
        decoded = header.decode("utf-8")
        if re.search(r'^\s*<(!DOCTYPE\s+html|html)', decoded, re.IGNORECASE):
            return "text/html", ".html", size
        if re.search(r'^\s*<\?php', decoded, re.IGNORECASE):
            return "application/x-php", ".php", size
        if re.search(r'^\s*#!.*python', decoded, re.IGNORECASE):
            return "text/x-python", ".py", size
        if re.search(r'^\s*#!\s*/bin/(ba)?sh', decoded, re.IGNORECASE):
            return "text/x-shellscript", ".sh", size
        if "function" in decoded or "const " in decoded or "var " in decoded or "let " in decoded:
            return "application/javascript", ".js", size
        return "text/plain", ".txt", size
    except UnicodeDecodeError:
        pass

    # 3. Fallback to mimetypes by filename
    guess, _ = mimetypes.guess_type(file_path.name)
    if guess:
        return guess, file_path.suffix.lower(), size

    return "application/octet-stream", file_path.suffix.lower(), size


def validate_file_size(size_bytes: int, max_bytes: Optional[int] = None) -> bool:
    """Validate that file does not exceed maximum upload size."""
    limit = max_bytes or settings.max_file_size_bytes
    return size_bytes <= limit

