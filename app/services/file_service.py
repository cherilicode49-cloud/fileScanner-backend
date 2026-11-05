import os
import shutil
import hashlib
import logging
from pathlib import Path
from typing import Tuple, Dict, Any, BinaryIO
from fastapi import UploadFile, HTTPException, status
from app.config import settings
from app.utils.file_validation import (
    sanitize_filename,
    generate_stored_filename,
    inspect_file,
    validate_file_size
)

logger = logging.getLogger(__name__)


class FileService:
    def __init__(self):
        self.upload_dir = settings.upload_path
        self.temp_dir = settings.temp_path

    async def save_uploaded_file(self, upload_file: UploadFile) -> Dict[str, Any]:
        """
        Safely saves an uploaded file to the upload directory.
        Calculates SHA256 and captures header bytes during streaming.
        Detects if host OS antivirus (e.g. Windows Defender) locks/quarantines the file.
        """
        original_name = upload_file.filename or "unknown_file"
        safe_original_name = sanitize_filename(original_name)
        stored_name, ext = generate_stored_filename(safe_original_name)
        dest_path = self.upload_dir / stored_name

        total_bytes = 0
        max_bytes = settings.max_file_size_bytes
        sha256_calc = hashlib.sha256()
        header_buffer = bytearray()
        host_quarantined = False

        try:
            with open(dest_path, "wb") as buffer:
                while True:
                    chunk = await upload_file.read(64 * 1024)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    if total_bytes > max_bytes:
                        buffer.close()
                        try:
                            if dest_path.exists():
                                dest_path.unlink()
                        except Exception:
                            pass
                        raise HTTPException(
                            status_code=getattr(status, "HTTP_413_CONTENT_TOO_LARGE", 413),
                            detail=f"File exceeds maximum allowed size of {settings.MAX_FILE_SIZE_MB}MB"
                        )
                    sha256_calc.update(chunk)
                    if len(header_buffer) < 2048:
                        header_buffer.extend(chunk[:2048 - len(header_buffer)])
                    try:
                        buffer.write(chunk)
                    except PermissionError:
                        logger.warning("PermissionError while writing %s - locked by host antivirus.", dest_path)
                        host_quarantined = True
                        break
        except PermissionError:
            logger.warning("PermissionError accessing %s - file locked by host OS antivirus.", dest_path)
            host_quarantined = True
        except HTTPException:
            raise
        except Exception as e:
            try:
                if dest_path.exists():
                    dest_path.unlink()
            except Exception:
                pass
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error saving uploaded file: {str(e)}"
            )

        mime_type = "application/octet-stream"
        detected_ext = ext
        file_size = total_bytes

        if not host_quarantined and dest_path.exists():
            try:
                mime_type, detected_ext, file_size = inspect_file(dest_path)
            except PermissionError:
                logger.warning("PermissionError inspecting %s - locked by host antivirus.", dest_path)
                host_quarantined = True
            except Exception:
                pass

        sha256_hash = sha256_calc.hexdigest()

        return {
            "original_filename": safe_original_name,
            "stored_filename": stored_name,
            "file_path": dest_path,
            "file_extension": ext or detected_ext,
            "mime_type": mime_type,
            "file_size": file_size,
            "sha256_hash": sha256_hash,
            "is_empty": file_size == 0,
            "host_quarantined": host_quarantined,
            "header_buffer": bytes(header_buffer)
        }

    def cleanup_file(self, file_path: Path):
        """Safely delete a file if it exists."""
        try:
            if file_path.exists():
                file_path.unlink()
        except Exception:
            pass


file_service = FileService()
