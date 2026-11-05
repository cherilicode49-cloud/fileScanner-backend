import os
import shutil
import zipfile
import uuid
import hashlib
import logging
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
from app.config import settings
from app.utils.file_validation import inspect_file, sanitize_filename
from app.utils.hash_utils import calculate_sha256

logger = logging.getLogger(__name__)


class ZipInspectionError(Exception):
    def __init__(self, message: str, status_code: str = "ERROR"):
        super().__init__(message)
        self.status_code = status_code


class ZipService:
    def __init__(self):
        self.temp_dir = settings.temp_path

    def inspect_and_extract(
        self,
        zip_path: Path,
        max_depth: Optional[int] = None,
        current_depth: int = 1
    ) -> Tuple[Path, List[Dict[str, Any]], Dict[str, Any]]:
        """
        Safely inspects and extracts a ZIP archive into a temporary directory.
        Returns: (extraction_dir, list_of_extracted_file_records, stats)
        """
        limit_depth = max_depth if max_depth is not None else settings.MAX_NESTED_ZIP_DEPTH
        if current_depth > limit_depth:
            raise ZipInspectionError(
                f"Maximum nested ZIP depth of {limit_depth} exceeded.",
                status_code="UNABLE_TO_SCAN"
            )

        if not zip_path.exists():
            raise ZipInspectionError(f"ZIP file not found: {zip_path}")

        session_id = uuid.uuid4().hex
        extract_root = self.temp_dir / f"zip_extract_{session_id}"
        extract_root.mkdir(parents=True, exist_ok=True)

        if not zipfile.is_zipfile(zip_path):
            self.cleanup(extract_root)
            raise ZipInspectionError("The uploaded file is not a valid ZIP archive.")

        total_extracted_size = 0
        total_files_count = 0
        extracted_records = []

        try:
            with zipfile.ZipFile(zip_path, "r") as archive:
                infolist = archive.infolist()

                if len(infolist) > settings.MAX_ZIP_FILES:
                    raise ZipInspectionError(
                        f"ZIP contains {len(infolist)} entries, exceeding the maximum limit of {settings.MAX_ZIP_FILES} files."
                    )

                for member in infolist:
                    # Detect encryption
                    if member.flag_bits & 0x1:
                        raise ZipInspectionError(
                            f"Archive contains password-protected or encrypted file: {member.filename}",
                            status_code="UNABLE_TO_SCAN"
                        )

                    # Path traversal check
                    member_path = member.filename
                    normalized = os.path.normpath(member_path)
                    if normalized.startswith("..") or os.path.isabs(normalized) or ":" in normalized:
                        raise ZipInspectionError(
                            f"Security warning: Potential ZIP path traversal detected in entry: {member.filename}"
                        )

                    # Check uncompressed size for ZIP bomb protection
                    total_extracted_size += member.file_size
                    if total_extracted_size > settings.max_zip_extract_bytes:
                        raise ZipInspectionError(
                            f"ZIP bomb protection triggered: Extracted size exceeds {settings.MAX_ZIP_EXTRACT_SIZE_MB}MB limit."
                        )

                    # Compression ratio check for individual files
                    if member.compress_size > 0:
                        ratio = member.file_size / member.compress_size
                        if ratio > 100.0 and member.file_size > 10 * 1024 * 1024:
                            raise ZipInspectionError(
                                f"ZIP bomb protection: Suspicious compression ratio ({ratio:.1f}:1) for {member.filename}"
                            )

                    if member.is_dir():
                        continue

                    total_files_count += 1
                    target_file_path = extract_root / normalized
                    target_file_path.parent.mkdir(parents=True, exist_ok=True)

                    # Read and hash content in memory
                    is_quarantined = False
                    sha256_hash = ""
                    header_buf = b""
                    try:
                        with archive.open(member) as source:
                            content = source.read()
                            sha256_hash = hashlib.sha256(content).hexdigest()
                            header_buf = content[:2048]
                            try:
                                with open(target_file_path, "wb") as target:
                                    target.write(content)
                            except PermissionError:
                                logger.warning("PermissionError writing %s - locked by host antivirus.", target_file_path)
                                is_quarantined = True
                    except PermissionError:
                        is_quarantined = True

                    mime_type = "application/octet-stream"
                    if not is_quarantined and target_file_path.exists():
                        try:
                            mime_type, _, _ = inspect_file(target_file_path)
                        except PermissionError:
                            is_quarantined = True

                    is_nested_zip = False
                    if not is_quarantined and target_file_path.exists():
                        try:
                            is_nested_zip = zipfile.is_zipfile(target_file_path)
                        except Exception:
                            pass

                    extracted_records.append({
                        "original_path": member.filename,
                        "extracted_path": target_file_path,
                        "file_size": member.file_size,
                        "mime_type": mime_type,
                        "sha256_hash": sha256_hash,
                        "is_nested_zip": is_nested_zip,
                        "is_quarantined": is_quarantined,
                        "header_buf": header_buf,
                        "depth": current_depth
                    })

        except ZipInspectionError:
            self.cleanup(extract_root)
            raise
        except zipfile.BadZipFile as e:
            self.cleanup(extract_root)
            raise ZipInspectionError(f"Corrupted or invalid ZIP file: {str(e)}")
        except Exception as e:
            self.cleanup(extract_root)
            raise ZipInspectionError(f"Error processing ZIP archive: {str(e)}")

        stats = {
            "total_files": total_files_count,
            "total_extracted_size": total_extracted_size,
            "archive_sha256": calculate_sha256(zip_path) if zip_path.exists() else ""
        }

        return extract_root, extracted_records, stats

    def cleanup(self, path: Path):
        """Safely removes extraction directory."""
        try:
            if path.exists() and path.is_dir():
                shutil.rmtree(path, ignore_errors=True)
        except Exception as e:
            logger.warning("Error cleaning up temp directory %s: %s", path, e)


zip_service = ZipService()
