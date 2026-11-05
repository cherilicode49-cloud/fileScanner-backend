from pathlib import Path
from typing import Optional
from fastapi import APIRouter, UploadFile, File, Query, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.dependencies import get_db
from app.config import settings
from app.services.file_service import file_service
from app.services.scan_service import scan_service
from app.utils.response_handler import success_response, error_response

router = APIRouter(prefix="/scan", tags=["Scanning"])


@router.post("/file")
async def scan_file_endpoint(
    file: UploadFile = File(..., description="The file to scan for malware and suspicious patterns"),
    sync: Optional[bool] = Query(None, description="Force synchronous execution (defaults to env setting)"),
    db: Session = Depends(get_db)
):
    """
    Upload and scan an individual file.
    Validates actual file signature, hashes contents, and scans via ClamAV and YARA.
    """
    if not file.filename:
        return error_response(message="No file uploaded or filename missing", status_code=status.HTTP_400_BAD_REQUEST)

    # Save and inspect
    file_info = await file_service.save_uploaded_file(file)

    if file_info["is_empty"]:
        return error_response(
            message="Uploaded file is empty (0 bytes)",
            status_code=status.HTTP_400_BAD_REQUEST
        )

    # Create scan history entry
    scan_record = scan_service.create_scan_record(
        db=db,
        scan_type="FILE",
        target_name=file_info["original_filename"]
    )
    scan_id = scan_record.scan_id

    # Determine if synchronous execution is requested
    is_sync = sync if sync is not None else (not settings.ASYNC_SCAN_ENABLED)

    if is_sync:
        result = scan_service.scan_file_sync(
            db=db,
            scan_id=scan_id,
            file_path=Path(file_info["file_path"]),
            original_filename=file_info["original_filename"],
            mime_type=file_info["mime_type"],
            file_size=file_info["file_size"],
            sha256_hash=file_info["sha256_hash"],
            host_quarantined=file_info.get("host_quarantined", False),
            header_buffer=file_info.get("header_buffer", b"")
        )
        return success_response(
            data=result,
            message="Scan completed",
            status_code=status.HTTP_200_OK
        )
    else:
        # Background task queueing
        try:
            from app.tasks.scan_tasks import task_scan_file
            task_scan_file.delay(
                scan_id=scan_id,
                file_path_str=str(file_info["file_path"]),
                original_filename=file_info["original_filename"],
                mime_type=file_info["mime_type"],
                file_size=file_info["file_size"],
                sha256_hash=file_info["sha256_hash"]
            )
        except Exception:
            result = scan_service.scan_file_sync(
                db=db,
                scan_id=scan_id,
                file_path=Path(file_info["file_path"]),
                original_filename=file_info["original_filename"],
                mime_type=file_info["mime_type"],
                file_size=file_info["file_size"],
                sha256_hash=file_info["sha256_hash"],
                host_quarantined=file_info.get("host_quarantined", False),
                header_buffer=file_info.get("header_buffer", b"")
            )
            return success_response(
                data=result,
                message="Scan completed (executed synchronously: background queue unreachable)",
                status_code=status.HTTP_200_OK
            )

        return success_response(
            data={
                "scan_id": scan_id,
                "scan_status": "SCANNING",
                "scan_type": "FILE"
            },
            message="Scan submitted successfully",
            status_code=status.HTTP_202_ACCEPTED
        )
