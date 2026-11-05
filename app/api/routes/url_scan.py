from typing import Optional
from fastapi import APIRouter, Body, Query, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.dependencies import get_db
from app.config import settings
from app.schemas.url_schema import URLScanRequest
from app.services.scan_service import scan_service
from app.utils.response_handler import success_response, error_response
from app.utils.security_utils import validate_url_security

router = APIRouter(prefix="/scan", tags=["Scanning"])


@router.post("/url")
@router.post("/url/")
def scan_url_endpoint(
    payload: URLScanRequest = Body(...),
    sync: Optional[bool] = Query(None, description="Force synchronous execution"),
    db: Session = Depends(get_db)
):
    """
    Scan and analyze a website URL for security indicators, phishing, and malware.
    Implements strict SSRF protection (blocking localhost, private IP ranges, cloud metadata).
    """
    target_url = payload.url.strip()

    is_safe, error_msg, _ = validate_url_security(target_url)
    if not is_safe:
        return error_response(
            message=f"URL validation failed: {error_msg}",
            status_code=status.HTTP_400_BAD_REQUEST,
            data={"url": target_url, "reason": error_msg}
        )

    scan_record = scan_service.create_scan_record(
        db=db,
        scan_type="URL",
        target_url=target_url
    )
    scan_id = scan_record.scan_id

    is_sync = sync if sync is not None else (not settings.ASYNC_SCAN_ENABLED)

    if is_sync:
        result = scan_service.scan_url_sync(db=db, scan_id=scan_id, url=target_url)
        return success_response(
            data=result,
            message="Scan completed",
            status_code=status.HTTP_200_OK
        )
    else:
        try:
            from app.tasks.scan_tasks import task_scan_url
            task_scan_url.delay(scan_id=scan_id, url=target_url)
        except Exception:
            result = scan_service.scan_url_sync(db=db, scan_id=scan_id, url=target_url)
            return success_response(
                data=result,
                message="Scan completed (executed synchronously: background queue unreachable)",
                status_code=status.HTTP_200_OK
            )

        return success_response(
            data={
                "scan_id": scan_id,
                "scan_status": "SCANNING",
                "scan_type": "URL"
            },
            message="Scan submitted successfully",
            status_code=status.HTTP_202_ACCEPTED
        )


@router.get("/url")
@router.get("/url/")
def url_scan_get_not_allowed():
    """Helpful rejection if a client attempts a GET request on url scan endpoint."""
    return error_response(
        message="The URL scan endpoint requires HTTP POST with JSON body. Example: curl -X POST 'http://127.0.0.1:8000/api/scan/url?sync=true' -H 'Content-Type: application/json' -d '{\"url\": \"https://example.com\"}'",
        status_code=status.HTTP_405_METHOD_NOT_ALLOWED
    )
