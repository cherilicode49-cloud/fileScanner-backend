from typing import Optional
from fastapi import APIRouter, Query, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.dependencies import get_db
from app.services.scan_service import scan_service
from app.utils.response_handler import success_response, error_response

router = APIRouter(prefix="/scan", tags=["History & Results"])


@router.get("/history")
def get_scan_history(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(10, ge=1, le=100, description="Items per page"),
    db: Session = Depends(get_db)
):
    """List historical scan records with pagination."""
    history = scan_service.list_history(db=db, page=page, page_size=limit)
    return success_response(
        data=history,
        message="Scan history retrieved successfully"
    )


@router.get("/{scan_id}")
def get_scan_result(
    scan_id: str,
    db: Session = Depends(get_db)
):
    """Retrieve full scan result and threat report by scan ID."""
    result = scan_service.get_scan_result(db=db, scan_id=scan_id)
    if not result:
        return error_response(
            message=f"Scan with ID '{scan_id}' not found",
            status_code=status.HTTP_404_NOT_FOUND
        )
    return success_response(
        data=result,
        message="Scan result retrieved successfully"
    )


@router.get("/{scan_id}/status")
def get_scan_status(
    scan_id: str,
    db: Session = Depends(get_db)
):
    """Retrieve current status of a scan by scan ID."""
    status_data = scan_service.get_scan_status(db=db, scan_id=scan_id)
    if not status_data:
        return error_response(
            message=f"Scan with ID '{scan_id}' not found",
            status_code=status.HTTP_404_NOT_FOUND
        )
    return success_response(
        data=status_data,
        message="Scan status retrieved successfully"
    )

