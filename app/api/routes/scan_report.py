from pathlib import Path
from typing import Optional
from fastapi import APIRouter, Query, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from app.dependencies import get_db
from app.services.scan_service import scan_service
from app.services.report_service import report_service
from app.utils.response_handler import success_response, error_response
from app.models.scan_report import ScanReport
from app.models.scan_history import ScanHistory

router = APIRouter(prefix="/scan", tags=["Reports"])


@router.get("/{scan_id}/report")
def get_scan_report(
    scan_id: str,
    format: str = Query("json", description="Report format: 'json' or 'pdf'"),
    db: Session = Depends(get_db)
):
    """
    Download or view security scan report in JSON or PDF format.
    """
    scan = db.query(ScanHistory).filter(ScanHistory.scan_id == scan_id).first()
    if not scan:
        return error_response(
            message=f"Scan with ID '{scan_id}' not found",
            status_code=status.HTTP_404_NOT_FOUND
        )

    scan_result = scan_service.get_scan_result(db=db, scan_id=scan_id)
    if not scan_result:
        return error_response(
            message=f"No report available yet for scan ID '{scan_id}'",
            status_code=status.HTTP_404_NOT_FOUND
        )

    if format.lower() == "pdf":
        # Check if PDF exists in database or generate on the fly
        report_record = db.query(ScanReport).filter(ScanReport.scan_history_id == scan.id).first()
        pdf_path = None
        if report_record and report_record.report_path:
            p = Path(report_record.report_path)
            if p.exists():
                pdf_path = p

        if not pdf_path or not pdf_path.exists():
            try:
                pdf_path = report_service.generate_pdf_report(scan_result)
                if report_record:
                    report_record.report_path = str(pdf_path)
                    db.commit()
            except Exception as e:
                return error_response(
                    message=f"Failed to generate PDF report: {str(e)}",
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

        return FileResponse(
            path=str(pdf_path),
            media_type="application/pdf",
            filename=f"filescanner_report_{scan_id}.pdf"
        )
    else:
        return success_response(
            data=scan_result,
            message="JSON report retrieved successfully"
        )

