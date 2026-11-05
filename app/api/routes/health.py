from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.dependencies import get_db
from app.services.clamav_service import clamav_service
from app.services.yara_service import yara_service
from app.utils.response_handler import success_response, error_response

router = APIRouter(tags=["Health"])


@router.get("/health")
def get_app_health(db: Session = Depends(get_db)):
    """Health check for application and database."""
    db_status = "HEALTHY"
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"UNHEALTHY: {str(e)}"

    return success_response(
        data={
            "status": "HEALTHY" if db_status == "HEALTHY" else "DEGRADED",
            "database": db_status,
            "application": "FileScanner Backend is operational"
        },
        message="Application health check"
    )


@router.get("/health/scanners")
def get_scanners_health():
    """Health check for ClamAV and YARA security engines."""
    clamav_info = clamav_service.get_version()
    yara_info = yara_service.get_status()

    all_engines_healthy = clamav_info.get("available", False) and yara_info.get("available", False)

    return success_response(
        data={
            "overall_status": "HEALTHY" if all_engines_healthy else "DEGRADED",
            "clamav": {
                "available": clamav_info.get("available", False),
                "version": clamav_info.get("version"),
                "database_version": clamav_info.get("database_version"),
                "database_date": clamav_info.get("database_date"),
                "error": clamav_info.get("error")
            },
            "yara": {
                "available": yara_info.get("available", False),
                "loaded_rule_files": yara_info.get("loaded_files_count", 0),
                "rule_files": yara_info.get("loaded_files", []),
                "error": yara_info.get("error")
            }
        },
        message="Scanner engines health check"
    )

