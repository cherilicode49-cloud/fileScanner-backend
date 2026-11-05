import logging
from pathlib import Path
from app.tasks.celery_app import celery_app
from app.database import SessionLocal
from app.services.scan_service import scan_service

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, max_retries=2, default_retry_delay=5)
def task_scan_file(
    self,
    scan_id: str,
    file_path_str: str,
    original_filename: str,
    mime_type: str,
    file_size: int,
    sha256_hash: str
):
    """Background Celery task to scan individual file."""
    logger.info("Executing Celery file scan task for scan_id %s", scan_id)
    db = SessionLocal()
    try:
        file_path = Path(file_path_str)
        result = scan_service.scan_file_sync(
            db=db,
            scan_id=scan_id,
            file_path=file_path,
            original_filename=original_filename,
            mime_type=mime_type,
            file_size=file_size,
            sha256_hash=sha256_hash
        )
        return result
    except Exception as exc:
        logger.error("Celery file scan task failed: %s", exc)
        db.rollback()
        raise self.retry(exc=exc)
    finally:
        db.close()


@celery_app.task(bind=True, max_retries=2, default_retry_delay=5)
def task_scan_zip(
    self,
    scan_id: str,
    zip_path_str: str,
    original_filename: str,
    mime_type: str,
    file_size: int,
    sha256_hash: str
):
    """Background Celery task to scan ZIP archive."""
    logger.info("Executing Celery ZIP scan task for scan_id %s", scan_id)
    db = SessionLocal()
    try:
        zip_path = Path(zip_path_str)
        result = scan_service.scan_zip_sync(
            db=db,
            scan_id=scan_id,
            zip_path=zip_path,
            original_filename=original_filename,
            mime_type=mime_type,
            file_size=file_size,
            sha256_hash=sha256_hash
        )
        return result
    except Exception as exc:
        logger.error("Celery ZIP scan task failed: %s", exc)
        db.rollback()
        raise self.retry(exc=exc)
    finally:
        db.close()


@celery_app.task(bind=True, max_retries=2, default_retry_delay=5)
def task_scan_url(self, scan_id: str, url: str):
    """Background Celery task to scan URL."""
    logger.info("Executing Celery URL scan task for scan_id %s", scan_id)
    db = SessionLocal()
    try:
        result = scan_service.scan_url_sync(
            db=db,
            scan_id=scan_id,
            url=url
        )
        return result
    except Exception as exc:
        logger.error("Celery URL scan task failed: %s", exc)
        db.rollback()
        raise self.retry(exc=exc)
    finally:
        db.close()

