import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
import logging
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.config import settings
from app.models.scan_history import ScanHistory
from app.models.scan_file import ScanFile
from app.models.threat_detection import ThreatDetection
from app.models.scan_report import ScanReport
from app.services.clamav_service import clamav_service
from app.services.yara_service import yara_service
from app.services.zip_service import zip_service, ZipInspectionError
from app.services.url_service import url_service
from app.services.report_service import report_service
from app.utils.hash_utils import calculate_sha256
from app.utils.file_validation import inspect_file

logger = logging.getLogger(__name__)


class ScanService:
    def create_scan_record(
        self,
        db: Session,
        scan_type: str,
        target_name: Optional[str] = None,
        target_url: Optional[str] = None
    ) -> ScanHistory:
        """Creates a pending scan record in the database."""
        scan = ScanHistory(
            scan_id=str(uuid.uuid4()),
            scan_type=scan_type.upper(),
            target_name=target_name,
            target_url=target_url,
            overall_status="SCANNING",
            scanner_status={},
            created_at=datetime.now(timezone.utc)
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        return scan

    def evaluate_file_scanners(
        self,
        clamav_res: Dict[str, Any],
        yara_res: Dict[str, Any]
    ) -> tuple[str, List[Dict[str, Any]], Dict[str, Any]]:
        """
        Evaluates scan status strictly according to Section 9:
        - CLEAN: All required scanners completed successfully without detections.
        - SUSPICIOUS: Heuristic or YARA rules identify potentially dangerous behavior without confirmed malware.
        - MALICIOUS: A trusted malware signature or sufficiently strong detection identifies a threat.
        - ERROR: Unexpected scanning failure occurred.
        - UNABLE_TO_SCAN: Scanner failed or was unavailable.
        - Never classify as CLEAN if scanning was incomplete or a required scanner failed.
        """
        threats: List[Dict[str, Any]] = []
        scanner_results = {
            "clamav": {
                "status": clamav_res.get("status", "UNABLE_TO_SCAN"),
                "available": clamav_res.get("available", False),
                "threats": clamav_res.get("threats", []),
                "error": clamav_res.get("error")
            },
            "yara": {
                "status": yara_res.get("status", "UNABLE_TO_SCAN"),
                "available": yara_res.get("available", False),
                "matched_rules": yara_res.get("matched_rules", []),
                "threats": yara_res.get("threats", []),
                "error": yara_res.get("error")
            }
        }

        for t in clamav_res.get("threats", []):
            threats.append(t)
        for t in yara_res.get("threats", []):
            threats.append(t)

        c_status = clamav_res.get("status")
        y_status = yara_res.get("status")

        if c_status == "MALICIOUS" or y_status == "MALICIOUS":
            return "MALICIOUS", threats, scanner_results

        if y_status == "SUSPICIOUS" or c_status == "SUSPICIOUS":
            return "SUSPICIOUS", threats, scanner_results

        if c_status in ("ERROR", "UNABLE_TO_SCAN") or not clamav_res.get("available", False):
            return "UNABLE_TO_SCAN", threats, scanner_results

        if y_status in ("ERROR", "UNABLE_TO_SCAN") or not yara_res.get("available", False):
            return "UNABLE_TO_SCAN", threats, scanner_results

        if c_status == "CLEAN" and y_status == "CLEAN":
            return "CLEAN", threats, scanner_results

        return "UNABLE_TO_SCAN", threats, scanner_results

    def scan_file_sync(
        self,
        db: Session,
        scan_id: str,
        file_path: Path,
        original_filename: str,
        mime_type: str,
        file_size: int,
        sha256_hash: str,
        host_quarantined: bool = False,
        header_buffer: bytes = b""
    ) -> Dict[str, Any]:
        """Synchronously scan a single file using ClamAV and YARA."""
        scan = db.query(ScanHistory).filter(ScanHistory.scan_id == scan_id).first()
        if not scan:
            scan = self.create_scan_record(db, "FILE", target_name=original_filename)

        if host_quarantined:
            yara_res = yara_service.scan_data(header_buffer) if header_buffer else {"status": "CLEAN", "threats": []}
            threats = yara_res.get("threats", [])
            threats.append({
                "scanner_name": "host_antivirus",
                "threat_name": "Host_OS_Defender_Quarantine",
                "threat_category": "malware",
                "severity": "CRITICAL",
                "description": "Host OS Antivirus detected malware signature and locked file access."
            })
            overall_status = "MALICIOUS"
            scanner_results = {
                "host_antivirus": {"status": "MALICIOUS", "quarantined": True},
                "yara": {"status": yara_res.get("status", "MALICIOUS"), "matched_rules": yara_res.get("matched_rules", [])},
                "clamav": {"status": "MALICIOUS", "note": "Quarantined by host"}
            }
        else:
            clamav_res = clamav_service.scan_file(file_path)
            yara_res = yara_service.scan_file(file_path)
            overall_status, threats, scanner_results = self.evaluate_file_scanners(clamav_res, yara_res)

        scan.overall_status = overall_status
        scan.scanner_status = {
            "clamav": scanner_results.get("clamav", {}).get("status", overall_status),
            "yara": scanner_results.get("yara", {}).get("status", overall_status)
        }
        scan.completed_at = datetime.now(timezone.utc)

        scan_file_rec = ScanFile(
            scan_history_id=scan.id,
            original_filename=original_filename,
            stored_filename=file_path.name if file_path else "quarantined",
            file_extension=file_path.suffix.lower() if file_path else "",
            mime_type=mime_type,
            file_size=file_size,
            sha256_hash=sha256_hash,
            scan_status=overall_status,
            created_at=datetime.now(timezone.utc)
        )
        db.add(scan_file_rec)
        db.flush()

        for t in threats:
            td = ThreatDetection(
                scan_history_id=scan.id,
                scan_file_id=scan_file_rec.id,
                scanner_name=t.get("scanner_name", "unknown"),
                threat_name=t.get("threat_name", "Unknown Threat"),
                threat_category=t.get("threat_category", "malware"),
                severity=t.get("severity", "HIGH"),
                description=t.get("description", ""),
                created_at=datetime.now(timezone.utc)
            )
            db.add(td)

        result_data = {
            "scan_id": scan.scan_id,
            "scan_type": "FILE",
            "file_name": original_filename,
            "file_size": file_size,
            "file_hash": sha256_hash,
            "mime_type": mime_type,
            "scan_status": overall_status,
            "scanner_results": scanner_results,
            "detected_threats": threats,
            "completed_at": scan.completed_at.isoformat()
        }

        pdf_path = None
        try:
            pdf_path = report_service.generate_pdf_report(result_data)
        except Exception as e:
            logger.error("Failed to generate PDF report: %s", e)

        scan_report_rec = ScanReport(
            scan_history_id=scan.id,
            report_json=result_data,
            report_path=str(pdf_path) if pdf_path else None,
            created_at=datetime.now(timezone.utc)
        )
        db.add(scan_report_rec)
        db.commit()

        return result_data

    def scan_zip_sync(
        self,
        db: Session,
        scan_id: str,
        zip_path: Path,
        original_filename: str,
        mime_type: str,
        file_size: int,
        sha256_hash: str,
        host_quarantined: bool = False
    ) -> Dict[str, Any]:
        """Safely unpacks ZIP and recursively scans each member file."""
        scan = db.query(ScanHistory).filter(ScanHistory.scan_id == scan_id).first()
        if not scan:
            scan = self.create_scan_record(db, "ZIP", target_name=original_filename)

        all_threats = []
        files_results = []
        extract_root = None
        overall_status = "CLEAN"
        clamav_overall_status = "CLEAN"
        yara_overall_status = "CLEAN"

        if host_quarantined:
            overall_status = "MALICIOUS"
            all_threats.append({
                "scanner_name": "host_antivirus",
                "threat_name": "Host_OS_Defender_Quarantine",
                "threat_category": "malware",
                "severity": "CRITICAL",
                "description": "Host OS Antivirus detected malware signature in uploaded archive and quarantined it."
            })
        else:
            try:
                extract_root, records, stats = zip_service.inspect_and_extract(zip_path)

                for rec in records:
                    member_path = rec["extracted_path"]
                    m_name = rec["original_path"]

                    if rec.get("is_quarantined"):
                        y_res = yara_service.scan_data(rec.get("header_buf", b""))
                        f_threats = y_res.get("threats", [])
                        f_threats.append({
                            "scanner_name": "host_antivirus",
                            "threat_name": "Host_OS_Defender_Quarantine",
                            "threat_category": "malware",
                            "severity": "CRITICAL",
                            "description": f"File '{m_name}' quarantined by host OS Antivirus."
                        })
                        f_status = "MALICIOUS"
                    else:
                        c_res = clamav_service.scan_file(member_path)
                        y_res = yara_service.scan_file(member_path)
                        f_status, f_threats, _ = self.evaluate_file_scanners(c_res, y_res)

                    sf = ScanFile(
                        scan_history_id=scan.id,
                        original_filename=m_name,
                        stored_filename=member_path.name if member_path else "quarantined",
                        file_extension=member_path.suffix.lower() if member_path else "",
                        mime_type=rec["mime_type"],
                        file_size=rec["file_size"],
                        sha256_hash=rec["sha256_hash"],
                        scan_status=f_status,
                        created_at=datetime.now(timezone.utc)
                    )
                    db.add(sf)
                    db.flush()

                    for t in f_threats:
                        t_copy = dict(t)
                        t_copy["file"] = m_name
                        all_threats.append(t_copy)

                        td = ThreatDetection(
                            scan_history_id=scan.id,
                            scan_file_id=sf.id,
                            scanner_name=t.get("scanner_name", "unknown"),
                            threat_name=t.get("threat_name", "Unknown"),
                            threat_category=t.get("threat_category", "malware"),
                            severity=t.get("severity", "HIGH"),
                            description=f"In archive file '{m_name}': {t.get('description', '')}",
                            created_at=datetime.now(timezone.utc)
                        )
                        db.add(td)

                    files_results.append({
                        "path": m_name,
                        "file_size": rec["file_size"],
                        "sha256_hash": rec["sha256_hash"],
                        "mime_type": rec["mime_type"],
                        "scan_status": f_status,
                        "threats": f_threats
                    })

                    if f_status == "MALICIOUS":
                        overall_status = "MALICIOUS"
                    elif f_status == "SUSPICIOUS" and overall_status != "MALICIOUS":
                        overall_status = "SUSPICIOUS"
                    elif f_status in ("UNABLE_TO_SCAN", "ERROR") and overall_status not in ("MALICIOUS", "SUSPICIOUS"):
                        overall_status = "UNABLE_TO_SCAN"

                if clamav_res := clamav_service.ping() is False:
                    clamav_overall_status = "UNABLE_TO_SCAN"
                    if overall_status == "CLEAN":
                        overall_status = "UNABLE_TO_SCAN"
                if yara_service.rules is None:
                    yara_overall_status = "UNABLE_TO_SCAN"
                    if overall_status == "CLEAN":
                        overall_status = "UNABLE_TO_SCAN"

            except ZipInspectionError as ze:
                ze_str = str(ze).lower()
                if "permission denied" in ze_str or "quarantined" in ze_str or "virus" in ze_str:
                    overall_status = "MALICIOUS"
                    all_threats.append({
                        "scanner_name": "host_antivirus",
                        "threat_name": "Host_OS_Defender_Quarantine",
                        "threat_category": "malware",
                        "severity": "CRITICAL",
                        "description": "Host OS Antivirus detected malware signature in archive and locked access."
                    })
                else:
                    overall_status = ze.status_code
                    all_threats.append({
                        "scanner_name": "zip_service",
                        "threat_name": "Archive_Inspection_Error",
                        "threat_category": "archive_security",
                        "severity": "HIGH" if overall_status == "ERROR" else "MEDIUM",
                        "description": str(ze)
                    })
            finally:
                if extract_root:
                    zip_service.cleanup(extract_root)

        scan.overall_status = overall_status
        scan.scanner_status = {
            "clamav": clamav_overall_status,
            "yara": yara_overall_status,
            "total_files": len(files_results)
        }
        scan.completed_at = datetime.now(timezone.utc)

        result_data = {
            "scan_id": scan.scan_id,
            "scan_type": "ZIP",
            "archive_name": original_filename,
            "archive_size": file_size,
            "archive_hash": sha256_hash,
            "total_files": len(files_results),
            "scan_status": overall_status,
            "scanner_results": {
                "clamav": {"status": clamav_overall_status},
                "yara": {"status": yara_overall_status}
            },
            "files": files_results,
            "detected_threats": all_threats,
            "completed_at": scan.completed_at.isoformat()
        }

        pdf_path = None
        try:
            pdf_path = report_service.generate_pdf_report(result_data)
        except Exception as e:
            logger.error("Failed to generate PDF report for zip: %s", e)

        scan_report_rec = ScanReport(
            scan_history_id=scan.id,
            report_json=result_data,
            report_path=str(pdf_path) if pdf_path else None,
            created_at=datetime.now(timezone.utc)
        )
        db.add(scan_report_rec)
        db.commit()

        return result_data

    def scan_url_sync(self, db: Session, scan_id: str, url: str) -> Dict[str, Any]:
        """Synchronously scan and analyze URL."""
        scan = db.query(ScanHistory).filter(ScanHistory.scan_id == scan_id).first()
        if not scan:
            scan = self.create_scan_record(db, "URL", target_url=url)

        res = url_service.analyze_url(url)
        overall_status = res.get("status", "CLEAN")
        threats = res.get("threats", [])

        scan.overall_status = overall_status
        scan.scanner_status = {
            "url_analyzer": res.get("scanner_results", {}).get("url_analyzer", {}).get("status", overall_status),
            "yara": res.get("scanner_results", {}).get("yara", {}).get("status", "CLEAN")
        }
        scan.completed_at = datetime.now(timezone.utc)

        for t in threats:
            td = ThreatDetection(
                scan_history_id=scan.id,
                scanner_name=t.get("scanner_name", "url_analyzer"),
                threat_name=t.get("threat_name", "URL_Indicator"),
                threat_category=t.get("threat_category", "phishing"),
                severity=t.get("severity", "MEDIUM"),
                description=t.get("description", ""),
                created_at=datetime.now(timezone.utc)
            )
            db.add(td)

        result_data = {
            "scan_id": scan.scan_id,
            "scan_type": "URL",
            "url": url,
            "final_url": res.get("final_url"),
            "scan_status": overall_status,
            "https_supported": res.get("https_supported", False),
            "redirect_count": res.get("redirect_count", 0),
            "redirect_chain": res.get("redirect_chain", [url]),
            "security_indicators": res.get("security_indicators", {}),
            "scanner_results": res.get("scanner_results", {}),
            "detected_threats": threats,
            "completed_at": scan.completed_at.isoformat()
        }

        pdf_path = None
        try:
            pdf_path = report_service.generate_pdf_report(result_data)
        except Exception as e:
            logger.error("Failed to generate PDF report for URL: %s", e)

        scan_report_rec = ScanReport(
            scan_history_id=scan.id,
            report_json=result_data,
            report_path=str(pdf_path) if pdf_path else None,
            created_at=datetime.now(timezone.utc)
        )
        db.add(scan_report_rec)
        db.commit()

        return result_data

    def get_scan_result(self, db: Session, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves scan record and report by scan_id."""
        scan = db.query(ScanHistory).filter(ScanHistory.scan_id == scan_id).first()
        if not scan:
            return None

        report = db.query(ScanReport).filter(ScanReport.scan_history_id == scan.id).order_by(desc(ScanReport.id)).first()
        if report and report.report_json:
            return report.report_json

        return {
            "scan_id": scan.scan_id,
            "scan_type": scan.scan_type,
            "target_name": scan.target_name,
            "target_url": scan.target_url,
            "scan_status": scan.overall_status,
            "scanner_results": scan.scanner_status or {},
            "detected_threats": [],
            "created_at": scan.created_at.isoformat(),
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None
        }

    def get_scan_status(self, db: Session, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves status summary of a scan."""
        scan = db.query(ScanHistory).filter(ScanHistory.scan_id == scan_id).first()
        if not scan:
            return None

        return {
            "scan_id": scan.scan_id,
            "scan_type": scan.scan_type,
            "scan_status": scan.overall_status,
            "created_at": scan.created_at.isoformat(),
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None
        }

    def list_history(self, db: Session, page: int = 1, page_size: int = 10) -> Dict[str, Any]:
        """Lists scan history with pagination."""
        if page < 1:
            page = 1
        if page_size < 1 or page_size > 100:
            page_size = 10

        query = db.query(ScanHistory)
        total = query.count()
        total_pages = (total + page_size - 1) // page_size if total > 0 else 1

        items = query.order_by(desc(ScanHistory.created_at)).offset((page - 1) * page_size).limit(page_size).all()

        formatted_items = [
            {
                "scan_id": s.scan_id,
                "scan_type": s.scan_type,
                "target_name": s.target_name,
                "target_url": s.target_url,
                "overall_status": s.overall_status,
                "scanner_status": s.scanner_status or {},
                "created_at": s.created_at.isoformat(),
                "completed_at": s.completed_at.isoformat() if s.completed_at else None
            }
            for s in items
        ]

        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "items": formatted_items
        }


scan_service = ScanService()
