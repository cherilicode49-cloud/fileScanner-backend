import io
import pytest
from unittest.mock import patch
from app.services.clamav_service import clamav_service
from app.services.yara_service import yara_service


def test_upload_empty_file(client):
    """Empty files must be rejected."""
    files = {"file": ("empty.txt", b"", "text/plain")}
    response = client.post("/api/scan/file?sync=true", files=files)
    assert response.status_code == 400
    data = response.json()
    assert data["success"] is False
    assert "empty" in data["message"].lower()


def test_upload_normal_pdf(client):
    """Uploading a benign PDF."""
    pdf_content = b"%PDF-1.4\n1 0 obj\n<<\n/Type /Catalog\n>>\nendobj\ntrailer\n<<\n/Root 1 0 R\n>>\n%%EOF"
    files = {"file": ("document.pdf", pdf_content, "application/pdf")}

    with patch.object(clamav_service, "scan_file", return_value={"status": "CLEAN", "threats": [], "available": True, "error": None}):
        response = client.post("/api/scan/file?sync=true", files=files)
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["data"]["scan_status"] == "CLEAN"
        assert data["data"]["file_name"] == "document.pdf"
        assert data["data"]["file_size"] == len(pdf_content)


def test_upload_normal_docx(client):
    """Uploading a benign DOCX (ZIP container)."""
    docx_content = b"PK\x03\x04\x14\x00\x00\x00\x08\x00[Content_Types].xml\nbenign content"
    files = {"file": ("document.docx", docx_content, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")}

    with patch.object(clamav_service, "scan_file", return_value={"status": "CLEAN", "threats": [], "available": True, "error": None}):
        response = client.post("/api/scan/file?sync=true", files=files)
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["data"]["scan_status"] == "CLEAN"


def test_eicar_antivirus_detection(client):
    """Standard EICAR test string must be detected as MALICIOUS."""
    eicar_bytes = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    files = {"file": ("eicar.com", eicar_bytes, "application/octet-stream")}

    with patch.object(clamav_service, "scan_file", return_value={"status": "CLEAN", "threats": [], "available": True, "error": None}):
        response = client.post("/api/scan/file?sync=true", files=files)
        assert response.status_code == 200
        data = response.json()
        assert data["data"]["scan_status"] == "MALICIOUS"
        assert len(data["data"]["detected_threats"]) > 0
        threat_names = [t["threat_name"] for t in data["data"]["detected_threats"]]
        assert "EICAR_Antivirus_Test" in threat_names or "Host_OS_Defender_Quarantine" in threat_names


def test_suspicious_javascript_detection(client):
    """Obfuscated JS with eval(unescape(...)) should be classified as SUSPICIOUS."""
    js_payload = b"var code = eval(unescape('%77%69%6e%64%6f%77'));"
    files = {"file": ("payload.js", js_payload, "application/javascript")}

    with patch.object(clamav_service, "scan_file", return_value={"status": "CLEAN", "threats": [], "available": True, "error": None}):
        response = client.post("/api/scan/file?sync=true", files=files)
        assert response.status_code == 200
        data = response.json()
        assert data["data"]["scan_status"] == "SUSPICIOUS"
        threat_names = [t["threat_name"] for t in data["data"]["detected_threats"]]
        assert "Suspicious_JavaScript_Eval_Unescape" in threat_names


def test_clamav_unavailable_never_marks_clean(client):
    """If ClamAV daemon is unreachable, clean files must be marked UNABLE_TO_SCAN, never CLEAN."""
    pdf_content = b"%PDF-1.4\nbenign content\n%%EOF"
    files = {"file": ("test.pdf", pdf_content, "application/pdf")}

    with patch.object(clamav_service, "scan_file", return_value={"status": "UNABLE_TO_SCAN", "threats": [], "available": False, "error": "Daemon unreachable"}):
        response = client.post("/api/scan/file?sync=true", files=files)
        assert response.status_code == 200
        data = response.json()
        assert data["data"]["scan_status"] == "UNABLE_TO_SCAN"
        assert data["data"]["scan_status"] != "CLEAN"


def test_yara_unavailable_never_marks_clean(client):
    """If YARA rules failed to load, file must not be marked CLEAN."""
    pdf_content = b"%PDF-1.4\nbenign content\n%%EOF"
    files = {"file": ("test.pdf", pdf_content, "application/pdf")}

    with patch.object(clamav_service, "scan_file", return_value={"status": "CLEAN", "threats": [], "available": True, "error": None}):
        with patch.object(yara_service, "scan_file", return_value={"status": "UNABLE_TO_SCAN", "threats": [], "available": False, "error": "No rules compiled"}):
            response = client.post("/api/scan/file?sync=true", files=files)
            assert response.status_code == 200
            data = response.json()
            assert data["data"]["scan_status"] == "UNABLE_TO_SCAN"
            assert data["data"]["scan_status"] != "CLEAN"


def test_oversized_file_rejection(client):
    """File larger than max allowed size is rejected with 413."""
    from app.config import settings
    original_max = settings.MAX_FILE_SIZE_MB
    try:
        settings.MAX_FILE_SIZE_MB = 1  # 1MB
        large_content = b"A" * (2 * 1024 * 1024)  # 2MB
        files = {"file": ("large.dat", large_content, "application/octet-stream")}
        response = client.post("/api/scan/file?sync=true", files=files)
        assert response.status_code == 413
    finally:
        settings.MAX_FILE_SIZE_MB = original_max
