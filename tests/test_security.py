import pytest
from unittest.mock import patch
from app.services.clamav_service import clamav_service
from app.utils.file_validation import sanitize_filename, inspect_file


def test_health_endpoints(client):
    """Test /api/health and /api/health/scanners."""
    res_health = client.get("/api/health")
    assert res_health.status_code == 200
    assert res_health.json()["success"] is True

    res_scanners = client.get("/api/health/scanners")
    assert res_scanners.status_code == 200
    assert res_scanners.json()["success"] is True
    assert "clamav" in res_scanners.json()["data"]
    assert "yara" in res_scanners.json()["data"]


def test_filename_sanitization():
    """Verify filename traversal and dangerous characters are cleansed."""
    assert sanitize_filename("../../../etc/passwd") == "passwd"
    assert sanitize_filename("..\\..\\boot.ini") == "boot.ini"
    assert "test" in sanitize_filename("test;rm -rf;.exe")


def test_scan_history_and_reports(client):
    """Scan a file, check status, retrieve result, fetch history, and download PDF report."""
    pdf_content = b"%PDF-1.4\nbenign content for report test\n%%EOF"
    files = {"file": ("report_test.pdf", pdf_content, "application/pdf")}

    with patch.object(clamav_service, "scan_file", return_value={"status": "CLEAN", "threats": [], "available": True, "error": None}):
        # 1. Scan file
        post_res = client.post("/api/scan/file?sync=true", files=files)
        assert post_res.status_code == 200
        scan_id = post_res.json()["data"]["scan_id"]
        assert scan_id is not None

        # 2. Check status endpoint
        status_res = client.get(f"/api/scan/{scan_id}/status")
        assert status_res.status_code == 200
        assert status_res.json()["data"]["scan_status"] == "CLEAN"

        # 3. Retrieve full scan result
        get_res = client.get(f"/api/scan/{scan_id}")
        assert get_res.status_code == 200
        assert get_res.json()["data"]["scan_id"] == scan_id

        # 4. Check history listing
        hist_res = client.get("/api/scan/history?page=1&limit=5")
        assert hist_res.status_code == 200
        hist_data = hist_res.json()["data"]
        assert hist_data["total"] >= 1
        assert any(item["scan_id"] == scan_id for item in hist_data["items"])

        # 5. Fetch JSON report
        report_json_res = client.get(f"/api/scan/{scan_id}/report?format=json")
        assert report_json_res.status_code == 200
        assert report_json_res.json()["data"]["scan_id"] == scan_id

        # 6. Download PDF report
        report_pdf_res = client.get(f"/api/scan/{scan_id}/report?format=pdf")
        assert report_pdf_res.status_code == 200
        assert report_pdf_res.headers["content-type"] == "application/pdf"
        assert len(report_pdf_res.content) > 100


def test_nonexistent_scan_404(client):
    """Queries for non-existent scan IDs should yield 404."""
    res = client.get("/api/scan/00000000-0000-0000-0000-000000000000")
    assert res.status_code == 404
    assert res.json()["success"] is False

