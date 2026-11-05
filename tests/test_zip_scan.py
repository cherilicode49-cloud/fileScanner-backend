import io
import zipfile
import pytest
from unittest.mock import patch
from app.services.clamav_service import clamav_service


def create_test_zip(files_dict: dict) -> bytes:
    """Helper to construct in-memory zip bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for filename, content in files_dict.items():
            zf.writestr(filename, content)
    buf.seek(0)
    return buf.getvalue()


def test_zip_with_multiple_files(client):
    """Scan ZIP containing multiple clean files."""
    files_data = {
        "readme.txt": b"Hello world, benign readme.",
        "docs/manual.txt": b"Manual page content for testing."
    }
    zip_bytes = create_test_zip(files_data)
    files = {"file": ("archive.zip", zip_bytes, "application/zip")}

    with patch.object(clamav_service, "scan_file", return_value={"status": "CLEAN", "threats": [], "available": True, "error": None}):
        with patch.object(clamav_service, "ping", return_value=True):
            response = client.post("/api/scan/zip?sync=true", files=files)
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["data"]["scan_status"] == "CLEAN"
            assert data["data"]["total_files"] == 2
            assert len(data["data"]["files"]) == 2


def test_zip_with_eicar_malware(client):
    """ZIP containing an EICAR infected file must flag archive as MALICIOUS."""
    eicar_bytes = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    files_data = {
        "safe.txt": b"Benign text",
        "virus.com": eicar_bytes
    }
    zip_bytes = create_test_zip(files_data)
    files = {"file": ("infected.zip", zip_bytes, "application/zip")}

    with patch.object(clamav_service, "scan_file", return_value={"status": "CLEAN", "threats": [], "available": True, "error": None}):
        with patch.object(clamav_service, "ping", return_value=True):
            response = client.post("/api/scan/zip?sync=true", files=files)
            assert response.status_code == 200
            data = response.json()
            assert data["data"]["scan_status"] == "MALICIOUS"
            assert len(data["data"]["detected_threats"]) > 0
            threat_names = [t["threat_name"] for t in data["data"]["detected_threats"]]
            assert "EICAR_Antivirus_Test" in threat_names or "Host_OS_Defender_Quarantine" in threat_names


def test_nested_zip_scanning(client):
    """Nested ZIP archive should be recursively extracted and inspected."""
    inner_zip = create_test_zip({"inner.txt": b"Inner text file content"})
    outer_zip = create_test_zip({
        "outer.txt": b"Outer text",
        "nested.zip": inner_zip
    })
    files = {"file": ("nested_test.zip", outer_zip, "application/zip")}

    with patch.object(clamav_service, "scan_file", return_value={"status": "CLEAN", "threats": [], "available": True, "error": None}):
        with patch.object(clamav_service, "ping", return_value=True):
            response = client.post("/api/scan/zip?sync=true", files=files)
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["data"]["scan_status"] == "CLEAN"


def test_zip_path_traversal_protection(client):
    """ZIP entry with path traversal (e.g., ../evil.sh) must be stopped."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("../../etc/passwd", b"root:x:0:0::/root:/bin/bash")
    buf.seek(0)

    files = {"file": ("traversal.zip", buf.getvalue(), "application/zip")}
    response = client.post("/api/scan/zip?sync=true", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["data"]["scan_status"] in ("ERROR", "SUSPICIOUS", "MALICIOUS")
    assert any("traversal" in str(t).lower() for t in data["data"]["detected_threats"])


def test_zip_bomb_protection(client):
    """ZIP containing uncompressed content exceeding limits must be blocked."""
    from app.config import settings
    orig_max = settings.MAX_ZIP_EXTRACT_SIZE_MB
    try:
        settings.MAX_ZIP_EXTRACT_SIZE_MB = 1  # 1MB limit for test
        large_uncompressed = b"\x00" * (2 * 1024 * 1024)  # 2MB
        zip_bytes = create_test_zip({"big.bin": large_uncompressed})
        files = {"file": ("bomb.zip", zip_bytes, "application/zip")}

        response = client.post("/api/scan/zip?sync=true", files=files)
        assert response.status_code == 200
        data = response.json()
        assert data["data"]["scan_status"] in ("ERROR", "UNABLE_TO_SCAN")
        assert any("zip bomb" in str(t).lower() for t in data["data"]["detected_threats"])
    finally:
        settings.MAX_ZIP_EXTRACT_SIZE_MB = orig_max
