import pytest
from unittest.mock import patch
import httpx
from app.services.url_service import url_service


def test_invalid_url_scheme(client):
    """Disallowed schemes must be rejected."""
    payload = {"url": "ftp://files.example.com"}
    response = client.post("/api/scan/url", json=payload)
    assert response.status_code in (400, 422)


def test_localhost_ssrf_blocked(client):
    """Attempts to scan 127.0.0.1 or localhost must trigger SSRF block."""
    for bad_url in ("http://127.0.0.1:8000/api/health", "http://localhost:8000"):
        response = client.post("/api/scan/url", json={"url": bad_url})
        assert response.status_code == 400
        data = response.json()
        assert data["success"] is False
        assert "SSRF" in data["message"]


def test_private_network_ssrf_blocked(client):
    """Private network ranges (192.168.x.x, 10.x.x.x, 172.16.x.x) must be blocked."""
    for private_url in ("http://192.168.1.1", "http://10.0.0.1", "http://172.16.0.5"):
        response = client.post("/api/scan/url", json={"url": private_url})
        assert response.status_code == 400
        data = response.json()
        assert "SSRF" in data["message"]


def test_cloud_metadata_blocked(client):
    """Cloud metadata IP 169.254.169.254 must be blocked."""
    response = client.post("/api/scan/url", json={"url": "http://169.254.169.254/latest/meta-data/"})
    assert response.status_code == 400
    data = response.json()
    assert "SSRF" in data["message"]


def test_normal_public_url(client):
    """Public domain analysis."""
    mock_html = b"""
    <!DOCTYPE html>
    <html>
    <head><title>Safe Example Domain</title></head>
    <body><p>This is a benign website.</p></body>
    </html>
    """

    class MockResponse:
        status_code = 200
        headers = {"content-type": "text/html"}
        content = mock_html
        is_redirect = False

    with patch("app.utils.security_utils.resolve_hostname_ips", return_value=(True, ["93.184.216.34"], None)):
        with patch.object(httpx.Client, "get", return_value=MockResponse()):
            response = client.post("/api/scan/url?sync=true", json={"url": "https://example.com"})
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["data"]["scan_status"] == "CLEAN"
            assert data["data"]["https_supported"] is True


def test_url_redirect_to_private_ip(client):
    """Redirect to private IP address must be halted by SSRF protection."""
    # First hop is safe, second hop redirects to 192.168.1.1
    class MockRedirectResponse:
        status_code = 302
        headers = {"location": "http://192.168.1.1/admin"}
        content = b""
        is_redirect = True

    with patch("app.utils.security_utils.resolve_hostname_ips") as mock_dns:
        # First call for initial validation
        mock_dns.side_effect = [
            (True, ["93.184.216.34"], None),  # initial check
            (True, ["93.184.216.34"], None),  # hop 1 fetch check
            (False, [], "Blocked private network address: 192.168.1.1")  # hop 2 check
        ]
        with patch.object(httpx.Client, "get", return_value=MockRedirectResponse()):
            response = client.post("/api/scan/url?sync=true", json={"url": "https://redirect-service.com/open"})
            assert response.status_code == 200
            data = response.json()
            assert data["data"]["scan_status"] == "MALICIOUS"
            assert any("SSRF" in t["threat_name"] for t in data["data"]["detected_threats"])

