import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_security_headers_present():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains"
    assert "camera=()" in response.headers["Permissions-Policy"]


def test_readiness_probe_endpoint():
    response = client.get("/ready")
    # Response should be 200 (if mongo connected) or 503 (if mongo disconnected in test environment)
    assert response.status_code in [200, 503]
    assert "status" in response.json()
    assert "database" in response.json()


def test_scan_request_extension_payload_format():
    # Browser extension sends { target: "https://example.com", scan_type: "url" }
    response = client.post(
        "/api/v1/scan",
        json={"target": "https://example.com", "scan_type": "url"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["target"] == "https://example.com"


def test_scan_request_legacy_payload_format():
    # Legacy client sends { url: "https://example.com" }
    response = client.post(
        "/api/v1/scan",
        json={"url": "https://example.com"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["target"] == "https://example.com"


def test_fake_login_scan_endpoint_ssrf_rejection():
    # fake-login endpoint should reject SSRF target
    response = client.post(
        "/api/v1/scan/fake-login",
        json={"url": "http://127.0.0.1:8000/internal"}
    )
    assert response.status_code == 400
    assert "SSRF" in response.json()["detail"] or "Private" in response.json()["detail"]
