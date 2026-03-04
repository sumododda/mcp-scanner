from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from mcp_scanner.database import get_session
from mcp_scanner.main import app


@pytest.fixture
def client():
    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    # Mock execute so scalar_one_or_none returns None (no existing scan)
    mock_exec_result = MagicMock()
    mock_exec_result.scalar_one_or_none.return_value = None
    mock_session.execute = AsyncMock(return_value=mock_exec_result)

    async def override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = override_get_session
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_full_scan_returns_grade(client):
    resp = client.post("/api/scan", json={"repo_url": "https://github.com/org/test-repo"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["grade"] in ("A", "B", "C", "D", "F")


def test_full_scan_returns_score(client):
    resp = client.post("/api/scan", json={"repo_url": "https://github.com/org/test-repo"})
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data["overall_score"], int)


def test_scan_returns_structured_findings(client):
    resp = client.post("/api/scan", json={"repo_url": "https://github.com/org/test-repo"})
    data = resp.json()
    for finding in data["findings"]:
        assert "id" in finding
        assert "checker" in finding
        assert "severity" in finding
        assert finding["severity"] in ("critical", "high", "medium", "low")
        assert "title" in finding
        assert "description" in finding
        assert "evidence" in finding
        assert "location" in finding


def test_pdf_report_endpoint(client):
    weasyprint = pytest.importorskip("weasyprint")

    # The report route now requires a valid scan in the DB.
    # We need to mock the session.execute to return a scan object.
    from unittest.mock import patch
    from mcp_scanner.models.scan import Scan, ScanStatus

    mock_scan = MagicMock(spec=Scan)
    mock_scan.id = "test-scan-123"
    mock_scan.status = ScanStatus.COMPLETED
    mock_scan.overall_score = 100
    mock_scan.grade = "A"
    mock_scan.summary = {"total": 0, "by_severity": {}, "by_checker": {}}
    mock_scan.error_message = None
    mock_scan.findings = []

    # The download_pdf route will try uuid.UUID(scan_id), so we need a valid UUID
    import uuid
    scan_uuid = uuid.uuid4()
    mock_scan.id = scan_uuid

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_scan

    # Override the mock_session's execute to return our scan
    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    mock_session.execute = AsyncMock(return_value=mock_result)

    async def override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = override_get_session

    resp = client.get(f"/api/scan/{scan_uuid}/pdf")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert f"mcp-scan-{scan_uuid}" in resp.headers["content-disposition"]
    assert resp.content[:4] == b"%PDF"
