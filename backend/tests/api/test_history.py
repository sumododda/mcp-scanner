import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from mcp_scanner.database import get_session
from mcp_scanner.main import app
from mcp_scanner.models.scan import Scan, ScanStatus


@pytest.fixture
def mock_session():
    return AsyncMock()


@pytest.fixture
def client(mock_session):
    async def override():
        yield mock_session

    app.dependency_overrides[get_session] = override
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_history_empty(client, mock_session):
    """GET /api/history returns empty paginated list."""
    # Mock count query
    count_result = MagicMock()
    count_result.scalar_one.return_value = 0

    # Mock scan list query
    list_result = MagicMock()
    list_result.scalars.return_value.all.return_value = []

    mock_session.execute = AsyncMock(side_effect=[count_result, list_result])

    resp = client.get("/api/history")
    assert resp.status_code == 200
    data = resp.json()
    assert data["scans"] == []
    assert data["total"] == 0
    assert data["page"] == 1
    assert data["per_page"] == 20


def test_history_with_scans(client, mock_session):
    """GET /api/history returns scan list items."""
    scan_id = uuid.uuid4()
    mock_scan = MagicMock(spec=Scan)
    mock_scan.id = scan_id
    mock_scan.status = ScanStatus.COMPLETED
    mock_scan.created_at = datetime(2026, 2, 22, tzinfo=timezone.utc)
    mock_scan.overall_score = 75
    mock_scan.grade = "B"
    mock_scan.repo_url = None
    mock_scan.commit_hash = None
    mock_scan.summary = {"total": 5, "by_severity": {"high": 2, "medium": 3}, "by_checker": {"tool_poisoning": 5}}

    count_result = MagicMock()
    count_result.scalar_one.return_value = 1

    list_result = MagicMock()
    list_result.scalars.return_value.all.return_value = [mock_scan]

    mock_session.execute = AsyncMock(side_effect=[count_result, list_result])

    resp = client.get("/api/history")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert len(data["scans"]) == 1
    assert data["scans"][0]["grade"] == "B"
    assert data["scans"][0]["overall_score"] == 75


def test_history_pagination(client, mock_session):
    """GET /api/history respects page and per_page params."""
    count_result = MagicMock()
    count_result.scalar_one.return_value = 50

    list_result = MagicMock()
    list_result.scalars.return_value.all.return_value = []

    mock_session.execute = AsyncMock(side_effect=[count_result, list_result])

    resp = client.get("/api/history?page=3&per_page=10")
    assert resp.status_code == 200
    data = resp.json()
    assert data["page"] == 3
    assert data["per_page"] == 10
    assert data["total"] == 50


def test_delete_scan_success(client, mock_session):
    """DELETE /api/scan/{id} deletes the scan."""
    scan_id = uuid.uuid4()
    mock_scan = MagicMock(spec=Scan)
    mock_scan.id = scan_id

    result = MagicMock()
    result.scalar_one_or_none.return_value = mock_scan

    mock_session.execute = AsyncMock(return_value=result)
    mock_session.delete = AsyncMock()
    mock_session.commit = AsyncMock()

    resp = client.delete(f"/api/scan/{scan_id}")
    assert resp.status_code == 200
    assert resp.json() == {"deleted": True}
    mock_session.delete.assert_called_once_with(mock_scan)
    mock_session.commit.assert_called_once()


def test_delete_scan_not_found(client, mock_session):
    """DELETE /api/scan/{id} returns 404 when not found."""
    result = MagicMock()
    result.scalar_one_or_none.return_value = None
    mock_session.execute = AsyncMock(return_value=result)

    resp = client.delete(f"/api/scan/{uuid.uuid4()}")
    assert resp.status_code == 404
