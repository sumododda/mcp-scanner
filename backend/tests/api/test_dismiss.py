"""Tests for finding dismissal (PATCH/DELETE /api/finding/{id}/dismiss)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from mcp_scanner.database import get_session
from mcp_scanner.main import app
from mcp_scanner.models.finding import Finding
from mcp_scanner.models.finding import Severity as DBSeverity
from mcp_scanner.models.scan import Scan, ScanStatus


def _make_mock_finding(
    scan_id: uuid.UUID,
    dismissed_as: str | None = None,
    dismissed_reason: str | None = None,
) -> MagicMock:
    f = MagicMock(spec=Finding)
    f.id = uuid.uuid4()
    f.scan_id = scan_id
    f.checker = "tool_poisoning"
    f.severity = DBSeverity.HIGH
    f.title = "Suspicious tool"
    f.description = "Bad tool desc"
    f.evidence = "evidence here"
    f.location = "test-server"
    f.remediation = "fix it"
    f.cwe_id = "CWE-94"
    f.llm_analysis = None
    f.source_file = None
    f.source_line = None
    f.dismissed_as = dismissed_as
    f.dismissed_reason = dismissed_reason
    return f


def _make_mock_scan(scan_id: uuid.UUID) -> MagicMock:
    s = MagicMock(spec=Scan)
    s.id = scan_id
    s.status = ScanStatus.COMPLETED
    s.summary = {"total": 1, "by_severity": {"high": 1}, "by_checker": {"tool_poisoning": 1}}
    return s


@pytest.fixture
def mock_session():
    session = AsyncMock()
    session.add = MagicMock()
    session.commit = AsyncMock()
    session.refresh = AsyncMock()
    mock_exec_result = MagicMock()
    mock_exec_result.scalar_one_or_none.return_value = None
    session.execute = AsyncMock(return_value=mock_exec_result)
    return session


@pytest.fixture
def client(mock_session):
    async def override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = override_get_session
    yield TestClient(app)
    app.dependency_overrides.clear()


class TestDismissFinding:
    def test_dismiss_false_positive(self, client, mock_session):
        """PATCH returns updated finding with dismissal fields set."""
        scan_id = uuid.uuid4()
        finding = _make_mock_finding(scan_id)

        # First execute: find the finding
        # Second execute: find the scan
        # Third execute: query active findings for recalc
        mock_finding_result = MagicMock()
        mock_finding_result.scalar_one_or_none.return_value = finding

        mock_scan = _make_mock_scan(scan_id)
        mock_scan_result = MagicMock()
        mock_scan_result.scalar_one_or_none.return_value = mock_scan

        # Active findings after dismissal (empty since the only finding is dismissed)
        mock_active_result = MagicMock()
        mock_active_result.scalars.return_value.all.return_value = []

        mock_session.execute = AsyncMock(
            side_effect=[mock_finding_result, mock_scan_result, mock_active_result]
        )

        # The endpoint sets these on the finding object, then refresh re-reads
        def apply_refresh(obj):
            if isinstance(obj, MagicMock) and hasattr(obj, 'dismissed_as'):
                pass  # values already set by endpoint

        mock_session.refresh = AsyncMock(side_effect=apply_refresh)

        resp = client.patch(
            f"/api/finding/{finding.id}/dismiss",
            json={"dismissed_as": "false_positive", "reason": "Benign GitHub MCP text"},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == str(finding.id)
        # The endpoint sets finding.dismissed_as, which we can verify via mock
        assert finding.dismissed_as == "false_positive"
        assert finding.dismissed_reason == "Benign GitHub MCP text"

    def test_dismiss_invalid_status(self, client, mock_session):
        """PATCH returns 400 for unknown dismissed_as value."""
        finding_id = uuid.uuid4()

        resp = client.patch(
            f"/api/finding/{finding_id}/dismiss",
            json={"dismissed_as": "not_a_real_status", "reason": "whatever"},
        )

        assert resp.status_code == 400
        assert "Invalid dismissed_as" in resp.json()["detail"]

    def test_dismiss_not_found(self, client, mock_session):
        """PATCH returns 404 when finding does not exist."""
        finding_id = uuid.uuid4()

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute = AsyncMock(return_value=mock_result)

        resp = client.patch(
            f"/api/finding/{finding_id}/dismiss",
            json={"dismissed_as": "false_positive", "reason": "test"},
        )

        assert resp.status_code == 404
        assert resp.json()["detail"] == "Finding not found"

    def test_restore_finding(self, client, mock_session):
        """DELETE clears dismissal fields."""
        scan_id = uuid.uuid4()
        finding = _make_mock_finding(scan_id, dismissed_as="false_positive", dismissed_reason="Was benign")

        mock_finding_result = MagicMock()
        mock_finding_result.scalar_one_or_none.return_value = finding

        mock_scan = _make_mock_scan(scan_id)
        mock_scan_result = MagicMock()
        mock_scan_result.scalar_one_or_none.return_value = mock_scan

        # After restore, finding is active again
        mock_active_result = MagicMock()
        mock_active_result.scalars.return_value.all.return_value = [finding]

        mock_session.execute = AsyncMock(
            side_effect=[mock_finding_result, mock_scan_result, mock_active_result]
        )

        resp = client.delete(f"/api/finding/{finding.id}/dismiss")

        assert resp.status_code == 200
        assert finding.dismissed_as is None
        assert finding.dismissed_reason is None

    def test_restore_not_dismissed(self, client, mock_session):
        """DELETE on an active finding still returns 200."""
        scan_id = uuid.uuid4()
        finding = _make_mock_finding(scan_id)  # not dismissed

        mock_finding_result = MagicMock()
        mock_finding_result.scalar_one_or_none.return_value = finding

        mock_scan = _make_mock_scan(scan_id)
        mock_scan_result = MagicMock()
        mock_scan_result.scalar_one_or_none.return_value = mock_scan

        mock_active_result = MagicMock()
        mock_active_result.scalars.return_value.all.return_value = [finding]

        mock_session.execute = AsyncMock(
            side_effect=[mock_finding_result, mock_scan_result, mock_active_result]
        )

        resp = client.delete(f"/api/finding/{finding.id}/dismiss")

        assert resp.status_code == 200

    def test_dismiss_updates_summary(self, client, mock_session):
        """Scan summary is recalculated after dismissal."""
        scan_id = uuid.uuid4()
        finding = _make_mock_finding(scan_id)

        mock_finding_result = MagicMock()
        mock_finding_result.scalar_one_or_none.return_value = finding

        mock_scan = _make_mock_scan(scan_id)
        mock_scan_result = MagicMock()
        mock_scan_result.scalar_one_or_none.return_value = mock_scan

        # No active findings after dismiss
        mock_active_result = MagicMock()
        mock_active_result.scalars.return_value.all.return_value = []

        mock_session.execute = AsyncMock(
            side_effect=[mock_finding_result, mock_scan_result, mock_active_result]
        )

        resp = client.patch(
            f"/api/finding/{finding.id}/dismiss",
            json={"dismissed_as": "accepted_risk", "reason": "We accept this risk"},
        )

        assert resp.status_code == 200
        # Verify scan summary was updated to reflect 0 active findings
        assert mock_scan.summary["total"] == 0
        assert mock_scan.summary["by_severity"] == {}
        assert mock_scan.summary["by_checker"] == {}
