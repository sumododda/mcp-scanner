"""Tests for DB persistence in ScanOrchestrator."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from mcp_scanner.checkers.base import CheckerResult, FindingData, Severity
from mcp_scanner.models.finding import Finding
from mcp_scanner.models.finding import Severity as DBSeverity
from mcp_scanner.models.scan import Scan, ScanStatus
from mcp_scanner.services.orchestrator import ScanOrchestrator


def _make_finding(
    severity: Severity = Severity.HIGH,
    checker: str = "test_checker",
    title: str = "Test Finding",
    location: str = "test-server",
) -> FindingData:
    return FindingData(
        checker=checker,
        severity=severity,
        title=title,
        description="A test finding",
        evidence="some evidence",
        location=location,
        remediation="fix it",
    )


def _make_checker_result(findings: list[FindingData] | None = None) -> CheckerResult:
    return CheckerResult(
        findings=findings or [],
        checker_name="mock_checker",
    )


@pytest.fixture
def mock_session():
    """Create a mock AsyncSession for DB tests."""
    session = AsyncMock(spec=AsyncSession)
    # .add() is a sync method on AsyncSession, so use MagicMock
    session.add = MagicMock()
    # Mock execute so scalar_one_or_none returns None (no existing scan found)
    mock_exec_result = MagicMock()
    mock_exec_result.scalar_one_or_none.return_value = None
    session.execute = AsyncMock(return_value=mock_exec_result)
    return session


@pytest.fixture
def orchestrator():
    """Create ScanOrchestrator with mocked checkers."""
    orch = ScanOrchestrator()
    return orch


@pytest.fixture
def mock_checkers_no_findings():
    """Patch get_all_checkers to return a checker with no findings."""
    mock_checker = AsyncMock()
    mock_checker.name = "mock_checker"
    mock_checker.description = "A mock checker"
    mock_checker.check = AsyncMock(return_value=_make_checker_result())
    with patch(
        "mcp_scanner.services.orchestrator.get_all_checkers",
        return_value=[mock_checker],
    ):
        yield


@pytest.fixture
def mock_checkers_with_findings():
    """Patch get_all_checkers to return a checker with findings."""
    findings = [
        _make_finding(Severity.HIGH, "tool_poisoning", "Suspicious tool description", location="server-a/tool1"),
        _make_finding(Severity.MEDIUM, "data_exfil", "Potential data leak", location="server-b/tool2"),
    ]
    mock_checker = AsyncMock()
    mock_checker.name = "mock_checker"
    mock_checker.description = "A mock checker"
    mock_checker.check = AsyncMock(return_value=_make_checker_result(findings))
    with patch(
        "mcp_scanner.services.orchestrator.get_all_checkers",
        return_value=[mock_checker],
    ):
        yield findings


@pytest.mark.asyncio
async def test_run_scan_creates_db_record(
    mock_session, mock_checkers_no_findings
):
    """When session is provided, orchestrator creates a Scan record with PENDING status."""
    # Track the status at the time of each commit to verify PENDING was persisted
    statuses_at_commit: list[ScanStatus] = []
    scan_ref: list[Scan] = []

    async def capture_commit():
        if scan_ref:
            statuses_at_commit.append(scan_ref[0].status)

    original_add = mock_session.add

    def capturing_add(obj):
        if isinstance(obj, Scan):
            scan_ref.append(obj)
        return original_add(obj)

    mock_session.add = MagicMock(side_effect=capturing_add)
    mock_session.commit = AsyncMock(side_effect=capture_commit)

    orchestrator = ScanOrchestrator()
    result = await orchestrator.run_scan(
        session=mock_session,
    )

    # Verify a Scan object was added to session
    assert len(scan_ref) >= 1, "Expected at least one Scan to be added to session"
    scan_obj = scan_ref[0]
    assert scan_obj.mcp_config == {"mcpServers": {}}

    # First commit should have been with PENDING status
    assert len(statuses_at_commit) >= 1, "Expected at least one commit"
    assert statuses_at_commit[0] == ScanStatus.PENDING

    # Verify commit was called (at least once for initial PENDING)
    assert mock_session.commit.await_count >= 1


@pytest.mark.asyncio
async def test_run_scan_updates_status_to_completed(
    mock_session, mock_checkers_no_findings
):
    """Scan transitions from PENDING to COMPLETED, commit called multiple times."""
    orchestrator = ScanOrchestrator()
    result = await orchestrator.run_scan(
        session=mock_session,
    )

    # Verify the scan ends up COMPLETED
    add_calls = mock_session.add.call_args_list
    scan_adds = [c for c in add_calls if isinstance(c[0][0], Scan)]
    scan_obj = scan_adds[0][0][0]
    assert scan_obj.status == ScanStatus.COMPLETED

    # Score/grade should be set on the scan object
    assert scan_obj.overall_score is not None
    assert scan_obj.grade is not None
    assert scan_obj.summary is not None

    # Commit called multiple times: PENDING, RUNNING, COMPLETED
    assert mock_session.commit.await_count >= 2

    # Result dict should include status
    assert result["status"] == "completed"


@pytest.mark.asyncio
async def test_run_scan_persists_findings(
    mock_session, mock_checkers_with_findings
):
    """Findings are added to the session and committed."""
    orchestrator = ScanOrchestrator()
    result = await orchestrator.run_scan(
        session=mock_session,
    )

    # Should have added Finding objects to session
    add_calls = mock_session.add.call_args_list
    finding_adds = [c for c in add_calls if isinstance(c[0][0], Finding)]
    assert len(finding_adds) == 2, f"Expected 2 Finding adds, got {len(finding_adds)}"

    # Verify finding attributes
    finding_objs = [c[0][0] for c in finding_adds]
    severities = {f.severity for f in finding_objs}
    assert DBSeverity.HIGH in severities
    assert DBSeverity.MEDIUM in severities

    # All findings should reference the same scan_id
    scan_ids = {f.scan_id for f in finding_objs}
    assert len(scan_ids) == 1

    # Findings should still be in the returned dict
    assert len(result["findings"]) == 2


@pytest.mark.asyncio
async def test_run_scan_without_session_still_works(
    mock_checkers_with_findings,
):
    """Backward compat: run_scan without session still returns scan_id, findings, score, grade."""
    orchestrator = ScanOrchestrator()
    result = await orchestrator.run_scan()

    assert "scan_id" in result
    assert "findings" in result
    assert "score" in result
    assert "grade" in result
    assert "summary" in result
    assert isinstance(result["scan_id"], str)
    assert isinstance(result["score"], int)
    assert result["grade"] in ("A", "B", "C", "D", "F")
    assert len(result["findings"]) == 2
