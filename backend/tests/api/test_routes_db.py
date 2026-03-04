"""Tests verifying DB session wiring in API routes."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from mcp_scanner.api.auth import require_api_key
from mcp_scanner.checkers.base import CheckerResult, FindingData, Severity
from mcp_scanner.database import get_session
from mcp_scanner.main import app
from mcp_scanner.models.finding import Finding
from mcp_scanner.models.finding import Severity as DBSeverity
from mcp_scanner.models.scan import Scan, ScanStatus


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
    """Create a mock AsyncSession."""
    session = AsyncMock()
    session.add = MagicMock()
    # Default: execute returns result where scalar_one_or_none is None
    mock_exec_result = MagicMock()
    mock_exec_result.scalar_one_or_none.return_value = None
    session.execute = AsyncMock(return_value=mock_exec_result)
    return session


@pytest.fixture
def client(mock_session):
    """TestClient with overridden get_session dependency."""
    async def override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = override_get_session
    app.dependency_overrides[require_api_key] = lambda: None
    yield TestClient(app)
    app.dependency_overrides.clear()


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


class TestPostScanSessionWiring:
    """Verify that POST /api/scan passes session to orchestrator."""

    def test_post_scan_passes_session_to_orchestrator(
        self, client, mock_session, mock_checkers_no_findings
    ):
        """POST /api/scan should invoke orchestrator.run_scan with session parameter."""
        with patch(
            "mcp_scanner.api.routes.ScanOrchestrator"
        ) as MockOrchestrator:
            mock_orch_instance = AsyncMock()
            mock_orch_instance.run_scan = AsyncMock(
                return_value={
                    "scan_id": str(uuid.uuid4()),
                    "findings": [],
                    "score": 100,
                    "grade": "A",
                    "summary": {"total": 0, "by_severity": {}, "by_checker": {}},
                    "status": "completed",
                }
            )
            MockOrchestrator.return_value = mock_orch_instance

            resp = client.post(
                "/api/scan",
                json={"repo_url": "https://github.com/org/mcp-server"},
            )

            assert resp.status_code == 200
            mock_orch_instance.run_scan.assert_awaited_once()
            call_kwargs = mock_orch_instance.run_scan.call_args.kwargs
            assert "session" in call_kwargs, "session must be passed to orchestrator.run_scan"
            assert call_kwargs["session"] is mock_session

    def test_post_scan_returns_scan_response(
        self, client, mock_session, mock_checkers_no_findings
    ):
        """POST /api/scan returns a valid ScanResponse with DB session wired."""
        resp = client.post(
            "/api/scan",
            json={"repo_url": "https://github.com/org/mcp-server"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "id" in data
        assert data["status"] == "completed"
        assert isinstance(data["overall_score"], int)
        assert data["grade"] in ("A", "B", "C", "D", "F")
        assert "findings" in data
        assert "summary" in data

    def test_post_scan_with_findings(
        self, client, mock_session, mock_checkers_with_findings
    ):
        """POST /api/scan returns findings from the orchestrator."""
        resp = client.post(
            "/api/scan",
            json={"repo_url": "https://github.com/org/mcp-server"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["findings"]) == 2


class TestGetScanEndpoint:
    """Verify that GET /scan/{id} queries the DB correctly."""

    def test_get_scan_returns_scan_from_db(self, client, mock_session):
        """GET /scan/{id} fetches a scan from the database and returns it."""
        scan_id = uuid.uuid4()
        now = datetime.now(timezone.utc)

        # Create mock Finding objects
        mock_finding = MagicMock(spec=Finding)
        mock_finding.id = uuid.uuid4()
        mock_finding.checker = "tool_poisoning"
        mock_finding.severity = DBSeverity.HIGH
        mock_finding.title = "Suspicious tool"
        mock_finding.description = "Bad tool desc"
        mock_finding.evidence = "evidence here"
        mock_finding.location = "test-server"
        mock_finding.remediation = "fix it"
        mock_finding.cwe_id = "CWE-94"
        mock_finding.llm_analysis = None
        mock_finding.source_file = None
        mock_finding.source_line = None
        mock_finding.dismissed_as = None
        mock_finding.dismissed_reason = None

        # Create mock Scan object
        mock_scan = MagicMock(spec=Scan)
        mock_scan.id = scan_id
        mock_scan.status = ScanStatus.COMPLETED
        mock_scan.created_at = now
        mock_scan.overall_score = 85
        mock_scan.grade = "B"
        mock_scan.repo_url = None
        mock_scan.commit_hash = None
        mock_scan.summary = {"total": 1, "by_severity": {"high": 1}, "by_checker": {"tool_poisoning": 1}}
        mock_scan.error_message = None
        mock_scan.findings = [mock_finding]
        mock_scan.tool_snapshots = []
        mock_scan.server_metadata = None
        mock_scan.code_graph = None

        # Mock session.execute to return the scan
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_scan
        mock_session.execute = AsyncMock(return_value=mock_result)

        resp = client.get(f"/api/scan/{scan_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == str(scan_id)
        assert data["status"] == "completed"
        assert data["overall_score"] == 85
        assert data["grade"] == "B"
        assert len(data["findings"]) == 1
        assert data["findings"][0]["checker"] == "tool_poisoning"
        assert data["findings"][0]["severity"] == "high"
        assert data["summary"]["total"] == 1

    def test_get_scan_not_found(self, client, mock_session):
        """GET /scan/{id} returns 404 when scan is not in the database."""
        scan_id = uuid.uuid4()

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute = AsyncMock(return_value=mock_result)

        resp = client.get(f"/api/scan/{scan_id}")
        assert resp.status_code == 404
        assert resp.json()["detail"] == "Scan not found"

    def test_get_scan_invalid_uuid(self, client, mock_session):
        """GET /scan/{id} returns 400 for invalid UUID."""
        resp = client.get("/api/scan/not-a-uuid")
        assert resp.status_code == 400
        assert resp.json()["detail"] == "Invalid scan ID format"


class TestReportRouteDB:
    """Verify that GET /scan/{scan_id}/pdf fetches from DB."""

    def test_download_pdf_not_found(self, client, mock_session):
        """GET /scan/{scan_id}/pdf returns 404 when scan not found."""
        scan_id = uuid.uuid4()

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute = AsyncMock(return_value=mock_result)

        resp = client.get(f"/api/scan/{scan_id}/pdf")
        assert resp.status_code == 404

    def test_download_pdf_from_db(self, client, mock_session):
        """GET /reports/{scan_id}/pdf generates PDF from DB scan data."""
        scan_id = uuid.uuid4()
        now = datetime.now(timezone.utc)

        mock_scan = MagicMock(spec=Scan)
        mock_scan.id = scan_id
        mock_scan.status = ScanStatus.COMPLETED
        mock_scan.created_at = now
        mock_scan.overall_score = 95
        mock_scan.grade = "A"
        mock_scan.summary = {"total": 0, "by_severity": {}, "by_checker": {}}
        mock_scan.error_message = None
        mock_scan.findings = []

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_scan
        mock_session.execute = AsyncMock(return_value=mock_result)

        with patch(
            "mcp_scanner.api.report_routes.PDFReportGenerator"
        ) as MockPDFGen:
            mock_gen = MagicMock()
            mock_gen.generate.return_value = b"%PDF-1.4 fake pdf content"
            MockPDFGen.return_value = mock_gen

            resp = client.get(f"/api/scan/{scan_id}/pdf")
            assert resp.status_code == 200
            assert resp.headers["content-type"] == "application/pdf"
            assert f"mcp-scan-{scan_id}" in resp.headers["content-disposition"]

            # Verify generate was called with correct data
            mock_gen.generate.assert_called_once()
            call_args = mock_gen.generate.call_args[0][0]
            assert call_args["score"] == 95
            assert call_args["grade"] == "A"
