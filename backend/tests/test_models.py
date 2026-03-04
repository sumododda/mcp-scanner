import uuid
from mcp_scanner.models.scan import Scan, ScanStatus
from mcp_scanner.models.finding import Finding, Severity
from mcp_scanner.models.tool_snapshot import ToolSnapshot


def test_scan_model_fields():
    scan = Scan(
        id=uuid.uuid4(),
        status=ScanStatus.PENDING,
        mcp_config={"mcpServers": {}},
    )
    assert scan.status == ScanStatus.PENDING
    assert scan.overall_score is None


def test_finding_severity_ordering():
    assert Severity.CRITICAL.weight > Severity.HIGH.weight
    assert Severity.HIGH.weight > Severity.MEDIUM.weight
    assert Severity.MEDIUM.weight > Severity.LOW.weight


def test_tool_snapshot_hash():
    snap = ToolSnapshot.compute_hash("server1", "tool1", {"description": "test"})
    assert isinstance(snap, str)
    assert len(snap) == 64  # SHA-256 hex


def test_scan_context_has_capability_report():
    from mcp_scanner.models.scan_context import ScanContext
    ctx = ScanContext(mcp_config={})
    assert ctx.capability_report is None
