import pytest
from mcp_scanner.checkers.base import BaseChecker, CheckerResult
from mcp_scanner.models.scan_context import ScanContext


class DummyChecker(BaseChecker):
    name = "dummy"
    description = "A dummy checker for testing"

    async def check(self, context: ScanContext) -> CheckerResult:
        return CheckerResult(findings=[], checker_name=self.name)


@pytest.mark.asyncio
async def test_dummy_checker_returns_empty_result():
    checker = DummyChecker()
    ctx = ScanContext(
        mcp_config={"mcpServers": {}},
        tool_definitions={},
        historical_snapshots=[],
        source_code_path=None,
    )
    result = await checker.check(ctx)
    assert result.findings == []
    assert result.checker_name == "dummy"


def test_base_checker_is_abstract():
    with pytest.raises(TypeError):
        BaseChecker()
