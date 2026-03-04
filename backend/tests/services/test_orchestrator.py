import pytest
from unittest.mock import AsyncMock, patch
from mcp_scanner.services.orchestrator import ScanOrchestrator
from mcp_scanner.services.scorer import ScoreCalculator
from mcp_scanner.checkers.base import Severity


def test_score_calculator_perfect():
    calc = ScoreCalculator()
    score, grade = calc.calculate(findings=[])
    assert score == 100
    assert grade == "A"


def test_score_calculator_critical():
    calc = ScoreCalculator()
    findings = [type("F", (), {"severity": Severity.CRITICAL})()] * 2
    score, grade = calc.calculate(findings=findings)
    assert score == 50
    assert grade == "C"


def test_score_calculator_floor():
    calc = ScoreCalculator()
    findings = [type("F", (), {"severity": Severity.CRITICAL})()] * 10
    score, grade = calc.calculate(findings=findings)
    assert score == 0
    assert grade == "F"


def test_score_calculator_mixed():
    calc = ScoreCalculator()
    findings = [
        type("F", (), {"severity": Severity.HIGH})(),
        type("F", (), {"severity": Severity.MEDIUM})(),
        type("F", (), {"severity": Severity.LOW})(),
    ]
    score, grade = calc.calculate(findings=findings)
    assert score == 79
    assert grade == "B"


@pytest.mark.asyncio
async def test_orchestrator_runs_scan():
    orchestrator = ScanOrchestrator()
    result = await orchestrator.run_scan()
    assert "scan_id" in result
    assert "findings" in result
    assert "score" in result
    assert "grade" in result
    assert "summary" in result
    assert isinstance(result["score"], int)
    assert result["grade"] in ("A", "B", "C", "D", "F")


@pytest.mark.asyncio
async def test_orchestrator_passes_prompt_and_resource_definitions():
    """Verify prompt_definitions and resource_definitions are passed to ScanContext."""
    from mcp_scanner.models.scan_context import PromptDefinition, ResourceDefinition, ToolDefinition

    mock_tools = {
        "srv": [ToolDefinition(
            server_name="srv", tool_name="test_tool",
            description="A test tool.", input_schema={"properties": {}}, raw={},
        )]
    }
    mock_prompts = {
        "srv": [PromptDefinition(
            server_name="srv", name="test_prompt", title="Test",
            description="A test prompt.", arguments=[],
        )]
    }
    mock_resources = {
        "srv": [ResourceDefinition(
            server_name="srv", name="test_resource", title="Test",
            uri="file:///data", description="A test resource.",
            mime_type="text/plain", size=100,
        )]
    }

    orchestrator = ScanOrchestrator()
    contexts_seen = []

    # Patch checkers to capture the ScanContext
    for checker in orchestrator.checkers:
        original = checker.check

        async def capture_check(ctx, _orig=original):
            contexts_seen.append(ctx)
            return await _orig(ctx)

        checker.check = capture_check

    await orchestrator.run_scan(
        tool_definitions=mock_tools,
        prompt_definitions=mock_prompts,
        resource_definitions=mock_resources,
    )

    assert len(contexts_seen) > 0
    ctx = contexts_seen[0]
    assert "srv" in ctx.prompt_definitions
    assert len(ctx.prompt_definitions["srv"]) == 1
    assert ctx.prompt_definitions["srv"][0].name == "test_prompt"
    assert "srv" in ctx.resource_definitions
    assert len(ctx.resource_definitions["srv"]) == 1
    assert ctx.resource_definitions["srv"][0].name == "test_resource"
