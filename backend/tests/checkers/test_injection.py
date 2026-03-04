import pytest

from mcp_scanner.checkers.injection import InjectionChecker
from mcp_scanner.models.scan_context import ScanContext, ToolDefinition


def _ctx(tools: dict[str, list[ToolDefinition]]) -> ScanContext:
    return ScanContext(
        mcp_config={"mcpServers": {}},
        tool_definitions=tools,
    )


@pytest.mark.asyncio
async def test_command_injection_param():
    tool = ToolDefinition(
        server_name="srv",
        tool_name="run_task",
        description="Run a task.",
        input_schema={
            "properties": {
                "command": {"type": "string", "description": "The command to run."},
                "shell": {"type": "string", "description": "Shell to use."},
            }
        },
        raw={},
    )
    checker = InjectionChecker()
    result = await checker.check(_ctx({"srv": [tool]}))
    cmd_findings = [f for f in result.findings if "command injection" in f.title.lower()]
    assert len(cmd_findings) >= 2


@pytest.mark.asyncio
async def test_sql_injection_param():
    tool = ToolDefinition(
        server_name="srv",
        tool_name="db_query",
        description="Query the database.",
        input_schema={
            "properties": {
                "query": {"type": "string", "description": "The SQL query to execute."},
                "where_clause": {"type": "string", "description": "WHERE clause for filtering."},
            }
        },
        raw={},
    )
    checker = InjectionChecker()
    result = await checker.check(_ctx({"srv": [tool]}))
    sql_findings = [f for f in result.findings if "sql injection" in f.title.lower()]
    assert len(sql_findings) >= 2


@pytest.mark.asyncio
async def test_desc_pattern_command_execution():
    tool = ToolDefinition(
        server_name="srv",
        tool_name="executor",
        description="Execute scripts.",
        input_schema={
            "properties": {
                "input": {
                    "type": "string",
                    "description": "This will execute the given shell command via subprocess.",
                }
            }
        },
        raw={},
    )
    checker = InjectionChecker()
    result = await checker.check(_ctx({"srv": [tool]}))
    desc_findings = [f for f in result.findings if "description suggests" in f.title.lower()]
    assert len(desc_findings) >= 1


@pytest.mark.asyncio
async def test_clean_tool_no_findings():
    tool = ToolDefinition(
        server_name="safe",
        tool_name="get_weather",
        description="Get weather information for a city.",
        input_schema={
            "properties": {
                "city": {"type": "string", "description": "City name."},
                "units": {"type": "string", "description": "Temperature units (C or F)."},
            }
        },
        raw={},
    )
    checker = InjectionChecker()
    result = await checker.check(_ctx({"safe": [tool]}))
    assert len(result.findings) == 0
