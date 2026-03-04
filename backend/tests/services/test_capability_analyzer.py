"""Tests for the capability analyzer service."""

import pytest
from mcp_scanner.models.scan_context import ToolDefinition
from mcp_scanner.services.capability_analyzer import CapabilityAnalyzer, ToolLabels, ToxicFlow


def _tool(name: str, desc: str = "", schema: dict | None = None, server: str = "test") -> ToolDefinition:
    return ToolDefinition(
        server_name=server,
        tool_name=name,
        description=desc,
        input_schema=schema or {"properties": {}},
        raw={},
    )


class TestLabelTool:
    """Test per-tool capability labeling."""

    def test_file_reader_labels_private_data(self):
        tool = _tool("read_file", "Read a file from the filesystem", {
            "properties": {"path": {"type": "string", "description": "File path to read"}},
        })
        analyzer = CapabilityAnalyzer()
        labels = analyzer.label_tool(tool)
        assert labels.private_data >= 0.5

    def test_http_sender_labels_public_sink(self):
        tool = _tool("http_post", "Send an HTTP request", {
            "properties": {"url": {"type": "string", "format": "uri", "description": "Target URL"}},
        })
        analyzer = CapabilityAnalyzer()
        labels = analyzer.label_tool(tool)
        assert labels.is_public_sink >= 0.5

    def test_command_executor_labels_destructive(self):
        tool = _tool("run_command", "Execute a shell command", {
            "properties": {"command": {"type": "string", "description": "Shell command to run"}},
        })
        analyzer = CapabilityAnalyzer()
        labels = analyzer.label_tool(tool)
        assert labels.destructive >= 0.5

    def test_web_fetcher_labels_untrusted(self):
        tool = _tool("fetch_page", "Fetch and parse a web page", {
            "properties": {"url": {"type": "string", "description": "URL to fetch content from"}},
        })
        analyzer = CapabilityAnalyzer()
        labels = analyzer.label_tool(tool)
        assert labels.untrusted_content >= 0.4

    def test_simple_math_tool_all_labels_low(self):
        tool = _tool("add", "Add two numbers", {
            "properties": {
                "a": {"type": "number", "description": "First number"},
                "b": {"type": "number", "description": "Second number"},
            },
        })
        analyzer = CapabilityAnalyzer()
        labels = analyzer.label_tool(tool)
        assert labels.is_public_sink < 0.3
        assert labels.destructive < 0.3
        assert labels.untrusted_content < 0.3
        assert labels.private_data < 0.3

    def test_webhook_param_labels_sink(self):
        tool = _tool("notify", "Send notification", {
            "properties": {"webhook": {"type": "string", "description": "Webhook URL"}},
        })
        analyzer = CapabilityAnalyzer()
        labels = analyzer.label_tool(tool)
        assert labels.is_public_sink >= 0.5

    def test_credential_param_labels_private(self):
        tool = _tool("auth", "Authenticate user", {
            "properties": {"token": {"type": "string", "description": "Auth token"}},
        })
        analyzer = CapabilityAnalyzer()
        labels = analyzer.label_tool(tool)
        assert labels.private_data >= 0.5

    def test_empty_schema_all_labels_zero_or_low(self):
        tool = _tool("empty", "A tool with no parameters")
        analyzer = CapabilityAnalyzer()
        labels = analyzer.label_tool(tool)
        assert labels.is_public_sink <= 0.4
        assert labels.destructive <= 0.4


class TestToxicFlows:
    """Test cross-server toxic flow detection."""

    def test_cross_server_file_to_http_flow(self):
        """File reader on server A + HTTP sender on server B = toxic flow."""
        tools = {
            "server_a": [_tool("read_file", "Read files", {
                "properties": {"path": {"type": "string", "description": "File path"}},
            }, server="server_a")],
            "server_b": [_tool("http_post", "Send HTTP request", {
                "properties": {"url": {"type": "string", "format": "uri", "description": "Target URL"}},
            }, server="server_b")],
        }
        analyzer = CapabilityAnalyzer()
        flows = analyzer.find_toxic_flows(tools)
        assert len(flows) >= 1
        assert any(f.source_server == "server_a" and f.sink_server == "server_b" for f in flows)

    def test_same_server_no_toxic_flow(self):
        """Source and sink on same server should NOT produce toxic flow."""
        tools = {
            "server_a": [
                _tool("read_file", "Read files", {
                    "properties": {"path": {"type": "string", "description": "File path"}},
                }, server="server_a"),
                _tool("http_post", "Send HTTP request", {
                    "properties": {"url": {"type": "string", "format": "uri", "description": "Target URL"}},
                }, server="server_a"),
            ],
        }
        analyzer = CapabilityAnalyzer()
        flows = analyzer.find_toxic_flows(tools)
        assert len(flows) == 0

    def test_simple_tools_no_toxic_flow(self):
        """Two simple math tools on different servers = no flow."""
        tools = {
            "server_a": [_tool("add", "Add numbers", {
                "properties": {"a": {"type": "number"}, "b": {"type": "number"}},
            }, server="server_a")],
            "server_b": [_tool("multiply", "Multiply numbers", {
                "properties": {"x": {"type": "number"}, "y": {"type": "number"}},
            }, server="server_b")],
        }
        analyzer = CapabilityAnalyzer()
        flows = analyzer.find_toxic_flows(tools)
        assert len(flows) == 0

    def test_credential_to_sink_is_critical(self):
        """Private data -> public sink should be critical severity."""
        tools = {
            "server_a": [_tool("get_secrets", "Read credentials", {
                "properties": {"credentials": {"type": "string", "description": "API credentials"}},
            }, server="server_a")],
            "server_b": [_tool("webhook", "Send to webhook", {
                "properties": {"webhook": {"type": "string", "description": "Webhook URL to post to"}},
            }, server="server_b")],
        }
        analyzer = CapabilityAnalyzer()
        flows = analyzer.find_toxic_flows(tools)
        critical_flows = [f for f in flows if f.severity == "critical"]
        assert len(critical_flows) >= 1


class TestAnalyzeAll:
    """Test full analysis report."""

    def test_analyze_all_returns_report(self):
        tools = {
            "s1": [_tool("read_file", "Read files", {
                "properties": {"path": {"type": "string"}},
            }, server="s1")],
            "s2": [_tool("send", "Send data", {
                "properties": {"url": {"type": "string", "format": "uri"}},
            }, server="s2")],
        }
        analyzer = CapabilityAnalyzer()
        report = analyzer.analyze_all(tools)
        assert "s1/read_file" in report.tool_labels
        assert "s2/send" in report.tool_labels
        assert len(report.toxic_flows) >= 1
        assert "s1" in report.server_risk
        assert "s2" in report.server_risk

    def test_empty_definitions(self):
        analyzer = CapabilityAnalyzer()
        report = analyzer.analyze_all({})
        assert report.tool_labels == {}
        assert report.toxic_flows == []
        assert report.server_risk == {}


class TestEntropySignal:
    """Test entropy-based anomaly detection."""

    def test_entropy_signal_high_entropy_description(self):
        tool = ToolDefinition(
            server_name="s", tool_name="t",
            description="xJ7kQ9mZ3rW1pL8vY5nB2cF4gH6tA0dE xJ7kQ9mZ3rW1pL8vY5nB2cF4gH6tA0dE",
            input_schema={}, raw={},
        )
        analyzer = CapabilityAnalyzer()
        labels = analyzer.label_tool(tool)
        assert labels.entropy_score > 0.0

    def test_entropy_signal_normal_description(self):
        tool = ToolDefinition(
            server_name="s", tool_name="t",
            description="This tool sends an email to the specified recipient.",
            input_schema={}, raw={},
        )
        analyzer = CapabilityAnalyzer()
        labels = analyzer.label_tool(tool)
        assert labels.entropy_score == 0.0


class TestStructuralMismatch:
    """Test structural mismatch detection."""

    def test_simple_tool_with_suspicious_params(self):
        """A simple 'add' tool with extra string params is suspicious."""
        tool = _tool("add", "Add two numbers", {
            "required": ["a", "b"],
            "properties": {
                "a": {"type": "number"},
                "b": {"type": "number"},
                "webhook": {"type": "string"},
                "callback_url": {"type": "string"},
            },
        })
        analyzer = CapabilityAnalyzer()
        labels = analyzer.label_tool(tool)
        assert labels.structural_mismatch >= 0.8

    def test_simple_tool_with_one_suspicious_param(self):
        """A simple 'add' tool with one extra string param gets moderate score."""
        tool = _tool("add", "Add two numbers", {
            "required": ["a", "b"],
            "properties": {
                "a": {"type": "number"},
                "b": {"type": "number"},
                "url": {"type": "string"},
            },
        })
        analyzer = CapabilityAnalyzer()
        labels = analyzer.label_tool(tool)
        assert labels.structural_mismatch >= 0.4

    def test_simple_tool_with_benign_params(self):
        """A simple tool with only benign params should have 0.0 mismatch."""
        tool = _tool("add", "Add two numbers", {
            "required": ["a", "b"],
            "properties": {
                "a": {"type": "number"},
                "b": {"type": "number"},
                "format": {"type": "string"},
            },
        })
        analyzer = CapabilityAnalyzer()
        labels = analyzer.label_tool(tool)
        assert labels.structural_mismatch == 0.0

    def test_non_simple_tool_no_mismatch(self):
        """A non-simple tool name should not trigger mismatch."""
        tool = _tool("send_email", "Send an email", {
            "properties": {
                "to": {"type": "string"},
                "body": {"type": "string"},
            },
        })
        analyzer = CapabilityAnalyzer()
        labels = analyzer.label_tool(tool)
        assert labels.structural_mismatch == 0.0


class TestSameServerToxicFlows:
    """Test same-server toxic flow detection."""

    def test_same_server_toxic_flows(self):
        tools = {
            "my_server": [
                ToolDefinition(server_name="my_server", tool_name="read_file",
                    description="Read a file from the filesystem",
                    input_schema={"properties": {"path": {"type": "string"}}}, raw={}),
                ToolDefinition(server_name="my_server", tool_name="send_webhook",
                    description="Send data to a webhook URL",
                    input_schema={"properties": {"url": {"type": "string", "format": "uri"}, "data": {"type": "string"}}}, raw={}),
            ],
        }
        analyzer = CapabilityAnalyzer()
        flows = analyzer.find_toxic_flows(tools, include_same_server=True)
        assert len(flows) >= 1
        assert flows[0].source_server == flows[0].sink_server == "my_server"

    def test_same_server_skipped_by_default(self):
        """Without include_same_server, same-server flows are not returned."""
        tools = {
            "my_server": [
                ToolDefinition(server_name="my_server", tool_name="read_file",
                    description="Read a file from the filesystem",
                    input_schema={"properties": {"path": {"type": "string"}}}, raw={}),
                ToolDefinition(server_name="my_server", tool_name="send_webhook",
                    description="Send data to a webhook URL",
                    input_schema={"properties": {"url": {"type": "string", "format": "uri"}, "data": {"type": "string"}}}, raw={}),
            ],
        }
        analyzer = CapabilityAnalyzer()
        flows = analyzer.find_toxic_flows(tools)
        assert len(flows) == 0

    def test_self_flow_skipped(self):
        """Same tool on same server should NOT produce a flow even with include_same_server."""
        tools = {
            "my_server": [
                ToolDefinition(server_name="my_server", tool_name="rw_file",
                    description="Read and write files from the filesystem, can also send data to webhook",
                    input_schema={"properties": {
                        "path": {"type": "string"},
                        "url": {"type": "string", "format": "uri"},
                    }}, raw={}),
            ],
        }
        analyzer = CapabilityAnalyzer()
        flows = analyzer.find_toxic_flows(tools, include_same_server=True)
        # Self-flows (same tool to itself) should be skipped
        self_flows = [f for f in flows if f.source_tool == f.sink_tool]
        assert len(self_flows) == 0
