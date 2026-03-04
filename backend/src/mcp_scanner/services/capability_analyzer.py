"""Capability Analyzer — schema-based tool risk labeling and toxic flow detection.

Inspired by Snyk/Invariant's 4-dimension tool labeling model. Analyzes what tools
CAN do based on their schemas and descriptions, not what they SAY they do.

Detection layers:
1. Per-tool capability labeling (4 dimensions: is_public_sink, destructive, untrusted_content, private_data)
2. Cross-server toxic flow detection (source->sink data flow paths)
3. Per-server aggregate risk scoring
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

from mcp_scanner.models.scan_context import ToolDefinition


@dataclass
class ToolLabels:
    """4-dimension risk labels per tool (0.0 - 1.0 each)."""
    is_public_sink: float = 0.0    # Can send data externally
    destructive: float = 0.0       # Can modify/delete data
    untrusted_content: float = 0.0 # Processes untrusted external input
    private_data: float = 0.0      # Accesses sensitive/private data
    entropy_score: float = 0.0     # High-entropy anomaly signal
    structural_mismatch: float = 0.0  # Simple tool with suspicious params


@dataclass
class ToxicFlow:
    """A dangerous data flow path between tools on different servers."""
    source_server: str
    source_tool: str
    sink_server: str
    sink_tool: str
    flow_type: str     # e.g. "private_data_to_public_sink"
    severity: str      # "critical", "high", "medium"


@dataclass
class CapabilityReport:
    """Complete capability analysis results."""
    tool_labels: dict[str, ToolLabels] = field(default_factory=dict)  # keyed by "server/tool"
    toxic_flows: list[ToxicFlow] = field(default_factory=list)
    server_risk: dict[str, float] = field(default_factory=dict)  # per-server risk 0.0-1.0


# -- Schema signal sets --

_SINK_PARAM_NAMES = {
    "url", "endpoint", "webhook", "callback", "hook_url", "api_url",
    "destination", "target_url", "notify_url", "webhook_url", "post_url",
    "send_to", "forward_to", "redirect_url",
}

_SINK_DESC_KEYWORDS = re.compile(
    r"(?i)\b(send|upload|post|forward|transmit|email|notify|push|publish|broadcast|webhook)\b"
)

_DESTRUCTIVE_PARAM_NAMES = {
    "command", "cmd", "script", "shell", "exec", "run", "code",
    "program", "query", "sql", "expression",
}

_DESTRUCTIVE_DESC_KEYWORDS = re.compile(
    r"(?i)\b(delete|remove|drop|destroy|overwrite|modify|write|create|update|execute|kill|terminate|truncate)\b"
)

_UNTRUSTED_PARAM_NAMES = {
    "url", "uri", "link", "source_url", "feed_url", "page_url",
    "fetch_url", "scrape_url", "input_url",
}

_UNTRUSTED_DESC_KEYWORDS = re.compile(
    r"(?i)\b(fetch|download|scrape|crawl|read\s+url|web\s+page|external|http|browse|parse\s+url)\b"
)

_PRIVATE_PARAM_NAMES = {
    "path", "file", "filepath", "file_path", "filename", "directory",
    "dir", "folder", "token", "key", "secret", "password", "api_key",
    "credentials", "private_key", "auth", "cookie", "session",
    "config_path", "env_file",
}

_PRIVATE_DESC_KEYWORDS = re.compile(
    r"(?i)\b(read\s+file|file\s+system|credentials|ssh|\.env|config|private|secret|password|"
    r"access\s+token|api\s+key|database|sensitive)\b"
)


class CapabilityAnalyzer:
    """Analyzes tool capabilities from schemas and detects toxic flows."""

    def label_tool(self, tool: ToolDefinition) -> ToolLabels:
        """Derive 4-dimension risk labels from a tool's schema and description."""
        labels = ToolLabels()
        schema = tool.input_schema or {}
        props = schema.get("properties", {})
        desc = (tool.description or "").lower()

        for param_name, param_def in props.items():
            lower = param_name.lower()
            param_desc = (param_def.get("description", "") or "").lower()
            param_format = param_def.get("format", "")
            combined_text = f"{lower} {param_desc}"

            # is_public_sink: can send data out
            if lower in _SINK_PARAM_NAMES or param_format == "uri":
                labels.is_public_sink = max(labels.is_public_sink, 0.8)
            elif _SINK_DESC_KEYWORDS.search(param_desc):
                labels.is_public_sink = max(labels.is_public_sink, 0.5)

            # destructive: can modify/destroy/execute
            if lower in _DESTRUCTIVE_PARAM_NAMES:
                labels.destructive = max(labels.destructive, 0.8)
            elif _DESTRUCTIVE_DESC_KEYWORDS.search(param_desc):
                labels.destructive = max(labels.destructive, 0.5)

            # untrusted_content: reads from external sources
            if lower in _UNTRUSTED_PARAM_NAMES and ("fetch" in combined_text or "read" in combined_text or "scrape" in combined_text or "source" in lower):
                labels.untrusted_content = max(labels.untrusted_content, 0.8)
            elif _UNTRUSTED_DESC_KEYWORDS.search(param_desc):
                labels.untrusted_content = max(labels.untrusted_content, 0.5)

            # private_data: accesses sensitive data
            if lower in _PRIVATE_PARAM_NAMES:
                labels.private_data = max(labels.private_data, 0.7)
            elif _PRIVATE_DESC_KEYWORDS.search(param_desc):
                labels.private_data = max(labels.private_data, 0.5)

        # Description-level signals (tool-wide)
        if _SINK_DESC_KEYWORDS.search(desc):
            labels.is_public_sink = max(labels.is_public_sink, 0.4)
        if _DESTRUCTIVE_DESC_KEYWORDS.search(desc):
            labels.destructive = max(labels.destructive, 0.4)
        if _UNTRUSTED_DESC_KEYWORDS.search(desc):
            labels.untrusted_content = max(labels.untrusted_content, 0.4)
        if _PRIVATE_DESC_KEYWORDS.search(desc):
            labels.private_data = max(labels.private_data, 0.4)

        # Entropy scoring — detect high-entropy gibberish in descriptions
        raw_desc = tool.description or ""
        if raw_desc and len(raw_desc) > 20:
            labels.entropy_score = self._description_entropy_score(raw_desc)

        # Structural mismatch — simple tool names with suspicious extra params
        required = schema.get("required", [])
        labels.structural_mismatch = self._structural_mismatch_score(tool, props, required)

        return labels

    _SIMPLE = {
        "add", "sum", "subtract", "multiply", "divide", "count",
        "calculate", "compute", "math", "rand", "random", "ping",
        "time", "date", "now", "hello", "greet", "echo", "noop",
    }

    @staticmethod
    def _description_entropy_score(desc: str) -> float:
        """Compute an anomaly score based on Shannon entropy of long tokens.

        Tokens >= 20 chars that have entropy > 4.0 bits are suspicious
        (random-looking gibberish rather than natural language).
        Returns a normalized 0.0-1.0 score.
        """
        long_tokens = re.findall(r"\S{20,}", desc)
        if not long_tokens:
            return 0.0

        max_entropy = 0.0
        for token in long_tokens:
            freq: dict[str, int] = {}
            for ch in token:
                freq[ch] = freq.get(ch, 0) + 1
            length = len(token)
            entropy = -sum(
                (c / length) * math.log2(c / length)
                for c in freq.values()
            )
            max_entropy = max(max_entropy, entropy)

        if max_entropy > 4.0:
            return min(1.0, max(0.0, (max_entropy - 4.0) / 2.0))
        return 0.0

    @staticmethod
    def _structural_mismatch_score(
        tool: ToolDefinition,
        props: dict,
        required: list,
    ) -> float:
        """Detect simple tool names that carry suspicious extra string params.

        A tool named "add" that accepts optional string params like "webhook"
        is structurally suspicious.
        """
        name_lower = tool.tool_name.lower().replace("-", "_")
        if name_lower not in CapabilityAnalyzer._SIMPLE or not props:
            return 0.0

        _BENIGN_PARAM_NAMES = {"format", "output", "result_type"}
        suspicious_count = 0
        for param_name, param_def in props.items():
            if param_name in required:
                continue
            if param_def.get("type") != "string":
                continue
            if param_name.lower() in _BENIGN_PARAM_NAMES:
                continue
            suspicious_count += 1

        if suspicious_count >= 2:
            return 0.8
        if suspicious_count == 1:
            return 0.4
        return 0.0

    def find_toxic_flows(
        self,
        tool_definitions: dict[str, list[ToolDefinition]],
        threshold: float = 0.5,
        include_same_server: bool = False,
    ) -> list[ToxicFlow]:
        """Find dangerous source->sink data flow paths.

        By default only cross-server flows are detected.  Set
        *include_same_server* to ``True`` to also surface intra-server
        flows (self-flows where source and sink are the same tool are
        always skipped).
        """
        # Collect sources (untrusted_content or private_data tools)
        sources: list[tuple[str, ToolDefinition, ToolLabels, str]] = []  # (server, tool, labels, type)
        sinks: list[tuple[str, ToolDefinition, ToolLabels, str]] = []

        for server, tools in tool_definitions.items():
            for tool in tools:
                labels = self.label_tool(tool)
                if labels.untrusted_content >= threshold:
                    sources.append((server, tool, labels, "untrusted_content"))
                if labels.private_data >= threshold:
                    sources.append((server, tool, labels, "private_data"))
                if labels.is_public_sink >= threshold:
                    sinks.append((server, tool, labels, "public_sink"))
                if labels.destructive >= threshold:
                    sinks.append((server, tool, labels, "destructive"))

        # Cross-server source->sink = toxic flow
        flows: list[ToxicFlow] = []
        seen: set[tuple[str, str, str, str]] = set()  # Dedup
        for src_server, src_tool, src_labels, src_type in sources:
            for sink_server, sink_tool, sink_labels, sink_type in sinks:
                if not include_same_server and src_server == sink_server:
                    continue
                if src_tool.tool_name == sink_tool.tool_name:
                    continue  # Skip self-flows
                key = (src_server, src_tool.tool_name, sink_server, sink_tool.tool_name)
                if key in seen:
                    continue
                seen.add(key)

                flow_type = f"{src_type}_to_{sink_type}"

                # Severity based on source type
                if src_type == "private_data" and sink_type == "public_sink":
                    severity = "critical"
                elif src_type == "untrusted_content" and sink_type == "destructive":
                    severity = "critical"
                elif src_type == "private_data":
                    severity = "high"
                else:
                    severity = "high"

                flows.append(ToxicFlow(
                    source_server=src_server,
                    source_tool=src_tool.tool_name,
                    sink_server=sink_server,
                    sink_tool=sink_tool.tool_name,
                    flow_type=flow_type,
                    severity=severity,
                ))

        return flows

    def analyze_all(
        self,
        tool_definitions: dict[str, list[ToolDefinition]],
        include_same_server: bool = False,
    ) -> CapabilityReport:
        """Full analysis: per-tool labels + toxic flows + per-server risk."""
        all_labels: dict[str, ToolLabels] = {}
        for server, tools in tool_definitions.items():
            for tool in tools:
                key = f"{server}/{tool.tool_name}"
                all_labels[key] = self.label_tool(tool)

        flows = self.find_toxic_flows(tool_definitions, include_same_server=include_same_server)

        # Per-server risk: max of any tool label dimension + flow penalty
        server_risk: dict[str, float] = {}
        for server in tool_definitions:
            server_labels = [
                lbl for k, lbl in all_labels.items() if k.startswith(f"{server}/")
            ]
            if not server_labels:
                server_risk[server] = 0.0
                continue
            max_dim = max(
                max(l.is_public_sink, l.destructive, l.untrusted_content, l.private_data)
                for l in server_labels
            )
            flow_penalty = 0.15 * len([f for f in flows if f.source_server == server or f.sink_server == server])
            server_risk[server] = min(1.0, max_dim + flow_penalty)

        return CapabilityReport(
            tool_labels=all_labels,
            toxic_flows=flows,
            server_risk=server_risk,
        )
