from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp_scanner.services.capability_analyzer import CapabilityReport
    from mcp_scanner.services.code_graph import CodeGraph


@dataclass
class ToolDefinition:
    server_name: str
    tool_name: str
    description: str
    input_schema: dict
    raw: dict


@dataclass
class PromptDefinition:
    server_name: str
    name: str
    title: str | None
    description: str | None
    arguments: list[dict]  # [{name, description, required}]


@dataclass
class ResourceDefinition:
    server_name: str
    name: str
    title: str | None
    uri: str
    description: str | None
    mime_type: str | None
    size: int | None


@dataclass
class ScanContext:
    mcp_config: dict
    tool_definitions: dict[str, list[ToolDefinition]] = field(default_factory=dict)
    prompt_definitions: dict[str, list[PromptDefinition]] = field(default_factory=dict)
    resource_definitions: dict[str, list[ResourceDefinition]] = field(default_factory=dict)
    historical_snapshots: list = field(default_factory=list)
    source_code_path: Path | None = None
    capability_report: CapabilityReport | None = None
    code_graph: CodeGraph | None = None
