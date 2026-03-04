"""Shared utility functions used by multiple checkers."""

from pathlib import Path

from mcp_scanner.models.scan_context import ToolDefinition


def resolve_source_location(
    tool: ToolDefinition,
    evidence: str,
    source_code_path: Path | None,
) -> tuple[str | None, int | None]:
    """Resolve a finding back to a source file and line number."""
    source_file = tool.raw.get("source_file")
    if not source_file:
        return None, None

    if not source_code_path:
        fallback_line = tool.raw.get("source_line")
        return source_file, fallback_line

    abs_path = source_code_path / source_file
    if not abs_path.is_file():
        fallback_line = tool.raw.get("source_line")
        return source_file, fallback_line

    # Try to grep for evidence text in the source file
    if len(evidence) >= 4:
        try:
            content = abs_path.read_text(encoding="utf-8", errors="ignore")
            # Single-line search first
            idx = content.find(evidence)
            if idx != -1:
                return source_file, content[:idx].count("\n") + 1
            # Multiline: try first line of evidence
            first_line = evidence.split("\n")[0].strip()
            if len(first_line) >= 4:
                idx = content.find(first_line)
                if idx != -1:
                    return source_file, content[:idx].count("\n") + 1
        except OSError:
            pass

    # Fall back to source_line from tool extraction
    fallback_line = tool.raw.get("source_line")
    return source_file, fallback_line
