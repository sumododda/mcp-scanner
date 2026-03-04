import json
import logging
import os
import re

import httpx

from mcp_scanner.config import settings
from mcp_scanner.models.scan_context import PromptDefinition, ResourceDefinition, ToolDefinition

logger = logging.getLogger(__name__)

SOURCE_EXTENSIONS = {".py", ".ts", ".js", ".go", ".rs", ".cs", ".java", ".kt"}
MAX_SAMPLE_CHARS = 15_000
MAX_REGEX_ATTEMPTS = 3

# Skip these directories during file discovery
SKIP_DIRS = {
    ".git", "node_modules", "vendor", "__pycache__", ".venv", "venv",
    "dist", "build", ".tox", ".mypy_cache", "target", "bin", "obj",
    "__toolsnaps__", "testdata", "fixtures", "e2e",
}

# MCP SDK import patterns — detect which SDK is used per language
SDK_IMPORT_PATTERNS = [
    # Python
    r'from\s+mcp',
    r'import\s+mcp',
    r'FastMCP',
    # TypeScript/JavaScript
    r'@modelcontextprotocol/sdk',
    r'McpServer',
    # Go
    r'mark3labs/mcp-go',
    r'modelcontextprotocol/go-sdk',
    r'mcp\.Tool\{',
    r'mcp\.NewTool\(',
    # Rust
    r'use\s+rmcp',
    r'#\[tool_box\]',
    r'#\[tool\(',
    # C#/.NET
    r'McpServerTool',
    r'ModelContextProtocol',
    # Java/Kotlin
    r'io\.modelcontextprotocol',
    r'@McpTool',
]

# Broad tool registration patterns across all SDKs
TOOL_REGISTRATION_PATTERNS = [
    r'server\.tool\s*\(',             # Python/TS MCP SDK
    r'@mcp\.tool',                     # Python decorator
    r'server\.registerTool\s*\(',      # TS newer API
    r'addTool\s*\(',                   # Generic SDK pattern
    r's\.AddTool\s*\(',                # Go mcp-go
    r'mcp\.AddTool\s*\(',              # Go official SDK
    r'mcp\.NewTool\s*\(',              # Go mcp-go
    r'mcp\.Tool\{',                    # Go struct literal
    r'#\[tool\(',                      # Rust rmcp macro
    r'#\[tool_box\]',                  # Rust rmcp impl macro
    r'\[McpServerTool',                # C# attribute
    r'@McpTool',                       # Java annotation
    r'new\s+Tool\s*\(',               # Java core SDK
    r'WithDescription\s*\(',           # Go mcp-go builder
    r'inputSchema',                    # Generic schema definition
    r'CallToolRequest',                # Go/TS handler
    r'ListToolsRequestSchema',         # Go/TS handler
]

# Files likely to contain tool definitions (name-based heuristics)
TOOL_FILE_PATTERNS = [
    r'tool',          # tools.go, tool_handler.ts, math_tools.py
    r'server\.py$',   # Python MCP entry point
    r'main\.go$',     # Go entry point
    r'index\.ts$',    # TS entry point
    r'index\.js$',    # JS entry point
    r'main\.rs$',     # Rust entry point
    r'Program\.cs$',  # C# entry point
]

# Regex patterns for extracting prompt registrations from source
PROMPT_REGISTRATION_PATTERNS = [
    # TypeScript/JS: server.prompt("name", "description", {args}, handler)
    re.compile(
        r'server\.prompt\s*\(\s*["\'](?P<name>[^"\']+)["\']\s*,\s*["\'](?P<description>[^"\']*)["\']',
    ),
    # Python decorator: @mcp.prompt() / @server.prompt()
    re.compile(
        r'@(?:mcp|server)\.prompt\s*\(\s*(?:name\s*=\s*)?["\'](?P<name>[^"\']+)["\']',
    ),
    # Python: server.add_prompt / server.register_prompt
    re.compile(
        r'(?:add_prompt|register_prompt)\s*\(\s*["\'](?P<name>[^"\']+)["\']',
    ),
]

# Regex patterns for extracting resource registrations from source
RESOURCE_REGISTRATION_PATTERNS = [
    # TypeScript/JS: server.resource("name", "uri://template", handler)
    re.compile(
        r'server\.resource\s*\(\s*["\'](?P<name>[^"\']+)["\']\s*,\s*["\'](?P<uri>[^"\']*)["\']',
    ),
    # Python decorator: @mcp.resource("uri://...")
    re.compile(
        r'@(?:mcp|server)\.resource\s*\(\s*["\'](?P<uri>[^"\']+)["\']',
    ),
    # Python: server.add_resource
    re.compile(
        r'(?:add_resource|register_resource)\s*\(\s*["\'](?P<name>[^"\']+)["\']',
    ),
]

DISCOVERY_PROMPT = """You are analyzing an MCP (Model Context Protocol) server repository to find which source files contain tool definitions.

MCP tools are registered differently per SDK:
- Python: @mcp.tool() decorator or server.tool() calls
- TypeScript: server.tool() or server.registerTool() with Zod schemas
- Go (mcp-go): mcp.NewTool() + s.AddTool(), or mcp.Tool{{}} struct literals
- Go (official): mcp.AddTool(server, &mcp.Tool{{Name: "..."}}, handler)
- Rust: #[tool] attribute macro on methods in #[tool_box] impl blocks
- C#: [McpServerTool] attribute on methods in [McpServerToolType] classes
- Java: new Tool("name", ...) or @McpTool annotation

Given the repository structure and file previews below, identify which files contain actual MCP tool DEFINITIONS (not tests, not imports, not usage).

Return JSON: {{"files": ["path/to/file1.go", "path/to/file2.ts", ...]}}
Return at most 20 files. Prioritize files that DEFINE tools over files that merely USE them.
If unsure, include the file — it's better to include extras than miss tool definitions.

Repository structure:
---
{tree}
---

File previews (first lines of candidate files):
---
{previews}
---"""

PATTERN_GENERATION_PROMPT = """Analyze this MCP server source code and generate a Python regex that captures each tool definition.

The regex MUST have these named capture groups:
- `name`: the tool's registered name string (e.g., "get_file_contents", "search_issues")
- `description`: the tool's description string

Requirements:
- Python `re` module compatible syntax
- Will be compiled with `re.DOTALL` flag
- Must match EVERY tool definition in the file, not just the first
- Use non-greedy quantifiers (.*?) between groups
- Escape special regex characters properly

Count the exact number of distinct tool definitions visible in this sample.

Return JSON: {{
  "pattern": "the regex pattern",
  "expected_matches": <exact count of tools in sample>,
  "explanation": "brief explanation of what the pattern matches"
}}

Source code:
---
{sample}
---"""

PATTERN_REFINEMENT_PROMPT = """Your regex pattern needs adjustment.

Previous pattern: {pattern}
Expected: {expected} matches
Found: {actual} matches
{match_info}

Fix the regex to capture ALL tool definitions. Same rules: named groups `name` and `description`, re.DOTALL compatible.

Return JSON: {{
  "pattern": "fixed regex",
  "expected_matches": <count>,
  "explanation": "what you changed"
}}

Source code:
---
{sample}
---"""

class RepoAnalyzer:
    def __init__(self, api_key: str | None = None, model: str | None = None):
        self.api_key = api_key or settings.openrouter_api_key
        self.model = model or settings.openrouter_model
        self.base_url = "https://openrouter.ai/api/v1"

    @staticmethod
    def _parse_llm_response(raw: str) -> dict:
        """Parse LLM response, handling markdown fences and bare JSON."""
        raw = raw.strip()

        # Try direct JSON parse
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass

        # Try extracting from markdown code fences
        fence_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", raw, re.DOTALL)
        if fence_match:
            try:
                return json.loads(fence_match.group(1).strip())
            except json.JSONDecodeError:
                pass

        # Try extracting bare JSON object
        brace_match = re.search(r"\{.*\}", raw, re.DOTALL)
        if brace_match:
            try:
                return json.loads(brace_match.group(0))
            except json.JSONDecodeError:
                pass

        logger.warning("Could not parse LLM response as JSON: %s", raw[:200])
        return {"mcpServers": {}}

    async def extract_tools_from_source(self, clone_path: str) -> list[ToolDefinition]:
        """Extract tool definitions from cloned source using LLM-generated regex.

        Phase 1: Discover which files contain tool definitions using repo structure
                 + file heuristics + LLM reasoning.
        Phase 2: Generate a regex pattern from a sample file, validate it in a loop
                 by checking match count against LLM's expected count.
        Phase 3: Apply validated regex to ALL files locally — no more LLM calls.
        """
        if not self.api_key:
            logger.warning("No OpenRouter API key configured, cannot extract tools from source")
            return []

        try:
            # Phase 1: Smart file discovery
            candidate_files = self._discover_candidate_files(clone_path)
            if not candidate_files:
                logger.info("No candidate tool files found in %s", clone_path)
                return []

            tree = self._build_tree(clone_path)
            previews = self._build_previews(clone_path, candidate_files)

            discovery_raw = await self._call_llm(
                DISCOVERY_PROMPT.replace("{tree}", tree).replace("{previews}", previews)
            )
            selected_files = self._parse_discovery_response(discovery_raw, clone_path)

            # Fallback: if LLM returned nothing, use our heuristic candidates directly
            if not selected_files:
                selected_files = candidate_files[:15]

            # Phase 2: Generate + validate regex on sample
            sample_file, sample_content = self._pick_best_sample(clone_path, selected_files)
            if not sample_content:
                logger.warning("No sample content available for regex generation")
                return []

            pattern = await self._generate_tool_regex(sample_content, sample_file)
            if pattern is None:
                logger.warning("Failed to generate valid tool extraction regex")
                return []

            # Phase 3: Apply regex to all selected files locally
            tools = self._extract_tools_with_regex(clone_path, selected_files, pattern)
            logger.info("Extracted %d tools from %d files using regex", len(tools), len(selected_files))
            return tools

        except Exception:
            logger.warning("LLM tool extraction failed", exc_info=True)
            return []

    def extract_prompts_from_source(self, clone_path: str, server_name: str = "source") -> list[PromptDefinition]:
        """Extract prompt definitions from source using regex patterns."""
        results: list[PromptDefinition] = []
        seen: set[str] = set()

        for root, dirs, files in os.walk(clone_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
            for fname in files:
                ext = os.path.splitext(fname)[1]
                if ext not in SOURCE_EXTENSIONS:
                    continue
                if self._is_test_file(fname):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except OSError:
                    continue

                for pattern in PROMPT_REGISTRATION_PATTERNS:
                    for match in pattern.finditer(content):
                        groups = match.groupdict()
                        name = groups.get("name", "").strip()
                        if not name or name in seen:
                            continue
                        seen.add(name)
                        results.append(PromptDefinition(
                            server_name=server_name,
                            name=name,
                            title=None,
                            description=groups.get("description", "").strip() or None,
                            arguments=[],
                        ))

        logger.info("Extracted %d prompts from source in %s", len(results), clone_path)
        return results

    def extract_resources_from_source(self, clone_path: str, server_name: str = "source") -> list[ResourceDefinition]:
        """Extract resource definitions from source using regex patterns."""
        results: list[ResourceDefinition] = []
        seen: set[str] = set()

        for root, dirs, files in os.walk(clone_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
            for fname in files:
                ext = os.path.splitext(fname)[1]
                if ext not in SOURCE_EXTENSIONS:
                    continue
                if self._is_test_file(fname):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except OSError:
                    continue

                for pattern in RESOURCE_REGISTRATION_PATTERNS:
                    for match in pattern.finditer(content):
                        groups = match.groupdict()
                        name = groups.get("name", "").strip()
                        uri = groups.get("uri", "").strip()
                        key = name or uri
                        if not key or key in seen:
                            continue
                        seen.add(key)
                        results.append(ResourceDefinition(
                            server_name=server_name,
                            name=name or uri,
                            title=None,
                            uri=uri or "",
                            description=None,
                            mime_type=None,
                            size=None,
                        ))

        logger.info("Extracted %d resources from source in %s", len(results), clone_path)
        return results

    def _discover_candidate_files(self, clone_path: str) -> list[str]:
        """Find files likely to contain MCP tool definitions using multiple signals.

        Signals (in priority order):
        1. Files with MCP SDK imports (strongest signal)
        2. Files matching tool registration regex patterns
        3. Files with tool-related names (tools.go, server.py, etc.)
        """
        sdk_import_compiled = [re.compile(p) for p in SDK_IMPORT_PATTERNS]
        tool_reg_compiled = [re.compile(p) for p in TOOL_REGISTRATION_PATTERNS]
        file_name_compiled = [re.compile(p, re.IGNORECASE) for p in TOOL_FILE_PATTERNS]

        # Collect files with scores
        scored_files: dict[str, int] = {}

        for root, dirs, files in os.walk(clone_path):
            # Prune directories in-place
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]

            for fname in files:
                ext = os.path.splitext(fname)[1]
                if ext not in SOURCE_EXTENSIONS:
                    continue

                # Skip test files
                if self._is_test_file(fname):
                    continue

                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, clone_path)
                score = 0

                # Signal 1: File name matches tool patterns (+2)
                for pat in file_name_compiled:
                    if pat.search(fname):
                        score += 2
                        break

                # Read file content for deeper signals
                try:
                    with open(fpath, encoding="utf-8", errors="ignore") as f:
                        content = f.read(20_000)  # Read first 20KB for pattern matching
                except OSError:
                    continue

                # Signal 2: SDK imports (+5, strongest)
                for pat in sdk_import_compiled:
                    if pat.search(content):
                        score += 5
                        break

                # Signal 3: Tool registration patterns (+3 each, up to 9)
                reg_matches = 0
                for pat in tool_reg_compiled:
                    if pat.search(content):
                        reg_matches += 1
                        if reg_matches >= 3:
                            break
                score += reg_matches * 3

                if score > 0:
                    scored_files[rel_path] = score

        # Sort by score descending, return top candidates
        sorted_files = sorted(scored_files, key=lambda f: scored_files[f], reverse=True)
        logger.info(
            "Found %d candidate tool files (top scores: %s)",
            len(sorted_files),
            {f: scored_files[f] for f in sorted_files[:5]},
        )
        return sorted_files

    @staticmethod
    def _is_test_file(fname: str) -> bool:
        """Check if a file is a test file."""
        lower = fname.lower()
        return (
            lower.startswith("test_")
            or lower.endswith("_test.go")
            or lower.endswith("_test.rs")
            or lower.endswith(".test.ts")
            or lower.endswith(".test.js")
            or lower.endswith(".spec.ts")
            or lower.endswith(".spec.js")
            or lower.endswith("tests.py")
            or "test" in lower.split(os.sep)
        )

    @staticmethod
    def _build_tree(clone_path: str, max_chars: int = 8_000) -> str:
        """Build a directory tree string for the LLM, skipping irrelevant dirs."""
        lines: list[str] = []
        total = 0
        for root, dirs, files in os.walk(clone_path):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("."))
            rel_root = os.path.relpath(root, clone_path)
            if rel_root == ".":
                rel_root = ""

            for fname in sorted(files):
                ext = os.path.splitext(fname)[1]
                if ext not in SOURCE_EXTENSIONS and fname not in ("go.mod", "package.json", "Cargo.toml", "pyproject.toml"):
                    continue
                path = f"{rel_root}/{fname}" if rel_root else fname
                line = path + "\n"
                if total + len(line) > max_chars:
                    lines.append("... (truncated)\n")
                    return "".join(lines)
                lines.append(line)
                total += len(line)
        return "".join(lines)

    @staticmethod
    def _build_previews(clone_path: str, candidate_files: list[str], max_chars: int = 15_000) -> str:
        """Build file header previews (first 30 lines) for candidate files."""
        previews: list[str] = []
        total = 0
        for rel_path in candidate_files[:25]:  # Cap at 25 files
            fpath = os.path.join(clone_path, rel_path)
            try:
                with open(fpath, encoding="utf-8", errors="ignore") as f:
                    first_lines = []
                    for i, line in enumerate(f):
                        if i >= 30:
                            break
                        first_lines.append(line)
            except OSError:
                continue

            preview = f"=== {rel_path} ===\n" + "".join(first_lines) + "\n"
            if total + len(preview) > max_chars:
                break
            previews.append(preview)
            total += len(preview)
        return "".join(previews)

    def _parse_discovery_response(self, raw: str, clone_path: str) -> list[str]:
        """Parse Phase 1 LLM response into list of file paths."""
        parsed = self._parse_llm_response(raw)
        files = parsed.get("files", [])
        if not isinstance(files, list):
            return []

        # Validate that files exist
        valid: list[str] = []
        for f in files:
            if not isinstance(f, str):
                continue
            fpath = os.path.join(clone_path, f)
            if os.path.isfile(fpath):
                valid.append(f)
        return valid

    def _pick_best_sample(self, clone_path: str, files: list[str]) -> tuple[str, str]:
        """Pick the best sample file for regex generation.

        Prefers files that: (1) fit entirely within MAX_SAMPLE_CHARS, and
        (2) have the most tool registration pattern matches.
        """
        tool_reg_compiled = [re.compile(p) for p in TOOL_REGISTRATION_PATTERNS]

        scored: list[tuple[str, str, int, bool]] = []
        for rel_path in files:
            fpath = os.path.join(clone_path, rel_path)
            try:
                with open(fpath, encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except OSError:
                continue

            match_count = sum(len(p.findall(content)) for p in tool_reg_compiled)
            if match_count == 0:
                continue
            fits = len(content) <= MAX_SAMPLE_CHARS
            scored.append((rel_path, content, match_count, fits))

        if not scored:
            return "", ""

        # Prefer files that fit entirely (True > False), then by match count
        scored.sort(key=lambda x: (x[3], x[2]), reverse=True)
        best_file, best_content, match_count, fits = scored[0]

        if not fits:
            best_content = best_content[:MAX_SAMPLE_CHARS]

        logger.info(
            "Selected sample file: %s (%d chars, %d pattern matches, fits=%s)",
            best_file, len(best_content), match_count, fits,
        )
        return best_file, best_content

    async def _generate_tool_regex(self, sample_content: str, sample_file: str) -> re.Pattern | None:
        """Generate a regex with named groups (name, description), validate on sample.

        Loops up to MAX_REGEX_ATTEMPTS times, refining if match count is off.
        """
        sample_header = f"=== {sample_file} ===\n{sample_content}"
        prompt = PATTERN_GENERATION_PROMPT.replace("{sample}", sample_header)

        best_pattern: re.Pattern | None = None
        best_match_count = 0

        for attempt in range(MAX_REGEX_ATTEMPTS):
            raw = await self._call_llm(prompt)
            parsed = self._parse_llm_response(raw)

            pattern_str = parsed.get("pattern", "")
            expected = parsed.get("expected_matches", 0)

            if not pattern_str:
                logger.warning("LLM returned empty pattern on attempt %d", attempt + 1)
                continue

            try:
                compiled = re.compile(pattern_str, re.DOTALL)
            except re.error as e:
                logger.warning("Invalid regex from LLM (attempt %d): %s — %s", attempt + 1, pattern_str[:100], e)
                prompt = PATTERN_REFINEMENT_PROMPT.format(
                    pattern=pattern_str, expected=expected, actual=0,
                    match_info=f"Regex compilation error: {e}",
                    sample=sample_header,
                )
                continue

            matches = list(compiled.finditer(sample_content))
            actual = len(matches)

            # Check that matches have the 'name' capture group
            has_name_group = actual > 0 and matches[0].groupdict().get("name")

            logger.info(
                "Regex attempt %d: pattern=%s, expected=%d, actual=%d, has_name=%s",
                attempt + 1, pattern_str[:80], expected, actual, bool(has_name_group),
            )

            # Track best result so far
            if has_name_group and actual > best_match_count:
                best_pattern = compiled
                best_match_count = actual

            # Accept if matches are reasonable
            if has_name_group and expected > 0 and actual >= expected * 0.7:
                logger.info("Regex validated: %d/%d matches on sample", actual, expected)
                return compiled

            # Build refinement prompt
            if actual > 0 and has_name_group:
                info_lines = []
                for m in matches[:3]:
                    g = m.groupdict()
                    info_lines.append(f"  name={g.get('name', 'N/A')}, desc={str(g.get('description', 'N/A'))[:60]}")
                match_info = "Matches found (first 3):\n" + "\n".join(info_lines)
            elif actual > 0:
                match_info = f"Found {actual} matches but 'name' capture group is missing or empty."
            else:
                match_info = "No matches found at all."

            prompt = PATTERN_REFINEMENT_PROMPT.format(
                pattern=pattern_str, expected=expected, actual=actual,
                match_info=match_info, sample=sample_header,
            )

        # Return best pattern even if not perfect
        if best_pattern is not None:
            logger.warning("Using best-effort regex (%d matches on sample)", best_match_count)
        return best_pattern

    @staticmethod
    def _extract_tools_with_regex(
        clone_path: str, files: list[str], pattern: re.Pattern,
    ) -> list[ToolDefinition]:
        """Apply validated regex to all files and build ToolDefinition list."""
        results: list[ToolDefinition] = []
        seen_names: set[str] = set()

        for rel_path in files:
            fpath = os.path.join(clone_path, rel_path)
            try:
                with open(fpath, encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except OSError:
                continue

            for match in pattern.finditer(content):
                groups = match.groupdict()
                name = (groups.get("name") or "").strip()
                if not name or name in seen_names:
                    continue

                seen_names.add(name)
                description = (groups.get("description") or "").strip()
                line_num = content[:match.start()].count("\n") + 1

                results.append(ToolDefinition(
                    server_name="source",
                    tool_name=name,
                    description=description,
                    input_schema={},
                    raw={"name": name, "description": description, "source_file": rel_path, "source_line": line_num},
                ))

            if results:
                file_count = len([m for m in pattern.finditer(content)])
                logger.debug("File %s: %d tool matches", rel_path, file_count)

        return results

    async def _call_llm(self, prompt: str) -> str:
        """Call OpenRouter LLM with a prompt and return the response text."""
        logger.info(
            "LLM request: model=%s, prompt_length=%d chars, first 200 chars: %s",
            self.model, len(prompt), prompt[:200].replace("\n", "\\n"),
        )
        timeout = httpx.Timeout(connect=30, read=300, write=30, pool=30)
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0,
                    "response_format": {"type": "json_object"},
                },
            )
            response.raise_for_status()
            data = response.json()

        content = data["choices"][0]["message"]["content"]
        usage = data.get("usage", {})
        logger.info(
            "LLM response: %d chars, tokens(prompt=%s, completion=%s), first 500 chars: %s",
            len(content),
            usage.get("prompt_tokens", "?"),
            usage.get("completion_tokens", "?"),
            content[:500].replace("\n", "\\n"),
        )
        return content

    def _parse_tools_response(self, raw: str, server_name: str) -> list[ToolDefinition]:
        """Parse LLM response into ToolDefinition objects."""
        parsed = self._parse_llm_response(raw)
        tools_list = parsed.get("tools", [])
        if not isinstance(tools_list, list):
            return []

        result: list[ToolDefinition] = []
        for t in tools_list:
            if not isinstance(t, dict) or "name" not in t:
                continue
            result.append(ToolDefinition(
                server_name=server_name,
                tool_name=t["name"],
                description=t.get("description", ""),
                input_schema=t.get("input_schema", {}),
                raw=t,
            ))
        return result

