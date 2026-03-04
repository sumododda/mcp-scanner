import json
import os
import re
import tempfile

import httpx
import pytest

from mcp_scanner.models.scan_context import ToolDefinition
from mcp_scanner.services.repo_analyzer import RepoAnalyzer


class TestDiscoverCandidateFiles:
    def test_finds_python_mcp_server(self):
        """Discovers Python files with MCP SDK imports and tool patterns."""
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "server.py"), "w") as f:
                f.write("from mcp.server.fastmcp import FastMCP\n")
                f.write("mcp = FastMCP('test')\n")
                f.write("@mcp.tool()\n")
                f.write("def my_tool(query: str):\n")
                f.write('    """Search."""\n')

            analyzer = RepoAnalyzer(api_key="test", model="test")
            candidates = analyzer._discover_candidate_files(tmp)
            assert "server.py" in candidates

    def test_finds_go_mcp_server(self):
        """Discovers Go files with MCP struct literals."""
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "tools.go"), "w") as f:
                f.write('package github\n\n')
                f.write('import "github.com/mark3labs/mcp-go/mcp"\n\n')
                f.write('func GetMe() {\n')
                f.write('    return mcp.Tool{Name: "get_me"}\n')
                f.write('}\n')

            analyzer = RepoAnalyzer(api_key="test", model="test")
            candidates = analyzer._discover_candidate_files(tmp)
            assert "tools.go" in candidates

    def test_finds_ts_mcp_server(self):
        """Discovers TypeScript files with MCP SDK imports."""
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "index.ts"), "w") as f:
                f.write('import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n')
                f.write('const server = new McpServer({name: "test"});\n')
                f.write('server.tool("search", {}, async () => {});\n')

            analyzer = RepoAnalyzer(api_key="test", model="test")
            candidates = analyzer._discover_candidate_files(tmp)
            assert "index.ts" in candidates

    def test_skips_test_files(self):
        """Test files are excluded from candidates."""
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "tools_test.go"), "w") as f:
                f.write('package github\nimport "github.com/mark3labs/mcp-go/mcp"\n')
                f.write('func TestTools() { mcp.Tool{Name: "test"} }\n')

            analyzer = RepoAnalyzer(api_key="test", model="test")
            candidates = analyzer._discover_candidate_files(tmp)
            assert candidates == []

    def test_skips_node_modules(self):
        """Files in node_modules are excluded."""
        with tempfile.TemporaryDirectory() as tmp:
            nm_dir = os.path.join(tmp, "node_modules", "pkg")
            os.makedirs(nm_dir)
            with open(os.path.join(nm_dir, "index.js"), "w") as f:
                f.write('server.tool("hidden")\n')

            analyzer = RepoAnalyzer(api_key="test", model="test")
            candidates = analyzer._discover_candidate_files(tmp)
            assert candidates == []

    def test_empty_dir_returns_empty(self):
        """Empty directory returns empty list."""
        with tempfile.TemporaryDirectory() as tmp:
            analyzer = RepoAnalyzer(api_key="test", model="test")
            candidates = analyzer._discover_candidate_files(tmp)
            assert candidates == []

    def test_ranks_by_signal_strength(self):
        """Files with more signals rank higher."""
        with tempfile.TemporaryDirectory() as tmp:
            # High signal: SDK import + tool pattern + name match
            with open(os.path.join(tmp, "tools.py"), "w") as f:
                f.write("from mcp.server.fastmcp import FastMCP\n")
                f.write("@mcp.tool()\ndef search(): pass\n")

            # Low signal: just a name match, no patterns
            with open(os.path.join(tmp, "utils.py"), "w") as f:
                f.write("def helper(): pass\n")

            analyzer = RepoAnalyzer(api_key="test", model="test")
            candidates = analyzer._discover_candidate_files(tmp)
            assert candidates[0] == "tools.py"


class TestBuildTree:
    def test_includes_source_files(self):
        """Tree includes source files with relevant extensions."""
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "main.go"), "w") as f:
                f.write("package main\n")
            with open(os.path.join(tmp, "README.md"), "w") as f:
                f.write("# Readme\n")
            os.makedirs(os.path.join(tmp, "pkg"))
            with open(os.path.join(tmp, "pkg", "tools.go"), "w") as f:
                f.write("package pkg\n")

            tree = RepoAnalyzer._build_tree(tmp)
            assert "main.go" in tree
            assert "pkg/tools.go" in tree
            assert "README.md" not in tree  # Not a source extension

    def test_skips_hidden_dirs(self):
        """Tree skips .git and similar hidden directories."""
        with tempfile.TemporaryDirectory() as tmp:
            git_dir = os.path.join(tmp, ".git", "objects")
            os.makedirs(git_dir)
            with open(os.path.join(git_dir, "pack.go"), "w") as f:
                f.write("package git\n")

            tree = RepoAnalyzer._build_tree(tmp)
            assert tree == ""


class TestIsTestFile:
    def test_python_test(self):
        assert RepoAnalyzer._is_test_file("test_tools.py")

    def test_go_test(self):
        assert RepoAnalyzer._is_test_file("tools_test.go")

    def test_ts_test(self):
        assert RepoAnalyzer._is_test_file("tools.test.ts")

    def test_ts_spec(self):
        assert RepoAnalyzer._is_test_file("tools.spec.ts")

    def test_normal_file(self):
        assert not RepoAnalyzer._is_test_file("tools.go")
        assert not RepoAnalyzer._is_test_file("server.py")
        assert not RepoAnalyzer._is_test_file("index.ts")


class TestPickBestSample:
    def test_prefers_file_that_fits(self):
        """Prefers a smaller file with good matches over a huge one."""
        with tempfile.TemporaryDirectory() as tmp:
            # Small file with tool patterns (fits in MAX_SAMPLE_CHARS)
            with open(os.path.join(tmp, "small.go"), "w") as f:
                f.write('import "github.com/mark3labs/mcp-go/mcp"\n')
                f.write('mcp.Tool{Name: "tool_a"}\n')
                f.write('mcp.Tool{Name: "tool_b"}\n')

            # Large file with more patterns (won't fit)
            with open(os.path.join(tmp, "large.go"), "w") as f:
                f.write('import "github.com/mark3labs/mcp-go/mcp"\n')
                for i in range(20):
                    f.write(f'mcp.Tool{{Name: "tool_{i}"}}\n')
                f.write("x" * 20_000)  # Push over MAX_SAMPLE_CHARS

            analyzer = RepoAnalyzer(api_key="test", model="test")
            sample_file, sample_content = analyzer._pick_best_sample(tmp, ["small.go", "large.go"])
            assert sample_file == "small.go"

    def test_empty_returns_empty(self):
        """No matching files returns empty."""
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "utils.py"), "w") as f:
                f.write("def helper(): pass\n")

            analyzer = RepoAnalyzer(api_key="test", model="test")
            sample_file, content = analyzer._pick_best_sample(tmp, ["utils.py"])
            assert sample_file == ""
            assert content == ""


class TestExtractToolsWithRegex:
    def test_extracts_go_tools(self):
        """Regex with named groups extracts tools from Go files."""
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "repos.go"), "w") as f:
                f.write('''func GetFileContents() {
    return mcp.Tool{
        Name: "get_file_contents",
        Description: "Get file contents from a repo",
    }
}
func SearchCode() {
    return mcp.Tool{
        Name: "search_code",
        Description: "Search for code",
    }
}
''')
            pattern = re.compile(
                r'Name:\s*"(?P<name>[^"]+)".*?Description:\s*"(?P<description>[^"]+)"',
                re.DOTALL,
            )
            tools = RepoAnalyzer._extract_tools_with_regex(tmp, ["repos.go"], pattern)
            assert len(tools) == 2
            names = {t.tool_name for t in tools}
            assert names == {"get_file_contents", "search_code"}
            assert tools[0].description == "Get file contents from a repo"

    def test_deduplicates_across_files(self):
        """Same tool name in multiple files is only counted once."""
        with tempfile.TemporaryDirectory() as tmp:
            for fname in ["a.go", "b.go"]:
                with open(os.path.join(tmp, fname), "w") as f:
                    f.write('Name: "dupe_tool", Description: "Same tool"')

            pattern = re.compile(
                r'Name:\s*"(?P<name>[^"]+)".*?Description:\s*"(?P<description>[^"]+)"',
                re.DOTALL,
            )
            tools = RepoAnalyzer._extract_tools_with_regex(tmp, ["a.go", "b.go"], pattern)
            assert len(tools) == 1

    def test_handles_large_files(self):
        """Works on files of any size without truncation."""
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "big.go"), "w") as f:
                for i in range(50):
                    f.write(f'mcp.Tool{{Name: "tool_{i}", Description: "Tool number {i}"}}\n')
                    f.write("x" * 1000 + "\n")  # Padding between tools

            pattern = re.compile(
                r'Name:\s*"(?P<name>[^"]+)".*?Description:\s*"(?P<description>[^"]+)"',
                re.DOTALL,
            )
            tools = RepoAnalyzer._extract_tools_with_regex(tmp, ["big.go"], pattern)
            assert len(tools) == 50


class TestParseToolsResponse:
    def test_valid_json(self):
        """Valid JSON with tools array produces ToolDefinition list."""
        raw = json.dumps({
            "tools": [
                {"name": "search", "description": "Search things", "input_schema": {"type": "object", "properties": {"q": {"type": "string"}}}},
                {"name": "create", "description": "Create item"},
            ]
        })
        analyzer = RepoAnalyzer(api_key="test", model="test")
        result = analyzer._parse_tools_response(raw, "my-server")
        assert len(result) == 2
        assert isinstance(result[0], ToolDefinition)
        assert result[0].server_name == "my-server"
        assert result[0].tool_name == "search"
        assert result[0].description == "Search things"
        assert result[0].input_schema["type"] == "object"
        assert result[1].tool_name == "create"
        assert result[1].input_schema == {}

    def test_markdown_fences(self):
        """JSON wrapped in markdown fences still parses."""
        raw = '```json\n{"tools": [{"name": "test_tool", "description": "A tool"}]}\n```'
        analyzer = RepoAnalyzer(api_key="test", model="test")
        result = analyzer._parse_tools_response(raw, "srv")
        assert len(result) == 1
        assert result[0].tool_name == "test_tool"

    def test_invalid_json_returns_empty(self):
        """Garbage text returns empty list."""
        analyzer = RepoAnalyzer(api_key="test", model="test")
        result = analyzer._parse_tools_response("not json at all", "srv")
        assert result == []

    def test_missing_name_skipped(self):
        """Tool entries without 'name' are skipped."""
        raw = json.dumps({"tools": [{"description": "no name"}, {"name": "valid", "description": "ok"}]})
        analyzer = RepoAnalyzer(api_key="test", model="test")
        result = analyzer._parse_tools_response(raw, "srv")
        assert len(result) == 1
        assert result[0].tool_name == "valid"

    def test_empty_tools_array(self):
        """Empty tools array returns empty list."""
        raw = json.dumps({"tools": []})
        analyzer = RepoAnalyzer(api_key="test", model="test")
        result = analyzer._parse_tools_response(raw, "srv")
        assert result == []


class TestExtractToolsFromSource:
    @pytest.mark.asyncio
    async def test_full_flow_regex(self, monkeypatch):
        """Discovery + regex gen + local extraction — no LLM extraction call."""
        call_count = {"llm": 0}

        # Phase 1: discovery returns file list
        # Phase 2: LLM returns regex pattern
        responses = [
            json.dumps({"files": ["server.py"]}),
            json.dumps({
                "pattern": r'@mcp\.tool\(\)\s*\ndef\s+(?P<name>\w+).*?"""(?P<description>[^"]*?)"""',
                "expected_matches": 1,
                "explanation": "Matches Python MCP tool decorators",
            }),
        ]

        async def mock_post(self, url, **kwargs):
            idx = call_count["llm"]
            call_count["llm"] += 1
            body = {"choices": [{"message": {"content": responses[idx]}}]}
            return httpx.Response(200, json=body, request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "server.py"), "w") as f:
                f.write('from mcp.server.fastmcp import FastMCP\n')
                f.write('@mcp.tool()\n')
                f.write('def search_reddit(query: str):\n')
                f.write('    """Search Reddit."""\n')

            analyzer = RepoAnalyzer(api_key="test-key", model="test-model")
            result = await analyzer.extract_tools_from_source(tmp)

        assert call_count["llm"] == 2  # Discovery + Pattern gen (no extraction LLM call!)
        assert len(result) == 1
        assert result[0].tool_name == "search_reddit"
        assert result[0].server_name == "source"
        assert result[0].description == "Search Reddit."
        assert isinstance(result[0], ToolDefinition)

    @pytest.mark.asyncio
    async def test_no_candidates_skips_llm(self, monkeypatch):
        """When no candidate files found, LLM is never called."""
        call_count = {"llm": 0}

        async def mock_post(self, url, **kwargs):
            call_count["llm"] += 1
            body = {"choices": [{"message": {"content": '{"tools": []}'}}]}
            return httpx.Response(200, json=body, request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

        with tempfile.TemporaryDirectory() as tmp:
            # No source files at all
            analyzer = RepoAnalyzer(api_key="test-key", model="test-model")
            result = await analyzer.extract_tools_from_source(tmp)

        assert result == []
        assert call_count["llm"] == 0

    @pytest.mark.asyncio
    async def test_regex_refinement_loop(self, monkeypatch):
        """If first regex is bad, LLM refines it on the next attempt."""
        call_count = {"llm": 0}

        responses = [
            json.dumps({"files": ["tools.go"]}),
            # First regex attempt: wrong pattern (no matches)
            json.dumps({
                "pattern": r'WRONG_PATTERN_(?P<name>\w+)',
                "expected_matches": 2,
                "explanation": "bad attempt",
            }),
            # Second attempt: correct pattern
            json.dumps({
                "pattern": r'Name:\s*"(?P<name>[^"]+)".*?Description:\s*"(?P<description>[^"]+)"',
                "expected_matches": 2,
                "explanation": "fixed",
            }),
        ]

        async def mock_post(self, url, **kwargs):
            idx = call_count["llm"]
            call_count["llm"] += 1
            body = {"choices": [{"message": {"content": responses[idx]}}]}
            return httpx.Response(200, json=body, request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "tools.go"), "w") as f:
                f.write('import "github.com/mark3labs/mcp-go/mcp"\n')
                f.write('mcp.Tool{Name: "tool_a", Description: "First tool"}\n')
                f.write('mcp.Tool{Name: "tool_b", Description: "Second tool"}\n')

            analyzer = RepoAnalyzer(api_key="test-key", model="test-model")
            result = await analyzer.extract_tools_from_source(tmp)

        assert call_count["llm"] == 3  # Discovery + bad regex + good regex
        assert len(result) == 2
        names = {t.tool_name for t in result}
        assert names == {"tool_a", "tool_b"}

    @pytest.mark.asyncio
    async def test_no_api_key_returns_empty(self):
        """Without API key, returns empty list without calling LLM."""
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "server.py"), "w") as f:
                f.write('from mcp import FastMCP\n@mcp.tool()\ndef my_tool(): pass\n')

            analyzer = RepoAnalyzer(api_key="", model="test-model")
            result = await analyzer.extract_tools_from_source(tmp)

        assert result == []

    @pytest.mark.asyncio
    async def test_llm_failure_returns_empty(self, monkeypatch):
        """If LLM call fails, returns empty list gracefully."""
        async def mock_post(self, url, **kwargs):
            raise httpx.HTTPStatusError("Server error", request=httpx.Request("POST", url), response=httpx.Response(500))

        monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "server.py"), "w") as f:
                f.write('from mcp import FastMCP\n@mcp.tool()\ndef my_tool(): pass\n')

            analyzer = RepoAnalyzer(api_key="test-key", model="test-model")
            result = await analyzer.extract_tools_from_source(tmp)

        assert result == []

    @pytest.mark.asyncio
    async def test_regex_works_on_large_files(self, monkeypatch):
        """Regex approach handles large files — sample is small but regex runs on full file."""
        call_count = {"llm": 0}

        # Sample is truncated to ~15K, so LLM only sees 1 tool in sample.
        # But the regex is applied to the FULL file, finding all 3.
        responses = [
            json.dumps({"files": ["big.go"]}),
            json.dumps({
                "pattern": r'Name:\s*"(?P<name>[^"]+)".*?Description:\s*"(?P<description>[^"]+)"',
                "expected_matches": 1,  # Only 1 visible in truncated sample
                "explanation": "Go tool struct pattern",
            }),
        ]

        async def mock_post(self, url, **kwargs):
            idx = call_count["llm"]
            call_count["llm"] += 1
            body = {"choices": [{"message": {"content": responses[idx]}}]}
            return httpx.Response(200, json=body, request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "big.go"), "w") as f:
                f.write('import "github.com/mark3labs/mcp-go/mcp"\n')
                # 3 tools spread across a large file (simulating 67K+ files)
                for i in range(3):
                    f.write(f'mcp.Tool{{Name: "tool_{i}", Description: "Tool {i} desc"}}\n')
                    f.write("x" * 20_000 + "\n")

            analyzer = RepoAnalyzer(api_key="test-key", model="test-model")
            result = await analyzer.extract_tools_from_source(tmp)

        assert len(result) == 3  # All 3 found despite file being >60K
        names = {t.tool_name for t in result}
        assert names == {"tool_0", "tool_1", "tool_2"}
