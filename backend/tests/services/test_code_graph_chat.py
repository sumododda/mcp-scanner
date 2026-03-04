"""Tests for code_graph_chat service."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_scanner.services.code_graph_chat import (
    _build_system_prompt,
    stream_code_graph_chat,
)


@pytest.fixture
def sample_code_graph():
    return {
        "stats": {
            "total_functions": 10,
            "total_imports": 25,
            "total_call_sites": 50,
            "tool_handlers": 3,
            "dangerous_calls": 2,
            "network_calls": 4,
            "file_access_calls": 1,
        },
        "tool_handlers": ["handle_query", "handle_execute", "handle_read"],
        "functions": [
            {
                "name": "handle_query",
                "file": "server.py",
                "line": 10,
                "params": ["query", "limit"],
                "is_tool_handler": True,
                "docstring": "Execute a database query.",
                "body_text": "...",
            },
            {
                "name": "handle_execute",
                "file": "server.py",
                "line": 30,
                "params": ["command"],
                "is_tool_handler": True,
                "docstring": "Execute a shell command.",
                "body_text": "...",
            },
            {
                "name": "handle_read",
                "file": "server.py",
                "line": 50,
                "params": ["path"],
                "is_tool_handler": True,
                "docstring": None,
                "body_text": "...",
            },
            {
                "name": "helper",
                "file": "utils.py",
                "line": 1,
                "params": [],
                "is_tool_handler": False,
                "docstring": "A helper.",
                "body_text": "...",
            },
        ],
        "imports": [
            {"module": "subprocess", "names": ["run"], "file": "server.py"},
            {"module": "requests", "names": ["get", "post"], "file": "server.py"},
            {"module": "os", "names": ["path"], "file": "utils.py"},
        ],
        "call_sites": [
            {
                "callee": "subprocess.run",
                "file": "server.py",
                "line": 35,
                "parent": "handle_execute",
                "args": "command, shell=True",
            },
            {
                "callee": "requests.get",
                "file": "server.py",
                "line": 15,
                "parent": "handle_query",
                "args": "url",
            },
            {
                "callee": "eval",
                "file": "server.py",
                "line": 40,
                "parent": "handle_execute",
                "args": "expression",
            },
            {
                "callee": "requests.post",
                "file": "server.py",
                "line": 20,
                "parent": "handle_query",
                "args": "url, data=result",
            },
        ],
    }


class TestBuildSystemPrompt:
    def test_includes_stats(self, sample_code_graph):
        prompt = _build_system_prompt(sample_code_graph)
        assert "Total functions: 10" in prompt
        assert "Total imports: 25" in prompt
        assert "Total call sites: 50" in prompt
        assert "Tool handlers: 3" in prompt
        assert "Dangerous calls: 2" in prompt
        assert "Network calls: 4" in prompt

    def test_includes_tool_handler_details(self, sample_code_graph):
        prompt = _build_system_prompt(sample_code_graph)
        assert "handle_query" in prompt
        assert "handle_execute" in prompt
        assert "handle_read" in prompt
        assert "server.py" in prompt

    def test_includes_handler_parameters(self, sample_code_graph):
        prompt = _build_system_prompt(sample_code_graph)
        assert "query, limit" in prompt
        assert "command" in prompt

    def test_includes_imports(self, sample_code_graph):
        prompt = _build_system_prompt(sample_code_graph)
        assert "subprocess" in prompt
        assert "requests" in prompt

    def test_includes_dangerous_calls(self, sample_code_graph):
        prompt = _build_system_prompt(sample_code_graph)
        assert "subprocess.run" in prompt
        assert "eval" in prompt

    def test_includes_network_calls(self, sample_code_graph):
        prompt = _build_system_prompt(sample_code_graph)
        assert "requests.get" in prompt
        assert "requests.post" in prompt

    def test_includes_security_delimiters(self, sample_code_graph):
        prompt = _build_system_prompt(sample_code_graph)
        assert "GRAPH_START_" in prompt
        assert "GRAPH_END_" in prompt

    def test_delimiter_is_random(self, sample_code_graph):
        prompt1 = _build_system_prompt(sample_code_graph)
        prompt2 = _build_system_prompt(sample_code_graph)
        # Extract delimiter from GRAPH_START_<hex>
        import re
        delims = re.findall(r"GRAPH_START_([a-f0-9]+)", prompt1 + prompt2)
        assert len(delims) == 2
        assert delims[0] != delims[1]

    def test_empty_code_graph(self):
        prompt = _build_system_prompt({"stats": {}, "tool_handlers": [], "functions": [], "imports": [], "call_sites": []})
        assert "Total functions: 0" in prompt
        assert "No tool handlers detected" in prompt
        assert "None detected" in prompt

    def test_handler_docstring_none_shows_none(self, sample_code_graph):
        prompt = _build_system_prompt(sample_code_graph)
        # handle_read has docstring=None
        assert "none" in prompt.lower()

    def test_system_role_description(self, sample_code_graph):
        prompt = _build_system_prompt(sample_code_graph)
        assert "security-focused code analyst" in prompt
        assert "MCP" in prompt


class TestStreamCodeGraphChat:
    @pytest.mark.asyncio
    async def test_streams_tokens(self, sample_code_graph):
        mock_line_iter = AsyncMock()

        async def mock_aiter_lines():
            yield 'data: {"choices":[{"delta":{"content":"Hello"}}]}'
            yield 'data: {"choices":[{"delta":{"content":" world"}}]}'
            yield "data: [DONE]"

        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.aiter_lines = mock_aiter_lines

        mock_client_ctx = AsyncMock()
        mock_client_ctx.__aenter__ = AsyncMock(return_value=mock_response)
        mock_client_ctx.__aexit__ = AsyncMock(return_value=False)

        mock_client = AsyncMock()
        mock_client.stream = MagicMock(return_value=mock_client_ctx)

        mock_client_outer = AsyncMock()
        mock_client_outer.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_outer.__aexit__ = AsyncMock(return_value=False)

        with patch("mcp_scanner.services.code_graph_chat.httpx.AsyncClient", return_value=mock_client_outer):
            with patch("mcp_scanner.services.code_graph_chat.settings") as mock_settings:
                mock_settings.openrouter_api_key = "test-key"
                mock_settings.openrouter_model = "test-model"

                chunks = []
                async for chunk in stream_code_graph_chat(sample_code_graph, "What does this code do?", []):
                    chunks.append(chunk)

        # Should have token chunks + DONE
        token_chunks = [c for c in chunks if '"token"' in c]
        assert len(token_chunks) == 2
        assert '"Hello"' in token_chunks[0]
        assert '" world"' in token_chunks[1]
        assert chunks[-1] == "data: [DONE]\n\n"

    @pytest.mark.asyncio
    async def test_handles_api_error(self, sample_code_graph):
        mock_response = AsyncMock()
        mock_response.status_code = 500
        mock_response.aread = AsyncMock(return_value=b"Internal Server Error")

        mock_client_ctx = AsyncMock()
        mock_client_ctx.__aenter__ = AsyncMock(return_value=mock_response)
        mock_client_ctx.__aexit__ = AsyncMock(return_value=False)

        mock_client = AsyncMock()
        mock_client.stream = MagicMock(return_value=mock_client_ctx)

        mock_client_outer = AsyncMock()
        mock_client_outer.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_outer.__aexit__ = AsyncMock(return_value=False)

        with patch("mcp_scanner.services.code_graph_chat.httpx.AsyncClient", return_value=mock_client_outer):
            with patch("mcp_scanner.services.code_graph_chat.settings") as mock_settings:
                mock_settings.openrouter_api_key = "test-key"
                mock_settings.openrouter_model = "test-model"

                chunks = []
                async for chunk in stream_code_graph_chat(sample_code_graph, "test", []):
                    chunks.append(chunk)

        error_chunks = [c for c in chunks if "error" in c]
        assert len(error_chunks) > 0
        assert "500" in error_chunks[0]

    @pytest.mark.asyncio
    async def test_includes_history(self, sample_code_graph):
        mock_response = AsyncMock()
        mock_response.status_code = 200

        async def mock_aiter_lines():
            yield "data: [DONE]"

        mock_response.aiter_lines = mock_aiter_lines

        mock_client_ctx = AsyncMock()
        mock_client_ctx.__aenter__ = AsyncMock(return_value=mock_response)
        mock_client_ctx.__aexit__ = AsyncMock(return_value=False)

        mock_client = AsyncMock()
        mock_client.stream = MagicMock(return_value=mock_client_ctx)

        mock_client_outer = AsyncMock()
        mock_client_outer.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client_outer.__aexit__ = AsyncMock(return_value=False)

        with patch("mcp_scanner.services.code_graph_chat.httpx.AsyncClient", return_value=mock_client_outer):
            with patch("mcp_scanner.services.code_graph_chat.settings") as mock_settings:
                mock_settings.openrouter_api_key = "test-key"
                mock_settings.openrouter_model = "test-model"

                history = [
                    {"role": "user", "content": "What is this?"},
                    {"role": "assistant", "content": "It's an MCP server."},
                ]
                async for _ in stream_code_graph_chat(sample_code_graph, "Tell me more", history):
                    pass

        # Check the messages passed to the API
        call_args = mock_client.stream.call_args
        request_json = call_args.kwargs.get("json") or call_args[1].get("json")
        messages = request_json["messages"]
        # system + 2 history + 1 user = 4 messages
        assert len(messages) == 4
        assert messages[0]["role"] == "system"
        assert messages[1]["content"] == "What is this?"
        assert messages[2]["content"] == "It's an MCP server."
        assert messages[3]["content"] == "Tell me more"
