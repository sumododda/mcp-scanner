"""Tests for infra_security checker with code graph analysis."""

import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from mcp_scanner.checkers.base import SecurityQuestion, CheckerResult
from mcp_scanner.checkers.infra_security import InfraSecurityChecker, InfraLLMJudge
from mcp_scanner.models.scan_context import ScanContext
from mcp_scanner.services.code_graph import (
    CallSite, CodeGraph, FunctionNode, ImportNode,
)


def _ctx(code_graph: CodeGraph | None = None) -> ScanContext:
    return ScanContext(
        mcp_config={"mcpServers": {}},
        code_graph=code_graph,
    )


def _make_graph(
    functions=None, imports=None, call_sites=None, tool_handlers=None,
) -> CodeGraph:
    g = CodeGraph(
        functions=functions or [],
        imports=imports or [],
        call_sites=call_sites or [],
    )
    if tool_handlers:
        for f in g.functions:
            if f.name in tool_handlers:
                f.is_tool_handler = True
        g.tool_handlers = [f for f in g.functions if f.is_tool_handler]
    return g


class TestNoAuthDetection:
    @pytest.mark.asyncio
    async def test_no_auth_with_tool_handlers(self):
        graph = _make_graph(
            functions=[
                FunctionNode(name="read_file", file_path="server.py", line=10, end_line=20),
            ],
            imports=[
                ImportNode(module="os", names=["path"], file_path="server.py"),
            ],
            tool_handlers=["read_file"],
        )
        checker = InfraSecurityChecker()
        result = await checker.check(_ctx(graph))
        auth_findings = [f for f in result.findings if "authentication" in f.title.lower()]
        assert len(auth_findings) == 1

    @pytest.mark.asyncio
    async def test_auth_present_no_finding(self):
        graph = _make_graph(
            functions=[
                FunctionNode(name="read_file", file_path="server.py", line=10, end_line=20),
            ],
            imports=[
                ImportNode(module="jwt", names=["decode"], file_path="server.py"),
            ],
            tool_handlers=["read_file"],
        )
        checker = InfraSecurityChecker()
        result = await checker.check(_ctx(graph))
        auth_findings = [f for f in result.findings if "authentication" in f.title.lower()]
        assert len(auth_findings) == 0

    @pytest.mark.asyncio
    async def test_no_finding_without_tool_handlers(self):
        graph = _make_graph(
            functions=[
                FunctionNode(name="helper", file_path="utils.py", line=1, end_line=5),
            ],
            imports=[
                ImportNode(module="os", names=[], file_path="utils.py"),
            ],
        )
        checker = InfraSecurityChecker()
        result = await checker.check(_ctx(graph))
        auth_findings = [f for f in result.findings if "authentication" in f.title.lower()]
        assert len(auth_findings) == 0


class TestNoValidationDetection:
    @pytest.mark.asyncio
    async def test_no_validation_with_tool_handlers(self):
        graph = _make_graph(
            functions=[
                FunctionNode(name="query_db", file_path="server.py", line=10, end_line=20),
            ],
            imports=[
                ImportNode(module="os", names=[], file_path="server.py"),
            ],
            tool_handlers=["query_db"],
        )
        checker = InfraSecurityChecker()
        result = await checker.check(_ctx(graph))
        val_findings = [f for f in result.findings if "validation" in f.title.lower()]
        assert len(val_findings) == 1

    @pytest.mark.asyncio
    async def test_pydantic_present_no_finding(self):
        graph = _make_graph(
            functions=[
                FunctionNode(name="query_db", file_path="server.py", line=10, end_line=20),
            ],
            imports=[
                ImportNode(module="pydantic", names=["BaseModel"], file_path="server.py"),
            ],
            tool_handlers=["query_db"],
        )
        checker = InfraSecurityChecker()
        result = await checker.check(_ctx(graph))
        val_findings = [f for f in result.findings if "validation" in f.title.lower()]
        assert len(val_findings) == 0


class TestInsecureHttpInSource:
    @pytest.mark.asyncio
    async def test_http_url_detected(self):
        graph = _make_graph(
            functions=[
                FunctionNode(
                    name="fetch_data", file_path="server.py", line=5, end_line=10,
                    body_text='def fetch_data():\n    requests.get("http://api.example.com/data")',
                ),
            ],
        )
        checker = InfraSecurityChecker()
        result = await checker.check(_ctx(graph))
        http_findings = [f for f in result.findings if "Insecure HTTP URL" in f.title]
        assert len(http_findings) == 1

    @pytest.mark.asyncio
    async def test_localhost_http_not_flagged(self):
        graph = _make_graph(
            functions=[
                FunctionNode(
                    name="test_local", file_path="server.py", line=5, end_line=10,
                    body_text='def test_local():\n    requests.get("http://localhost:8080")',
                ),
            ],
        )
        checker = InfraSecurityChecker()
        result = await checker.check(_ctx(graph))
        http_findings = [f for f in result.findings if "Insecure HTTP URL" in f.title]
        assert len(http_findings) == 0


class TestDangerousOpsInHandler:
    @pytest.mark.asyncio
    async def test_subprocess_in_handler(self):
        graph = _make_graph(
            functions=[
                FunctionNode(name="run_cmd", file_path="server.py", line=10, end_line=20),
            ],
            call_sites=[
                CallSite(
                    callee="subprocess.run", file_path="server.py", line=12,
                    parent_function="run_cmd", arguments_text='(cmd, shell=True)',
                ),
            ],
            tool_handlers=["run_cmd"],
        )
        checker = InfraSecurityChecker()
        result = await checker.check(_ctx(graph))
        danger_findings = [f for f in result.findings if "Dangerous operation" in f.title]
        assert len(danger_findings) == 1

    @pytest.mark.asyncio
    async def test_no_finding_for_non_handler(self):
        graph = _make_graph(
            functions=[
                FunctionNode(name="helper", file_path="utils.py", line=10, end_line=20),
            ],
            call_sites=[
                CallSite(
                    callee="subprocess.run", file_path="utils.py", line=12,
                    parent_function="helper", arguments_text='(cmd)',
                ),
            ],
        )
        checker = InfraSecurityChecker()
        result = await checker.check(_ctx(graph))
        danger_findings = [f for f in result.findings if "Dangerous operation" in f.title]
        assert len(danger_findings) == 0


class TestNoCodeGraph:
    @pytest.mark.asyncio
    async def test_no_code_graph_still_works(self):
        """Checker should work fine without code graph (existing behavior)."""
        checker = InfraSecurityChecker()
        result = await checker.check(_ctx(None))
        assert result.checker_name == "infra_security"


class TestSecurityQuestionDataclass:
    def test_security_question_fields(self):
        sq = SecurityQuestion(
            id="auth_middleware",
            question="Does the server use authentication?",
            answer="No auth imports found",
            status="issue",
            items_checked=12,
            items_checked_label="imports",
            finding_ids=["f1"],
            severity="medium",
        )
        assert sq.id == "auth_middleware"
        assert sq.status == "issue"
        assert sq.finding_ids == ["f1"]

    def test_checker_result_has_security_questions(self):
        sq = SecurityQuestion(
            id="test", question="Q?", answer="A",
            status="clear", items_checked=0,
            items_checked_label="items", finding_ids=[],
        )
        result = CheckerResult(
            checker_name="infra_security",
            security_questions=[sq],
        )
        assert len(result.security_questions) == 1
        assert result.security_questions[0].id == "test"


class TestSecurityQuestionEmission:
    @pytest.mark.asyncio
    async def test_config_checks_emit_questions(self):
        config = {
            "mcpServers": {
                "safe": {
                    "command": "node", "args": ["server.js"],
                    "url": "https://secure.example.com",
                    "env": {"NODE_ENV": "production"},
                }
            }
        }
        checker = InfraSecurityChecker()
        result = await checker.check(ScanContext(mcp_config=config))
        question_ids = [sq.id for sq in result.security_questions]
        assert "http_transport" in question_ids
        assert "plaintext_secrets_config" in question_ids
        assert "elevated_privileges" in question_ids
        for sq in result.security_questions:
            if sq.id in ("http_transport", "plaintext_secrets_config", "elevated_privileges"):
                assert sq.status == "clear", f"{sq.id} should be clear"

    @pytest.mark.asyncio
    async def test_code_graph_checks_emit_questions(self):
        graph = _make_graph(
            functions=[FunctionNode(name="handler", file_path="server.py", line=10, end_line=20)],
            imports=[
                ImportNode(module="jwt", names=["decode"], file_path="server.py"),
                ImportNode(module="pydantic", names=["BaseModel"], file_path="server.py"),
            ],
            tool_handlers=["handler"],
        )
        checker = InfraSecurityChecker()
        result = await checker.check(_ctx(graph))
        question_ids = [sq.id for sq in result.security_questions]
        assert "auth_middleware" in question_ids
        assert "input_validation" in question_ids
        auth_q = next(sq for sq in result.security_questions if sq.id == "auth_middleware")
        assert auth_q.status == "clear"

    @pytest.mark.asyncio
    async def test_issue_question_has_severity(self):
        graph = _make_graph(
            functions=[FunctionNode(name="handler", file_path="server.py", line=10, end_line=20)],
            imports=[ImportNode(module="os", names=[], file_path="server.py")],
            tool_handlers=["handler"],
        )
        checker = InfraSecurityChecker()
        result = await checker.check(_ctx(graph))
        auth_q = next(sq for sq in result.security_questions if sq.id == "auth_middleware")
        assert auth_q.status == "issue"
        assert auth_q.severity == "medium"


class TestInsecureDeserialization:
    @pytest.mark.asyncio
    async def test_pickle_loads_in_handler(self):
        graph = _make_graph(
            functions=[FunctionNode(name="load_data", file_path="server.py", line=10, end_line=20)],
            call_sites=[CallSite(callee="pickle.loads", file_path="server.py", line=12, parent_function="load_data", arguments_text="(user_data)")],
            tool_handlers=["load_data"],
        )
        checker = InfraSecurityChecker()
        result = await checker.check(_ctx(graph))
        deser_findings = [f for f in result.findings if "deserialization" in f.title.lower()]
        assert len(deser_findings) == 1
        assert deser_findings[0].cwe_id == "CWE-502"

    @pytest.mark.asyncio
    async def test_yaml_safe_load_not_flagged(self):
        graph = _make_graph(
            functions=[FunctionNode(name="parse", file_path="server.py", line=10, end_line=20)],
            call_sites=[CallSite(callee="yaml.safe_load", file_path="server.py", line=12, parent_function="parse", arguments_text="(data)")],
            tool_handlers=["parse"],
        )
        checker = InfraSecurityChecker()
        result = await checker.check(_ctx(graph))
        assert not [f for f in result.findings if "deserialization" in f.title.lower()]


class TestWeakCrypto:
    @pytest.mark.asyncio
    async def test_md5_detected(self):
        graph = _make_graph(
            functions=[FunctionNode(name="hash_pw", file_path="server.py", line=5, end_line=10, body_text='def hash_pw(pw):\n    return hashlib.md5(pw.encode()).hexdigest()')],
            call_sites=[CallSite(callee="hashlib.md5", file_path="server.py", line=6, parent_function="hash_pw", arguments_text="(pw.encode())")],
        )
        checker = InfraSecurityChecker()
        result = await checker.check(_ctx(graph))
        assert len([f for f in result.findings if "weak" in f.title.lower() or "crypto" in f.title.lower()]) == 1

    @pytest.mark.asyncio
    async def test_sha256_not_flagged(self):
        graph = _make_graph(
            functions=[FunctionNode(name="h", file_path="server.py", line=5, end_line=10)],
            call_sites=[CallSite(callee="hashlib.sha256", file_path="server.py", line=6, parent_function="h", arguments_text="(data)")],
        )
        checker = InfraSecurityChecker()
        result = await checker.check(_ctx(graph))
        assert not [f for f in result.findings if "weak" in f.title.lower() or "crypto" in f.title.lower()]


class TestInsecureTLS:
    @pytest.mark.asyncio
    async def test_verify_false(self):
        graph = _make_graph(
            functions=[FunctionNode(name="fetch", file_path="server.py", line=5, end_line=10, body_text='def fetch():\n    requests.get("https://api.com", verify=False)')],
        )
        checker = InfraSecurityChecker()
        result = await checker.check(_ctx(graph))
        assert len([f for f in result.findings if "tls" in f.title.lower() or "certificate" in f.title.lower()]) == 1

    @pytest.mark.asyncio
    async def test_cert_none(self):
        graph = _make_graph(
            functions=[FunctionNode(name="conn", file_path="server.py", line=5, end_line=15, body_text='def conn():\n    ctx = ssl.create_default_context()\n    ctx.check_hostname = False\n    ctx.verify_mode = ssl.CERT_NONE')],
        )
        checker = InfraSecurityChecker()
        result = await checker.check(_ctx(graph))
        assert len([f for f in result.findings if "tls" in f.title.lower() or "certificate" in f.title.lower()]) >= 1


class TestHardcodedSecretsInSource:
    @pytest.mark.asyncio
    async def test_api_key_in_body(self):
        graph = _make_graph(
            functions=[FunctionNode(name="call_api", file_path="server.py", line=5, end_line=10, body_text='def call_api():\n    key = "sk-abcdefghijklmnopqrstuvwxyz1234567890"')],
        )
        checker = InfraSecurityChecker()
        result = await checker.check(_ctx(graph))
        assert len([f for f in result.findings if "secret" in f.title.lower() and "source" in f.title.lower()]) == 1

    @pytest.mark.asyncio
    async def test_test_file_not_flagged(self):
        graph = _make_graph(
            functions=[FunctionNode(name="test_api", file_path="tests/test_api.py", line=5, end_line=10, body_text='def test_api():\n    key = "sk-abcdefghijklmnopqrstuvwxyz1234567890"')],
        )
        checker = InfraSecurityChecker()
        result = await checker.check(_ctx(graph))
        assert not [f for f in result.findings if "secret" in f.title.lower() and "source" in f.title.lower()]


class TestMissingErrorHandling:
    @pytest.mark.asyncio
    async def test_handler_without_try_except(self):
        graph = _make_graph(
            functions=[FunctionNode(name="do_work", file_path="server.py", line=10, end_line=20, body_text='def do_work(args):\n    result = dangerous_call(args)\n    return result')],
            tool_handlers=["do_work"],
        )
        checker = InfraSecurityChecker()
        result = await checker.check(_ctx(graph))
        assert len([f for f in result.findings if "error handling" in f.title.lower()]) == 1

    @pytest.mark.asyncio
    async def test_handler_with_try_except(self):
        graph = _make_graph(
            functions=[FunctionNode(name="do_work", file_path="server.py", line=10, end_line=20, body_text='def do_work(args):\n    try:\n        result = dangerous_call(args)\n    except Exception as e:\n        return error(str(e))')],
            tool_handlers=["do_work"],
        )
        checker = InfraSecurityChecker()
        result = await checker.check(_ctx(graph))
        assert not [f for f in result.findings if "error handling" in f.title.lower()]


class TestFileAccessInHandler:
    @pytest.mark.asyncio
    async def test_open_with_handler_param(self):
        graph = _make_graph(
            functions=[FunctionNode(name="read_file", file_path="server.py", line=10, end_line=20, parameters=["file_path"])],
            call_sites=[CallSite(callee="open", file_path="server.py", line=12, parent_function="read_file", arguments_text="(file_path, 'r')")],
            tool_handlers=["read_file"],
        )
        checker = InfraSecurityChecker()
        result = await checker.check(_ctx(graph))
        assert len([f for f in result.findings if "file" in f.title.lower() and "path" in f.title.lower()]) == 1

    @pytest.mark.asyncio
    async def test_open_hardcoded_path_not_flagged(self):
        graph = _make_graph(
            functions=[FunctionNode(name="read_config", file_path="server.py", line=10, end_line=20, parameters=["options"])],
            call_sites=[CallSite(callee="open", file_path="server.py", line=12, parent_function="read_config", arguments_text='("/etc/config.json", "r")')],
            tool_handlers=["read_config"],
        )
        checker = InfraSecurityChecker()
        result = await checker.check(_ctx(graph))
        assert not [f for f in result.findings if "file" in f.title.lower() and "path" in f.title.lower()]


class TestMissingRateLimiting:
    @pytest.mark.asyncio
    async def test_no_rate_limit(self):
        graph = _make_graph(
            functions=[FunctionNode(name="handler", file_path="server.py", line=10, end_line=20)],
            imports=[ImportNode(module="os", names=[], file_path="server.py")],
            tool_handlers=["handler"],
        )
        checker = InfraSecurityChecker()
        result = await checker.check(_ctx(graph))
        assert len([f for f in result.findings if "rate limit" in f.title.lower()]) == 1

    @pytest.mark.asyncio
    async def test_slowapi_present(self):
        graph = _make_graph(
            functions=[FunctionNode(name="handler", file_path="server.py", line=10, end_line=20)],
            imports=[ImportNode(module="slowapi", names=["Limiter"], file_path="server.py")],
            tool_handlers=["handler"],
        )
        checker = InfraSecurityChecker()
        result = await checker.check(_ctx(graph))
        assert not [f for f in result.findings if "rate limit" in f.title.lower()]


class TestInfraLLMJudge:
    def test_class_exists_and_importable(self):
        """InfraLLMJudge should be importable from infra_security."""
        assert InfraLLMJudge is not None

    @pytest.mark.asyncio
    async def test_no_llm_analysis_when_disabled(self):
        """Without LLM judge enabled, findings should have no llm_analysis."""
        graph = _make_graph(
            functions=[
                FunctionNode(
                    name="run_cmd", file_path="server.py", line=10, end_line=20,
                    body_text='def run_cmd():\n    subprocess.run(["ls", "-la"])',
                ),
            ],
            call_sites=[
                CallSite(
                    callee="subprocess.run", file_path="server.py", line=12,
                    parent_function="run_cmd", arguments_text='(["ls", "-la"])',
                ),
            ],
            tool_handlers=["run_cmd"],
        )
        with patch("mcp_scanner.config.settings") as mock_settings:
            mock_settings.llm_judge_enabled = False
            checker = InfraSecurityChecker()
            result = await checker.check(_ctx(graph))
        danger_findings = [f for f in result.findings if "Dangerous operation" in f.title]
        assert len(danger_findings) == 1
        assert danger_findings[0].llm_analysis is None

    @pytest.mark.asyncio
    async def test_llm_judge_annotates_finding_when_enabled(self):
        """When LLM judge is enabled, ambiguous findings get llm_analysis set."""
        graph = _make_graph(
            functions=[
                FunctionNode(
                    name="run_cmd", file_path="server.py", line=10, end_line=20,
                    body_text='def run_cmd():\n    subprocess.run(["ls", "-la"])',
                ),
            ],
            call_sites=[
                CallSite(
                    callee="subprocess.run", file_path="server.py", line=12,
                    parent_function="run_cmd", arguments_text='(["ls", "-la"])',
                ),
            ],
            tool_handlers=["run_cmd"],
        )

        with patch("mcp_scanner.config.settings") as mock_settings, \
             patch("mcp_scanner.checkers.infra_security.InfraLLMJudge") as MockJudge:
            mock_settings.llm_judge_enabled = True
            mock_instance = MockJudge.return_value
            mock_instance.evaluate_finding = AsyncMock(return_value={
                "is_threat": False,
                "confidence": 0.8,
                "severity": "none",
                "reasoning": "Arguments are hardcoded constants",
                "evidence": '["ls", "-la"]',
            })
            mock_instance.enrich_questions = AsyncMock()
            checker = InfraSecurityChecker()
            result = await checker.check(_ctx(graph))

        danger_findings = [f for f in result.findings if "Dangerous operation" in f.title]
        assert len(danger_findings) == 1
        assert danger_findings[0].llm_analysis is not None
        assert "hardcoded constants" in danger_findings[0].llm_analysis

    @pytest.mark.asyncio
    async def test_llm_judge_confirmed_threat(self):
        """When LLM judge confirms a threat, llm_analysis starts with 'LLM confirmed'."""
        graph = _make_graph(
            functions=[
                FunctionNode(
                    name="run_cmd", file_path="server.py", line=10, end_line=20,
                    body_text='def run_cmd(cmd):\n    subprocess.run(cmd, shell=True)',
                    parameters=["cmd"],
                ),
            ],
            call_sites=[
                CallSite(
                    callee="subprocess.run", file_path="server.py", line=12,
                    parent_function="run_cmd", arguments_text='(cmd, shell=True)',
                ),
            ],
            tool_handlers=["run_cmd"],
        )

        with patch("mcp_scanner.config.settings") as mock_settings, \
             patch("mcp_scanner.checkers.infra_security.InfraLLMJudge") as MockJudge:
            mock_settings.llm_judge_enabled = True
            mock_instance = MockJudge.return_value
            mock_instance.evaluate_finding = AsyncMock(return_value={
                "is_threat": True,
                "confidence": 0.9,
                "severity": "high",
                "reasoning": "User input passed directly to shell command",
                "evidence": "subprocess.run(cmd, shell=True)",
            })
            mock_instance.enrich_questions = AsyncMock()
            checker = InfraSecurityChecker()
            result = await checker.check(_ctx(graph))

        danger_findings = [f for f in result.findings if "Dangerous operation" in f.title]
        assert len(danger_findings) == 1
        assert danger_findings[0].llm_analysis is not None
        assert danger_findings[0].llm_analysis.startswith("LLM confirmed:")
