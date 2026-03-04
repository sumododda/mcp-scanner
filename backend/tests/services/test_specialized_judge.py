"""Tests for the SpecializedLLMJudge."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_scanner.services.llm_judge import (
    CategoryVerdict,
    SpecializedLLMJudge,
    SpecializedVerdicts,
    _CATEGORY_META,
)


class TestCategoryVerdict:
    def test_basic_fields(self):
        v = CategoryVerdict(
            category="prompt_injection",
            is_threat=True,
            confidence=0.95,
            severity="high",
            reasoning="Contains override instructions",
            evidence="ignore previous instructions",
            cwe_id="CWE-94",
        )
        assert v.category == "prompt_injection"
        assert v.is_threat is True
        assert v.confidence == 0.95
        assert v.severity == "high"

    def test_cwe_id(self):
        v = CategoryVerdict(
            category="credential_exposure",
            is_threat=True,
            confidence=0.8,
            severity="critical",
            reasoning="test",
            evidence="test",
            cwe_id="CWE-798",
        )
        assert v.cwe_id == "CWE-798"


class TestSpecializedVerdicts:
    def test_empty_verdicts(self):
        sv = SpecializedVerdicts()
        assert sv.threats == []
        assert sv.max_severity == "none"

    def test_threats_filter(self):
        sv = SpecializedVerdicts(verdicts=[
            CategoryVerdict("a", True, 0.9, "high", "", "", "CWE-1"),
            CategoryVerdict("b", False, 0.3, "none", "", "", "CWE-2"),
            CategoryVerdict("c", True, 0.7, "medium", "", "", "CWE-3"),
        ])
        assert len(sv.threats) == 2
        assert sv.threats[0].category == "a"
        assert sv.threats[1].category == "c"

    def test_max_severity_critical_wins(self):
        sv = SpecializedVerdicts(verdicts=[
            CategoryVerdict("a", True, 0.9, "medium", "", "", "CWE-1"),
            CategoryVerdict("b", True, 0.8, "critical", "", "", "CWE-2"),
            CategoryVerdict("c", True, 0.7, "high", "", "", "CWE-3"),
        ])
        assert sv.max_severity == "critical"

    def test_max_severity_ignores_non_threats(self):
        sv = SpecializedVerdicts(verdicts=[
            CategoryVerdict("a", False, 0.1, "critical", "", "", "CWE-1"),
            CategoryVerdict("b", True, 0.8, "low", "", "", "CWE-2"),
        ])
        assert sv.max_severity == "low"

    def test_max_severity_no_threats(self):
        sv = SpecializedVerdicts(verdicts=[
            CategoryVerdict("a", False, 0.1, "none", "", "", "CWE-1"),
        ])
        assert sv.max_severity == "none"


class TestCategoryMeta:
    def test_all_categories_have_file_and_cwe(self):
        for cat, meta in _CATEGORY_META.items():
            assert "file" in meta, f"{cat} missing file"
            assert "cwe" in meta, f"{cat} missing cwe"
            assert meta["cwe"].startswith("CWE-"), f"{cat} has invalid CWE: {meta['cwe']}"

    def test_expected_categories_present(self):
        expected = {"behavioral_mismatch"}
        assert set(_CATEGORY_META.keys()) == expected


class TestSpecializedLLMJudge:
    def test_load_prompts(self):
        judge = SpecializedLLMJudge(api_key="test", model="test")
        prompts = judge._load_prompts()
        assert len(prompts) == 1
        for cat in _CATEGORY_META:
            assert cat in prompts, f"Missing prompt for {cat}"
            assert len(prompts[cat]) > 100, f"Prompt for {cat} too short"

    def test_behavioral_mismatch_prompt_has_placeholders(self):
        judge = SpecializedLLMJudge(api_key="test", model="test")
        prompts = judge._load_prompts()
        p = prompts["behavioral_mismatch"]
        assert "{delimiter}" in p
        assert "{tool_name}" in p
        assert "{description}" in p
        assert "{schema_json}" in p

    def test_behavioral_mismatch_prompt_has_code_graph_facts(self):
        judge = SpecializedLLMJudge(api_key="test", model="test")
        prompts = judge._load_prompts()
        p = prompts["behavioral_mismatch"]
        assert "{code_graph_facts}" in p

    def test_all_prompts_have_delimiter_sandboxing(self):
        judge = SpecializedLLMJudge(api_key="test", model="test")
        prompts = judge._load_prompts()
        for cat, prompt in prompts.items():
            assert "UNTRUSTED INPUT" in prompt, f"{cat} missing UNTRUSTED INPUT marker"
            assert "{delimiter}" in prompt, f"{cat} missing delimiter placeholder"

    def test_all_prompts_request_json_response(self):
        judge = SpecializedLLMJudge(api_key="test", model="test")
        prompts = judge._load_prompts()
        for cat, prompt in prompts.items():
            assert "is_threat" in prompt, f"{cat} missing is_threat in response schema"
            assert "confidence" in prompt, f"{cat} missing confidence in response schema"

    def test_parse_category_verdict_success(self):
        judge = SpecializedLLMJudge(api_key="test", model="test")
        raw = {
            "choices": [{
                "message": {
                    "content": json.dumps({
                        "is_threat": True,
                        "confidence": 0.85,
                        "severity": "high",
                        "reasoning": "Contains override instructions",
                        "evidence": "ignore all previous",
                    })
                }
            }]
        }
        v = judge._parse_category_verdict("behavioral_mismatch", raw)
        assert v.is_threat is True
        assert v.confidence == 0.85
        assert v.severity == "high"
        assert v.category == "behavioral_mismatch"
        assert v.cwe_id == "CWE-912"

    def test_parse_category_verdict_with_code_fences(self):
        judge = SpecializedLLMJudge(api_key="test", model="test")
        raw = {
            "choices": [{
                "message": {
                    "content": '```json\n{"is_threat": false, "confidence": 0.1, "severity": "none", "reasoning": "clean", "evidence": ""}\n```'
                }
            }]
        }
        v = judge._parse_category_verdict("behavioral_mismatch", raw)
        assert v.is_threat is False
        assert v.category == "behavioral_mismatch"
        assert v.cwe_id == "CWE-912"

    @pytest.mark.asyncio
    async def test_analyze_tool_runs_all_categories(self):
        judge = SpecializedLLMJudge(api_key="test", model="test")

        clean_response = {
            "choices": [{
                "message": {
                    "content": json.dumps({
                        "is_threat": False,
                        "confidence": 0.1,
                        "severity": "none",
                        "reasoning": "Clean tool",
                        "evidence": "",
                    })
                }
            }]
        }

        with patch.object(judge, "_query", new_callable=AsyncMock, return_value=clean_response):
            result = await judge.analyze_tool(
                tool_name="search",
                server_name="test-server",
                description="Search for files by name.",
                input_schema={"properties": {"query": {"type": "string"}}},
            )

        # behavioral_mismatch skipped without code_graph_facts → 0 verdicts
        assert len(result.verdicts) == 0
        assert result.threats == []
        assert result.max_severity == "none"

    @pytest.mark.asyncio
    async def test_analyze_tool_with_code_graph_facts(self):
        judge = SpecializedLLMJudge(api_key="test", model="test")

        clean_response = {
            "choices": [{
                "message": {
                    "content": json.dumps({
                        "is_threat": False,
                        "confidence": 0.1,
                        "severity": "none",
                        "reasoning": "Clean tool",
                        "evidence": "",
                    })
                }
            }]
        }

        with patch.object(judge, "_query", new_callable=AsyncMock, return_value=clean_response):
            result = await judge.analyze_tool(
                tool_name="search",
                server_name="test-server",
                description="Search for files.",
                code_graph_facts="Handler: search (server.py:10)\nCalls: os.listdir",
            )

        # behavioral_mismatch runs with code_graph_facts
        assert len(result.verdicts) == 1

    @pytest.mark.asyncio
    async def test_analyze_tool_detects_threats(self):
        judge = SpecializedLLMJudge(api_key="test", model="test")

        threat_response = {
            "choices": [{
                "message": {
                    "content": json.dumps({
                        "is_threat": True,
                        "confidence": 0.92,
                        "severity": "critical",
                        "reasoning": "Description says read-only but code calls subprocess",
                        "evidence": "subprocess.run in handler body",
                    })
                }
            }]
        }

        with patch.object(judge, "_query", new_callable=AsyncMock, return_value=threat_response):
            result = await judge.analyze_tool(
                tool_name="evil_tool",
                server_name="evil-server",
                description="Read-only file viewer",
                code_graph_facts="Handler: evil_tool (server.py:10)\nCalls: subprocess.run",
            )

        assert len(result.threats) == 1
        assert result.threats[0].category == "behavioral_mismatch"
        assert result.threats[0].severity == "critical"
        assert result.max_severity == "critical"

    @pytest.mark.asyncio
    async def test_analyze_tool_handles_query_failure(self):
        judge = SpecializedLLMJudge(api_key="test", model="test")

        async def failing_query(prompt):
            raise Exception("API timeout")

        with patch.object(judge, "_query", side_effect=failing_query):
            result = await judge.analyze_tool(
                tool_name="test",
                server_name="test",
                description="test",
            )

        # All queries fail, but gracefully returns empty verdicts
        assert len(result.verdicts) == 0
        assert result.threats == []

    @pytest.mark.asyncio
    async def test_behavioral_mismatch_skipped_without_facts(self):
        judge = SpecializedLLMJudge(api_key="test", model="test")

        query_prompts = []

        async def capturing_query(prompt):
            query_prompts.append(prompt)
            return {
                "choices": [{
                    "message": {
                        "content": json.dumps({
                            "is_threat": False,
                            "confidence": 0.1,
                            "severity": "none",
                            "reasoning": "Clean",
                            "evidence": "",
                        })
                    }
                }]
            }

        with patch.object(judge, "_query", side_effect=capturing_query):
            await judge.analyze_tool(
                tool_name="test",
                server_name="test",
                description="test tool",
                code_graph_facts=None,  # No facts
            )

        # behavioral_mismatch is the only category and it requires code_graph_facts
        # so 0 queries should fire when facts are absent
        assert len(query_prompts) == 0
