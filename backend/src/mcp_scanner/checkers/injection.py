"""Injection Checker — detects command/SQL injection surfaces in tool definitions and source code."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from mcp_scanner.checkers.base import BaseChecker, CheckerResult, FindingData, Severity, is_test_path
from mcp_scanner.models.scan_context import ScanContext

if TYPE_CHECKING:
    from mcp_scanner.services.code_graph import CodeGraph

# Dangerous parameter names (command injection)
_DANGEROUS_PARAMS = {
    "command", "cmd", "shell", "exec", "script",
    "code", "expression", "eval",
}

# SQL parameter names
_SQL_PARAMS = {
    "query", "sql", "statement", "where_clause",
}

# Description patterns for command execution
_CMD_DESC_RE = re.compile(
    r"\b(execute|run|eval|shell|subprocess)\b",
    re.IGNORECASE,
)

# Description patterns for SQL
_SQL_DESC_RE = re.compile(
    r"\b(sql|query|select|insert|update|delete)\b",
    re.IGNORECASE,
)


class InjectionChecker(BaseChecker):
    name = "injection"
    description = "Detects command and SQL injection surfaces in tool definitions"

    async def check(self, context: ScanContext) -> CheckerResult:
        findings: list[FindingData] = []

        for server_name, tools in context.tool_definitions.items():
            for tool in tools:
                loc = f"{server_name}/{tool.tool_name}"
                props = (tool.input_schema or {}).get("properties", {})

                for param_name, param_def in props.items():
                    lower_name = param_name.lower()
                    param_desc = param_def.get("description", "")

                    # Command injection params
                    if lower_name in _DANGEROUS_PARAMS:
                        findings.append(
                            FindingData(
                                checker="injection",
                                severity=Severity.HIGH,
                                title="Command injection surface",
                                description=(
                                    f"Parameter '{param_name}' in tool "
                                    f"'{tool.tool_name}' has a name associated "
                                    "with command execution. If user input flows "
                                    "into this parameter without sanitization, "
                                    "it may allow command injection."
                                ),
                                evidence=f"param: {param_name}",
                                location=f"{loc}:param:{param_name}",
                                remediation=(
                                    "Validate and sanitize all inputs. Use "
                                    "allowlists rather than blocklists."
                                ),
                                cwe_id="CWE-78",
                            )
                        )

                    # SQL injection params
                    if lower_name in _SQL_PARAMS:
                        findings.append(
                            FindingData(
                                checker="injection",
                                severity=Severity.HIGH,
                                title="SQL injection surface",
                                description=(
                                    f"Parameter '{param_name}' in tool "
                                    f"'{tool.tool_name}' has a name associated "
                                    "with SQL queries. If user input flows "
                                    "into this parameter without parameterized "
                                    "queries, it may allow SQL injection."
                                ),
                                evidence=f"param: {param_name}",
                                location=f"{loc}:param:{param_name}",
                                remediation=(
                                    "Use parameterized queries / prepared "
                                    "statements instead of string concatenation."
                                ),
                                cwe_id="CWE-89",
                            )
                        )

                    # Command execution patterns in param description
                    if param_desc and _CMD_DESC_RE.search(param_desc):
                        findings.append(
                            FindingData(
                                checker="injection",
                                severity=Severity.MEDIUM,
                                title="Parameter description suggests command execution",
                                description=(
                                    f"Parameter '{param_name}' in tool "
                                    f"'{tool.tool_name}' has a description that "
                                    "mentions command execution terms."
                                ),
                                evidence=param_desc[:200],
                                location=f"{loc}:param:{param_name}",
                                remediation=(
                                    "Review whether this parameter allows "
                                    "arbitrary command execution."
                                ),
                                cwe_id="CWE-78",
                            )
                        )

                    # SQL patterns in param description
                    if param_desc and _SQL_DESC_RE.search(param_desc):
                        findings.append(
                            FindingData(
                                checker="injection",
                                severity=Severity.MEDIUM,
                                title="Parameter description suggests SQL execution",
                                description=(
                                    f"Parameter '{param_name}' in tool "
                                    f"'{tool.tool_name}' has a description that "
                                    "mentions SQL-related terms."
                                ),
                                evidence=param_desc[:200],
                                location=f"{loc}:param:{param_name}",
                                remediation=(
                                    "Ensure parameterized queries are used. "
                                    "Do not concatenate user input into SQL."
                                ),
                                cwe_id="CWE-89",
                            )
                        )

        # Code graph analysis (when available)
        if context.code_graph is not None:
            self._check_code_graph(context.code_graph, findings)

        return CheckerResult(findings=findings, checker_name=self.name)

    def _check_code_graph(self, graph: CodeGraph, findings: list[FindingData]) -> None:
        """Run injection checks using the code graph."""

        _SUBPROCESS_CALLEES = {
            "subprocess.run", "subprocess.call", "subprocess.Popen",
            "subprocess.check_output", "subprocess.check_call",
            "os.system", "os.popen",
            "child_process.exec", "child_process.execSync",
            "child_process.spawn",
        }
        _EVAL_CALLEES = {"eval", "exec"}
        _SQL_CONCAT_RE = re.compile(
            r'(?:f"[^"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)'
            r"|\.format\([^)]*\).*(?:SELECT|INSERT|UPDATE|DELETE)"
            r'|"[^"]*(?:SELECT|INSERT|UPDATE|DELETE)[^"]*"\s*\+)',
            re.IGNORECASE,
        )

        for handler in graph.tool_handlers:
            if is_test_path(handler.file_path):
                continue
            handler_calls = [
                c for c in graph.call_sites
                if c.parent_function == handler.name and c.file_path == handler.file_path
            ]

            # Check 1: Unsanitized subprocess call from tool handler
            subprocess_calls = [c for c in handler_calls if c.callee in _SUBPROCESS_CALLEES]
            for call in subprocess_calls:
                # Check if shlex.quote is used in the same function
                has_shlex = any(
                    c.callee in ("shlex.quote", "shlex.split")
                    for c in handler_calls
                )
                if not has_shlex:
                    findings.append(
                        FindingData(
                            checker="injection",
                            severity=Severity.HIGH,
                            title="Unsanitized subprocess in tool handler",
                            description=(
                                f"Tool handler '{handler.name}' in {handler.file_path} "
                                f"calls '{call.callee}' without using shlex.quote for "
                                "input sanitization."
                            ),
                            evidence=f"{call.callee}({call.arguments_text[:100]})",
                            location=f"source:{call.file_path}:{call.line}",
                            remediation="Use shlex.quote() to sanitize inputs before passing to subprocess.",
                            cwe_id="CWE-78",
                        )
                    )

            # Check 2: eval/exec with tool input
            eval_calls = [c for c in handler_calls if c.callee in _EVAL_CALLEES]
            for call in eval_calls:
                findings.append(
                    FindingData(
                        checker="injection",
                        severity=Severity.CRITICAL,
                        title="eval/exec in tool handler",
                        description=(
                            f"Tool handler '{handler.name}' in {handler.file_path} "
                            f"uses '{call.callee}()' which can execute arbitrary code "
                            "from tool input."
                        ),
                        evidence=f"{call.callee}({call.arguments_text[:100]})",
                        location=f"source:{call.file_path}:{call.line}",
                        remediation="Remove eval/exec from tool handlers. Use safe alternatives.",
                        cwe_id="CWE-95",
                    )
                )

            # Check 3: SQL string concatenation in tool handler
            if _SQL_CONCAT_RE.search(handler.body_text):
                findings.append(
                    FindingData(
                        checker="injection",
                        severity=Severity.HIGH,
                        title="SQL string concatenation in tool handler",
                        description=(
                            f"Tool handler '{handler.name}' in {handler.file_path} "
                            "appears to build SQL queries using string concatenation "
                            "or f-strings instead of parameterized queries."
                        ),
                        evidence="SQL string concatenation detected in handler body",
                        location=f"source:{handler.file_path}:{handler.line}",
                        remediation="Use parameterized queries instead of string concatenation.",
                        cwe_id="CWE-89",
                    )
                )
