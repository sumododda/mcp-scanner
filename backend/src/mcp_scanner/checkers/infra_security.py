"""Infrastructure Security Checker — checks configuration and source code for infrastructure issues."""

from __future__ import annotations

import asyncio
import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING

from mcp_scanner.checkers.base import BaseChecker, CheckerResult, FindingData, Severity, is_test_path, SecurityQuestion
from mcp_scanner.models.scan_context import ScanContext

if TYPE_CHECKING:
    from mcp_scanner.services.code_graph import CodeGraph

logger = logging.getLogger(__name__)

# Secret patterns (prefixes that indicate plaintext secrets)
_SECRET_PATTERNS = [
    (r"sk-[a-zA-Z0-9]{20,}", "OpenAI API key"),
    (r"ghp_[a-zA-Z0-9]{36,}", "GitHub personal access token"),
    (r"npm_[a-zA-Z0-9]{36,}", "npm token"),
    (r"AKIA[A-Z0-9]{16}", "AWS access key ID"),
    (r"xoxb-[a-zA-Z0-9\-]{20,}", "Slack bot token"),
    (r"xoxp-[a-zA-Z0-9\-]{20,}", "Slack user token"),
]

_SECRET_REGEXES = [(re.compile(pat), label) for pat, label in _SECRET_PATTERNS]

# Insecure deserialization callees
_DESER_CALLEES = {
    "pickle.loads", "pickle.load", "marshal.loads", "marshal.load",
    "yaml.load", "yaml.unsafe_load", "shelve.open", "jsonpickle.decode",
}

# Weak cryptographic hash functions
_WEAK_CRYPTO = {"hashlib.md5", "hashlib.sha1", "MD5.new", "SHA.new", "Crypto.Hash.MD5.new", "Crypto.Hash.SHA.new"}

# Insecure TLS configuration patterns
_TLS_RE = re.compile(r'verify\s*=\s*False|check_hostname\s*=\s*False|CERT_NONE', re.IGNORECASE)

# Error handling patterns
_ERROR_HANDLING_RE = re.compile(r'\b(try\s*:|except\s|catch\s*\(|\.catch\s*\()', re.IGNORECASE)

# File access callees that may allow path traversal
_FILE_CALLEES = {"open", "pathlib.Path.read_text", "pathlib.Path.read_bytes", "pathlib.Path.write_text", "pathlib.Path.write_bytes"}

# Rate limiting library modules
_RATE_LIMIT_MODULES = {"slowapi", "ratelimit", "express-rate-limit", "rate-limiter-flexible", "throttle", "flask_limiter", "django_ratelimit"}


class InfraSecurityChecker(BaseChecker):
    name = "infra_security"
    description = "Checks MCP server configuration for infrastructure security issues"

    async def check(self, context: ScanContext) -> CheckerResult:
        findings: list[FindingData] = []
        security_questions: list[SecurityQuestion] = []

        servers = context.mcp_config.get("mcpServers", {})
        for server_name, server_config in servers.items():
            if not isinstance(server_config, dict):
                continue

            loc = f"config:{server_name}"

            # Check for HTTP (not HTTPS) transport URLs
            url = server_config.get("url", "")
            if url.startswith("http://"):
                findings.append(
                    FindingData(
                        checker="infra_security",
                        severity=Severity.HIGH,
                        title="Insecure HTTP transport",
                        description=(
                            f"Server '{server_name}' uses plaintext HTTP "
                            f"transport ({url}). Data in transit is not encrypted."
                        ),
                        evidence=url,
                        location=loc,
                        remediation="Use HTTPS instead of HTTP for transport.",
                        cwe_id="CWE-319",
                    )
                )

            # Check for plaintext secrets in env vars
            env = server_config.get("env", {})
            if isinstance(env, dict):
                for env_key, env_val in env.items():
                    if not isinstance(env_val, str):
                        continue
                    for regex, label in _SECRET_REGEXES:
                        if regex.search(env_val):
                            findings.append(
                                FindingData(
                                    checker="infra_security",
                                    severity=Severity.HIGH,
                                    title="Plaintext secret in configuration",
                                    description=(
                                        f"Environment variable '{env_key}' in server "
                                        f"'{server_name}' contains a plaintext "
                                        f"{label}."
                                    ),
                                    evidence=f"{env_key}={env_val[:8]}...",
                                    location=f"{loc}:env:{env_key}",
                                    remediation=(
                                        "Use a secrets manager or environment variable "
                                        "reference instead of plaintext secrets."
                                    ),
                                    cwe_id="CWE-798",
                                )
                            )

            # Check for plaintext secrets in headers
            headers = server_config.get("headers", {})
            if isinstance(headers, dict):
                for hdr_key, hdr_val in headers.items():
                    if not isinstance(hdr_val, str):
                        continue
                    for regex, label in _SECRET_REGEXES:
                        if regex.search(hdr_val):
                            findings.append(
                                FindingData(
                                    checker="infra_security",
                                    severity=Severity.HIGH,
                                    title="Plaintext secret in headers",
                                    description=(
                                        f"Header '{hdr_key}' in server "
                                        f"'{server_name}' contains a plaintext "
                                        f"{label}."
                                    ),
                                    evidence=f"{hdr_key}={hdr_val[:8]}...",
                                    location=f"{loc}:headers:{hdr_key}",
                                    remediation=(
                                        "Use a secrets manager or environment variable "
                                        "reference instead of plaintext secrets."
                                    ),
                                    cwe_id="CWE-798",
                                )
                            )

            # Check for elevated privileges (sudo in command)
            command = server_config.get("command", "")
            args = server_config.get("args", [])
            full_command = f"{command} {' '.join(str(a) for a in args)}".strip()

            if "sudo" in full_command.split():
                findings.append(
                    FindingData(
                        checker="infra_security",
                        severity=Severity.CRITICAL,
                        title="Elevated privileges detected",
                        description=(
                            f"Server '{server_name}' uses sudo, granting "
                            "elevated privileges. A compromised MCP server "
                            "with root access can cause severe damage."
                        ),
                        evidence=full_command,
                        location=loc,
                        remediation=(
                            "Run MCP servers with least-privilege access. "
                            "Remove sudo from the command."
                        ),
                        cwe_id="CWE-250",
                    )
                )

        # Build SecurityQuestions for config checks
        http_issues = [f for f in findings if f.cwe_id == "CWE-319" and f.location.startswith("config:")]
        security_questions.append(SecurityQuestion(
            id="http_transport",
            question="Is the transport layer encrypted?",
            answer=f"Found {len(http_issues)} insecure HTTP transport(s)" if http_issues else "All transports use HTTPS or no URLs configured",
            status="issue" if http_issues else "clear",
            items_checked=len(servers),
            items_checked_label="server configs",
            severity="high" if http_issues else None,
        ))

        secret_issues = [f for f in findings if f.cwe_id == "CWE-798" and f.location.startswith("config:")]
        security_questions.append(SecurityQuestion(
            id="plaintext_secrets_config",
            question="Are secrets stored securely in configuration?",
            answer=f"Found {len(secret_issues)} plaintext secret(s)" if secret_issues else "No plaintext secrets detected in config",
            status="issue" if secret_issues else "clear",
            items_checked=sum(len(sc.get("env", {})) + len(sc.get("headers", {})) for sc in servers.values() if isinstance(sc, dict)),
            items_checked_label="env vars and headers",
            severity="high" if secret_issues else None,
        ))

        priv_issues = [f for f in findings if f.cwe_id == "CWE-250"]
        security_questions.append(SecurityQuestion(
            id="elevated_privileges",
            question="Does the server run with elevated privileges?",
            answer=f"Found {len(priv_issues)} server(s) using sudo" if priv_issues else "No elevated privileges detected",
            status="issue" if priv_issues else "clear",
            items_checked=len(servers),
            items_checked_label="server configs",
            severity="critical" if priv_issues else None,
        ))

        # Code graph analysis (when available)
        if context.code_graph is not None:
            await self._check_code_graph(context.code_graph, findings, security_questions)

        return CheckerResult(findings=findings, checker_name=self.name, security_questions=security_questions)

    async def _check_code_graph(self, graph: CodeGraph, findings: list[FindingData], security_questions: list[SecurityQuestion]) -> None:
        """Run infrastructure checks using the code graph."""

        # Auth library imports
        _AUTH_MODULES = {
            "jwt", "jose", "pyjwt", "passport", "oauth", "oauthlib",
            "fastapi.security", "authlib", "go-oidc", "casbin",
            "flask_login", "django.contrib.auth",
        }
        # Validation library imports
        _VALIDATION_MODULES = {
            "pydantic", "zod", "joi", "jsonschema", "marshmallow", "ajv",
            "cerberus", "voluptuous", "wtforms",
        }

        has_tool_handlers = len(graph.tool_handlers) > 0

        # Check 1: No authentication middleware when tool handlers exist
        auth_found = False
        found_module = ""
        if has_tool_handlers:
            for imp in graph.imports:
                for auth in _AUTH_MODULES:
                    if auth in imp.module.lower():
                        auth_found = True
                        found_module = imp.module
                        break
                    if any(auth in name.lower() for name in imp.names):
                        auth_found = True
                        found_module = imp.module
                        break
                if auth_found:
                    break
            if not auth_found:
                findings.append(
                    FindingData(
                        checker="infra_security",
                        severity=Severity.MEDIUM,
                        title="No authentication middleware detected",
                        description=(
                            "Source code defines tool handlers but imports no "
                            "authentication libraries (jwt, passport, oauth, etc.). "
                            "MCP servers should authenticate callers."
                        ),
                        evidence=f"{len(graph.tool_handlers)} tool handlers, no auth imports",
                        location="source:code_graph",
                        remediation="Add authentication middleware to verify caller identity.",
                        cwe_id="CWE-306",
                    )
                )

            security_questions.append(SecurityQuestion(
                id="auth_middleware",
                question="Does the server use authentication middleware?",
                answer=f"Found auth via {found_module}" if auth_found else "No auth middleware imports found",
                status="clear" if auth_found else "issue",
                items_checked=len(graph.imports),
                items_checked_label="imports",
                severity=None if auth_found else "medium",
            ))

            # Check 2: No input validation framework
            validation_found = False
            found_val_module = ""
            for imp in graph.imports:
                for val in _VALIDATION_MODULES:
                    if val in imp.module.lower():
                        validation_found = True
                        found_val_module = imp.module
                        break
                    if any(val in name.lower() for name in imp.names):
                        validation_found = True
                        found_val_module = imp.module
                        break
                if validation_found:
                    break
            if not validation_found:
                findings.append(
                    FindingData(
                        checker="infra_security",
                        severity=Severity.MEDIUM,
                        title="No input validation framework detected",
                        description=(
                            "Source code defines tool handlers but imports no "
                            "input validation libraries (pydantic, zod, joi, etc.). "
                            "All tool inputs should be validated."
                        ),
                        evidence=f"{len(graph.tool_handlers)} tool handlers, no validation imports",
                        location="source:code_graph",
                        remediation="Add input validation using a schema validation library.",
                        cwe_id="CWE-20",
                    )
                )

            security_questions.append(SecurityQuestion(
                id="input_validation",
                question="Is input validation implemented for tool handlers?",
                answer=f"Found validation via {found_val_module}" if validation_found else "No input validation framework imports found",
                status="clear" if validation_found else "issue",
                items_checked=len(graph.imports),
                items_checked_label="imports",
                severity=None if validation_found else "medium",
            ))

        # Check 3: Insecure HTTP in source code
        _HTTP_RE = re.compile(r'http://[^\s"\']+')
        http_source_issues = []
        for func in graph.functions:
            # Skip test files — HTTP URLs in tests are expected (example.com etc.)
            if is_test_path(func.file_path):
                continue
            for m in _HTTP_RE.finditer(func.body_text):
                url = m.group()
                # Skip localhost/127.0.0.1 (local dev)
                if "localhost" in url or "127.0.0.1" in url or "0.0.0.0" in url:
                    continue
                f = FindingData(
                    checker="infra_security",
                    severity=Severity.HIGH,
                    title="Insecure HTTP URL in source code",
                    description=(
                        f"Function '{func.name}' in {func.file_path} contains "
                        f"an insecure HTTP URL. Data in transit is not encrypted."
                    ),
                    evidence=url[:200],
                    location=f"source:{func.file_path}:{func.line}",
                    remediation="Use HTTPS instead of HTTP.",
                    cwe_id="CWE-319",
                )
                findings.append(f)
                http_source_issues.append(f)
                break  # One finding per function

        security_questions.append(SecurityQuestion(
            id="http_in_source",
            question="Are there insecure HTTP URLs in source code?",
            answer=f"Found {len(http_source_issues)} insecure HTTP URL(s) in source" if http_source_issues else "No insecure HTTP URLs detected in source",
            status="issue" if http_source_issues else "clear",
            items_checked=len(graph.functions),
            items_checked_label="functions",
            severity="high" if http_source_issues else None,
        ))

        # Check 4: Dangerous operations in tool handlers
        dangerous_op_issues = []
        for handler in graph.tool_handlers:
            if is_test_path(handler.file_path):
                continue
            handler_calls = [
                c for c in graph.call_sites
                if c.parent_function == handler.name and c.file_path == handler.file_path
            ]
            dangerous_in_handler = [
                c for c in handler_calls if c.callee in {
                    "subprocess.run", "subprocess.call", "subprocess.Popen",
                    "subprocess.check_output", "os.system", "os.popen",
                    "eval", "exec",
                    "child_process.exec", "child_process.execSync",
                    "exec.Command",
                }
            ]
            for call in dangerous_in_handler:
                f = FindingData(
                    checker="infra_security",
                    severity=Severity.HIGH,
                    title="Dangerous operation in tool handler",
                    description=(
                        f"Tool handler '{handler.name}' in {handler.file_path} "
                        f"calls '{call.callee}', which can execute arbitrary code."
                    ),
                    evidence=f"{call.callee}({call.arguments_text[:100]})",
                    location=f"source:{call.file_path}:{call.line}",
                    remediation="Avoid subprocess/exec/eval in tool handlers. Use safe APIs.",
                    cwe_id="CWE-78",
                )
                findings.append(f)
                dangerous_op_issues.append(f)

        security_questions.append(SecurityQuestion(
            id="dangerous_operations",
            question="Do tool handlers use dangerous operations (subprocess, eval, exec)?",
            answer=f"Found {len(dangerous_op_issues)} dangerous operation(s) in tool handlers" if dangerous_op_issues else "No dangerous operations detected in tool handlers",
            status="issue" if dangerous_op_issues else "clear",
            items_checked=len(graph.tool_handlers),
            items_checked_label="tool handlers",
            severity="high" if dangerous_op_issues else None,
        ))

        # Check 5: Insecure deserialization in tool handlers
        deser_issues = []
        for handler in graph.tool_handlers:
            if is_test_path(handler.file_path):
                continue
            handler_calls = [c for c in graph.call_sites if c.parent_function == handler.name and c.file_path == handler.file_path]
            for call in handler_calls:
                if call.callee in _DESER_CALLEES:
                    f = FindingData(
                        checker="infra_security", severity=Severity.HIGH,
                        title="Insecure deserialization in tool handler",
                        description=f"Tool handler '{handler.name}' calls '{call.callee}', which can execute arbitrary code when deserializing untrusted data.",
                        evidence=f"{call.callee}({call.arguments_text[:100]})",
                        location=f"source:{call.file_path}:{call.line}",
                        remediation="Use safe alternatives (json.loads, yaml.safe_load) or validate input before deserialization.",
                        cwe_id="CWE-502",
                    )
                    findings.append(f)
                    deser_issues.append(f)

        security_questions.append(SecurityQuestion(
            id="insecure_deserialization",
            question="Is untrusted data deserialized unsafely?",
            answer=f"Found {len(deser_issues)} insecure deserialization call(s)" if deser_issues else "No insecure deserialization detected",
            status="issue" if deser_issues else "clear",
            items_checked=len(graph.tool_handlers),
            items_checked_label="tool handlers",
            severity="high" if deser_issues else None,
        ))

        # Check 6: Weak cryptographic hashing
        weak_crypto_issues = []
        for func in graph.functions:
            if is_test_path(func.file_path):
                continue
            func_calls = [c for c in graph.call_sites if c.parent_function == func.name and c.file_path == func.file_path]
            for call in func_calls:
                if call.callee in _WEAK_CRYPTO:
                    f = FindingData(
                        checker="infra_security", severity=Severity.MEDIUM,
                        title="Weak cryptographic hash algorithm",
                        description=f"Function '{func.name}' uses '{call.callee}'. MD5 and SHA-1 are cryptographically broken.",
                        evidence=f"{call.callee}({call.arguments_text[:100]})",
                        location=f"source:{call.file_path}:{call.line}",
                        remediation="Use SHA-256 or stronger (hashlib.sha256, hashlib.sha3_256).",
                        cwe_id="CWE-328",
                    )
                    findings.append(f)
                    weak_crypto_issues.append(f)
                    break  # One per function

        security_questions.append(SecurityQuestion(
            id="weak_crypto",
            question="Are weak hash algorithms used for security?",
            answer=f"Found {len(weak_crypto_issues)} weak crypto usage(s)" if weak_crypto_issues else "No weak cryptographic hashing detected",
            status="issue" if weak_crypto_issues else "clear",
            items_checked=len(graph.functions),
            items_checked_label="functions",
            severity="medium" if weak_crypto_issues else None,
        ))

        # Check 7: Insecure TLS configuration
        tls_issues = []
        for func in graph.functions:
            if is_test_path(func.file_path):
                continue
            match = _TLS_RE.search(func.body_text)
            if match:
                f = FindingData(
                    checker="infra_security", severity=Severity.HIGH,
                    title="Insecure TLS certificate verification disabled",
                    description=f"Function '{func.name}' disables TLS certificate verification ({match.group()}). This allows man-in-the-middle attacks.",
                    evidence=match.group(),
                    location=f"source:{func.file_path}:{func.line}",
                    remediation="Enable certificate verification. Remove verify=False or set check_hostname=True.",
                    cwe_id="CWE-295",
                )
                findings.append(f)
                tls_issues.append(f)

        security_questions.append(SecurityQuestion(
            id="insecure_tls",
            question="Is TLS certificate verification disabled?",
            answer=f"Found {len(tls_issues)} TLS verification bypass(es)" if tls_issues else "TLS certificate verification is properly configured",
            status="issue" if tls_issues else "clear",
            items_checked=len(graph.functions),
            items_checked_label="functions",
            severity="high" if tls_issues else None,
        ))

        # Check 8: Hardcoded secrets in source code
        hardcoded_secret_issues = []
        for func in graph.functions:
            if is_test_path(func.file_path):
                continue
            for regex, label in _SECRET_REGEXES:
                if regex.search(func.body_text):
                    f = FindingData(
                        checker="infra_security", severity=Severity.HIGH,
                        title="Hardcoded secret in source code",
                        description=f"Function '{func.name}' in {func.file_path} contains a hardcoded {label}.",
                        evidence=f"{label} found in function body",
                        location=f"source:{func.file_path}:{func.line}",
                        remediation="Use environment variables or a secrets manager instead of hardcoded secrets.",
                        cwe_id="CWE-798",
                    )
                    findings.append(f)
                    hardcoded_secret_issues.append(f)
                    break

        security_questions.append(SecurityQuestion(
            id="hardcoded_secrets_source",
            question="Are secrets hardcoded in source code?",
            answer=f"Found {len(hardcoded_secret_issues)} hardcoded secret(s)" if hardcoded_secret_issues else "No hardcoded secrets detected in source",
            status="issue" if hardcoded_secret_issues else "clear",
            items_checked=len(graph.functions),
            items_checked_label="functions",
            severity="high" if hardcoded_secret_issues else None,
        ))

        # Check 9: Missing error handling in tool handlers
        error_handling_issues = []
        for handler in graph.tool_handlers:
            if is_test_path(handler.file_path):
                continue
            if not _ERROR_HANDLING_RE.search(handler.body_text):
                f = FindingData(
                    checker="infra_security", severity=Severity.LOW,
                    title="Missing error handling in tool handler",
                    description=f"Tool handler '{handler.name}' has no try/except or catch blocks. Unhandled errors may crash the server or leak stack traces.",
                    evidence=f"No error handling found in {handler.name}",
                    location=f"source:{handler.file_path}:{handler.line}",
                    remediation="Add try/except blocks to handle errors gracefully.",
                    cwe_id="CWE-755",
                )
                findings.append(f)
                error_handling_issues.append(f)

        security_questions.append(SecurityQuestion(
            id="error_handling",
            question="Do tool handlers have proper error handling?",
            answer=f"Found {len(error_handling_issues)} handler(s) without error handling" if error_handling_issues else "All handlers have error handling",
            status="issue" if error_handling_issues else "clear",
            items_checked=len(graph.tool_handlers),
            items_checked_label="tool handlers",
            severity="low" if error_handling_issues else None,
        ))

        # Check 10: User-controlled file access in tool handlers
        file_access_issues = []
        for handler in graph.tool_handlers:
            if is_test_path(handler.file_path):
                continue
            handler_calls = [c for c in graph.call_sites if c.parent_function == handler.name and c.file_path == handler.file_path]
            for call in handler_calls:
                if call.callee in _FILE_CALLEES:
                    param_in_args = any(p in call.arguments_text for p in handler.parameters if p not in ("self", "cls"))
                    if param_in_args:
                        f = FindingData(
                            checker="infra_security", severity=Severity.MEDIUM,
                            title="User-controlled file path in tool handler",
                            description=f"Tool handler '{handler.name}' passes user parameter to '{call.callee}'. This may allow path traversal.",
                            evidence=f"{call.callee}({call.arguments_text[:100]})",
                            location=f"source:{call.file_path}:{call.line}",
                            remediation="Validate and sanitize file paths. Use os.path.realpath() and check against an allowlist.",
                            cwe_id="CWE-22",
                        )
                        findings.append(f)
                        file_access_issues.append(f)

        security_questions.append(SecurityQuestion(
            id="file_access",
            question="Do handlers access files with user-controlled paths?",
            answer=f"Found {len(file_access_issues)} user-controlled file path(s)" if file_access_issues else "No user-controlled file access detected",
            status="issue" if file_access_issues else "clear",
            items_checked=len(graph.tool_handlers),
            items_checked_label="tool handlers",
            severity="medium" if file_access_issues else None,
        ))

        # Check 11: Missing rate limiting
        if has_tool_handlers:
            rate_limit_found = any(
                any(rl in imp.module.lower() for rl in _RATE_LIMIT_MODULES)
                or any(rl in name.lower() for rl in _RATE_LIMIT_MODULES for name in imp.names)
                for imp in graph.imports
            )
            security_questions.append(SecurityQuestion(
                id="rate_limiting",
                question="Is rate limiting implemented?",
                answer="Rate limiting library detected" if rate_limit_found else "No rate limiting library detected",
                status="clear" if rate_limit_found else "issue",
                items_checked=len(graph.imports),
                items_checked_label="imports",
                severity=None if rate_limit_found else "low",
            ))
            if not rate_limit_found:
                findings.append(FindingData(
                    checker="infra_security", severity=Severity.LOW,
                    title="No rate limiting detected",
                    description="Source code defines tool handlers but imports no rate limiting library. MCP servers should rate-limit requests to prevent abuse.",
                    evidence=f"{len(graph.tool_handlers)} tool handlers, no rate limiting imports",
                    location="source:code_graph",
                    remediation="Add rate limiting (e.g., slowapi for FastAPI, express-rate-limit for Express).",
                    cwe_id="CWE-770",
                ))

        # LLM judge pass for ambiguous findings + enrichment (all concurrent)
        from mcp_scanner.config import settings
        if settings.llm_judge_enabled:
            _JUDGEABLE_TITLES = {
                "Dangerous operation in tool handler",
                "User-controlled file path in tool handler",
                "Insecure deserialization in tool handler",
            }
            judge = InfraLLMJudge()

            # Build evaluation tasks for ambiguous findings
            async def _evaluate(finding: FindingData, handler_body: str, calls_text: str) -> None:
                verdict = await judge.evaluate_finding(finding, handler_body, calls_text)
                if verdict["is_threat"]:
                    finding.llm_analysis = f"LLM confirmed: {verdict['reasoning']}"
                else:
                    finding.llm_analysis = f"LLM assessment: {verdict['reasoning']}"

            eval_tasks = []
            for finding in findings:
                if finding.checker == "infra_security" and finding.title in _JUDGEABLE_TITLES:
                    handler = next(
                        (h for h in graph.tool_handlers
                         if h.name in finding.description and h.file_path in finding.location),
                        None,
                    )
                    if not handler:
                        continue
                    handler_calls = [
                        f"{c.callee}({c.arguments_text[:80]})"
                        for c in graph.call_sites
                        if c.parent_function == handler.name and c.file_path == handler.file_path
                    ]
                    eval_tasks.append(_evaluate(finding, handler.body_text, "\n".join(handler_calls)))

            # Run finding evaluations + question enrichment concurrently
            await asyncio.gather(
                *eval_tasks,
                judge.enrich_questions(security_questions, findings, graph),
            )


_LLM_CONCURRENCY = 4  # Max parallel LLM calls to avoid rate limits


class InfraLLMJudge:
    """LLM judge for ambiguous infrastructure security findings."""

    def __init__(self, max_concurrency: int = _LLM_CONCURRENCY):
        from mcp_scanner.services.llm_judge import LLMJudge
        self._judge = LLMJudge()
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._prompt_template: str | None = None
        self._enrich_template: str | None = None

    def _load_prompt(self) -> str:
        if self._prompt_template is None:
            prompt_file = Path(__file__).parent.parent / "data" / "prompts" / "judge_infra_security.txt"
            self._prompt_template = prompt_file.read_text()
        return self._prompt_template

    def _load_enrich_prompt(self) -> str:
        if self._enrich_template is None:
            prompt_file = Path(__file__).parent.parent / "data" / "prompts" / "judge_infra_enrich.txt"
            self._enrich_template = prompt_file.read_text()
        return self._enrich_template

    async def evaluate_finding(
        self, finding: FindingData, handler_body: str, call_sites_text: str,
    ) -> dict:
        """Evaluate an ambiguous finding.

        Returns dict with is_threat, confidence, severity, reasoning, evidence.
        """
        import secrets
        delimiter = secrets.token_hex(16)
        template = self._load_prompt()

        # Use safe string replacement (no .format() to avoid brace issues)
        prompt = template
        for key, value in {
            "delimiter": delimiter,
            "finding_type": finding.cwe_id or "unknown",
            "finding_title": finding.title,
            "handler_name": finding.location.split(":")[-1] if ":" in finding.location else "unknown",
            "file_path": finding.source_file or finding.location,
            "source_code": handler_body[:2000],
            "call_sites": call_sites_text[:1000],
        }.items():
            prompt = prompt.replace("{" + key + "}", value)

        try:
            async with self._semaphore:
                raw = await self._judge._query(prompt)
            verdict = self._judge._parse_verdict(raw)
            return {
                "is_threat": verdict.suspicious,
                "confidence": 0.8,
                "severity": verdict.severity,
                "reasoning": verdict.reasoning,
                "evidence": verdict.evidence,
            }
        except Exception as e:
            logger.warning("Infra LLM judge failed: %s", e)
            return {
                "is_threat": True,
                "confidence": 0.5,
                "severity": finding.severity.value,
                "reasoning": f"Judge unavailable: {e}",
                "evidence": "",
            }

    async def enrich_questions(
        self,
        questions: list[SecurityQuestion],
        findings: list[FindingData],
        graph: "CodeGraph | None" = None,
    ) -> None:
        """Enrich each SecurityQuestion with a detailed LLM-generated explanation (concurrent)."""
        import secrets as _secrets

        template = self._load_enrich_prompt()

        async def _enrich_one(q: SecurityQuestion) -> None:
            q_findings = [f for f in findings if f.checker == "infra_security"]
            matched = self._match_findings_to_question(q, q_findings)

            evidence_lines = []
            for f in matched:
                evidence_lines.append(
                    f"- **{f.title}** ({f.severity.value}): {f.description}\n"
                    f"  Evidence: `{f.evidence}`\n"
                    f"  Location: {f.location}"
                )
            evidence_block = "\n".join(evidence_lines) if evidence_lines else "No specific findings."

            code_context = ""
            if graph and matched:
                code_snippets = []
                for f in matched[:3]:
                    handler = next(
                        (h for h in graph.tool_handlers
                         if h.name in f.description and h.file_path in f.location),
                        None,
                    )
                    if handler:
                        calls = [
                            f"  {c.callee}({c.arguments_text[:60]})"
                            for c in graph.call_sites
                            if c.parent_function == handler.name and c.file_path == handler.file_path
                        ][:5]
                        code_snippets.append(
                            f"### {handler.name} ({handler.file_path}:{handler.line})\n"
                            f"```\n{handler.body_text[:1500]}\n```\n"
                            f"Calls:\n" + "\n".join(calls)
                        )
                code_context = "\n\n".join(code_snippets) if code_snippets else "No source code available."

            delimiter = _secrets.token_hex(16)
            prompt = template
            for key, value in {
                "delimiter": delimiter,
                "question": q.question,
                "status": q.status,
                "answer": q.answer,
                "evidence_block": evidence_block,
                "code_context": code_context or "No source code available.",
            }.items():
                prompt = prompt.replace("{" + key + "}", value)

            try:
                async with self._semaphore:
                    content = await self._judge._query_text(prompt)
                # Strip code fences if present
                if content.startswith("```"):
                    lines = content.split("\n")
                    content = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
                q.detail = content.strip()
            except Exception as e:
                logger.warning("Infra enrichment failed for %s: %s", q.id, e)

        await asyncio.gather(*[_enrich_one(q) for q in questions])

    @staticmethod
    def _match_findings_to_question(
        q: SecurityQuestion, findings: list[FindingData],
    ) -> list[FindingData]:
        """Match findings to a security question by ID-to-CWE/title mapping."""
        _Q_TO_CRITERIA: dict[str, dict] = {
            "http_transport": {"cwe": "CWE-319", "loc_prefix": "config:"},
            "plaintext_secrets_config": {"cwe": "CWE-798", "loc_prefix": "config:"},
            "elevated_privileges": {"cwe": "CWE-250"},
            "auth_middleware": {"cwe": "CWE-306"},
            "input_validation": {"cwe": "CWE-20"},
            "http_in_source": {"cwe": "CWE-319", "loc_prefix": "source:"},
            "dangerous_operations": {"cwe": "CWE-78"},
            "insecure_deserialization": {"cwe": "CWE-502"},
            "weak_crypto": {"cwe": "CWE-328"},
            "insecure_tls": {"cwe": "CWE-295"},
            "hardcoded_secrets_source": {"cwe": "CWE-798", "loc_prefix": "source:"},
            "error_handling": {"cwe": "CWE-755"},
            "file_access": {"cwe": "CWE-22"},
            "rate_limiting": {"cwe": "CWE-770"},
        }
        criteria = _Q_TO_CRITERIA.get(q.id)
        if not criteria:
            return []
        matched = []
        for f in findings:
            if f.cwe_id == criteria["cwe"]:
                loc_prefix = criteria.get("loc_prefix")
                if loc_prefix and not f.location.startswith(loc_prefix):
                    continue
                matched.append(f)
        return matched
