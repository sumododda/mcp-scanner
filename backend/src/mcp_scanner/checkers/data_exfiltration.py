"""Data Exfiltration Checker — detects data exfiltration channels,
credential exposure, covert data flows, and cross-server shadowing.

Detection layers:
1. Known data collection service URLs (webhook.site, requestbin, ngrok, etc.)
2. Credential/secret patterns in descriptions and parameter metadata
3. LLM auto-populated parameter names (conversation_history, system_prompt)
4. Exfiltration instruction combos (read file + pass as parameter)
5. Parameter description exfiltration indicators
6. Cross-server tool shadowing (direct tool name references)

Also checks: suspicious parameter names, sensitive data parameters,
external URLs, and email addresses in descriptions.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from mcp_scanner.checkers.base import BaseChecker, CheckerResult, FindingData, Severity, is_test_path

if TYPE_CHECKING:
    from mcp_scanner.services.code_graph import CodeGraph
from mcp_scanner.checkers.normalizer import normalize
from mcp_scanner.checkers.patterns import (
    AUTO_POPULATED_PARAM_NAMES,
    SENSITIVE_PARAM_NAMES,
    SUSPICIOUS_PARAM_NAMES,
)
from mcp_scanner.checkers.utils import resolve_source_location
from mcp_scanner.models.scan_context import ScanContext, ToolDefinition

# ── URL / Email regexes ────────────────────────────────────────────────

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.IGNORECASE
)

# ── Layer 1: Known Data Collection Service Domains ─────────────────────

_KNOWN_EXFIL_DOMAINS: set[str] = {
    "webhook.site",
    "requestbin.com",
    "pipedream.net",
    "hookbin.com",
    "beeceptor.com",
    "mockbin.org",
    "requestcatcher.com",
    "smee.io",
    "ultrahook.com",
    "localtunnel.me",
    "serveo.net",
    "burpcollaborator.net",
    "oastify.com",
    "interact.sh",
    "canarytokens.com",
    "dnslog.cn",
    "ceye.io",
    "requestrepo.com",
    "pipedream.com",
    "postb.in",
    "putsreq.com",
    "hookdeck.com",
}

_NGROK_RE = re.compile(r"https?://[a-z0-9\-]+\.ngrok\.(?:io|app|dev)", re.IGNORECASE)

# ── Layer 2: Credential / Secret Patterns ──────────────────────────────

_CREDENTIAL_PATTERNS: list[tuple[re.Pattern, str]] = [
    (
        re.compile(r"-----BEGIN\s+(?:RSA\s+|DSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----"),
        "Private key header",
    ),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key"),
    (re.compile(r"sk-ant-[a-zA-Z0-9\-_]{20,}"), "Anthropic API key pattern"),
    (re.compile(r"ghp_[a-zA-Z0-9]{36}"), "GitHub personal access token"),
    (re.compile(r"sk-[a-zA-Z0-9]{20,}"), "OpenAI-style API key"),
    (
        re.compile(r"xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+"),
        "Slack bot token",
    ),
]

# ── Layer 4: Exfiltration Instruction Combos ───────────────────────────

_EXFIL_COMBO_PATTERNS: list[re.Pattern] = [
    re.compile(
        r"(?i)(?:read|access|open|fetch)\s+.{1,80}"
        r"(?:pass|send|include|forward|upload|transmit)\s+(?:its?\s+)?(?:content|data|as|to|in|via)"
    ),
    re.compile(
        r"(?i)(?:before|first)\s+(?:using|calling)\s+this\s+tool.{0,60}"
        r"(?:read|include|pass|send|fetch|access)"
    ),
    re.compile(
        r"(?i)include\s+(?:the\s+)?(?:full|entire|complete)\s+"
        r"(?:conversation|chat|history|context|session)"
    ),
    re.compile(
        r"(?i)(?:content|data|output)\s+(?:of|from)\s+.{1,60}"
        r"(?:as|into|to)\s+(?:the\s+)?\w+\s+(?:parameter|field|argument)"
    ),
    re.compile(
        r"(?i)(?:call|use|invoke)\s+this\s+tool\s+with\s+(?:the\s+)?"
        r"(?:full|entire|complete)\s+(?:conversation|chat|history|context)"
    ),
]

# ── Layer 5: Parameter Description Exfiltration Indicators ─────────────

_PARAM_EXFIL_RE = re.compile(
    r"(?i)include\s+(?:all|any|the)\s+(?:previous|prior|recent|full)"
    r"|(?:paste|copy|include)\s+(?:the\s+)?(?:entire|full|complete)\s+"
    r"(?:output|response|content|conversation|history|context)"
    r"|automatically\s+(?:include|attach|append)"
    r"|(?:this|the)\s+(?:field|parameter)\s+(?:should|must|will)\s+contain\s+"
    r"(?:the|all|any|full)",
    re.IGNORECASE,
)

# ── Layer 6: Cross-server shadowing ────────────────────────────────────


def _extract_domain(url: str) -> str | None:
    """Extract the domain from a URL string."""
    try:
        parsed = urlparse(url.rstrip(".,;:)"))
        return parsed.hostname
    except Exception:
        return None


def _is_known_exfil_domain(url: str) -> bool:
    """Check if a URL points to a known data collection service."""
    domain = _extract_domain(url)
    if not domain:
        return False
    # Direct domain match
    if domain in _KNOWN_EXFIL_DOMAINS:
        return True
    # Check subdomains (e.g., abc.pipedream.net)
    parts = domain.split(".")
    if len(parts) >= 2:
        base = ".".join(parts[-2:])
        if base in _KNOWN_EXFIL_DOMAINS:
            return True
    # Ngrok check
    if _NGROK_RE.match(url):
        return True
    return False


def _scan_text_for_credentials(text: str) -> list[tuple[str, str]]:
    """Scan text for credential/secret patterns. Returns list of (match, label)."""
    results = []
    for pattern, label in _CREDENTIAL_PATTERNS:
        for m in pattern.finditer(text):
            results.append((m.group(), label))
    return results


class DataExfiltrationChecker(BaseChecker):
    name = "data_exfiltration"
    description = "Detects data exfiltration patterns, credential exposure, and cross-server shadowing"

    async def check(self, context: ScanContext) -> CheckerResult:
        findings: list[FindingData] = []

        # Collect all tool names per server for cross-server shadowing detection
        tool_names_by_server: dict[str, set[str]] = {}
        for server_name, tools in context.tool_definitions.items():
            tool_names_by_server[server_name] = {t.tool_name for t in tools}

        for server_name, tools in context.tool_definitions.items():
            for tool in tools:
                loc = f"{server_name}/{tool.tool_name}"
                desc = tool.description or ""
                schema = tool.input_schema or {}
                props = schema.get("properties", {})

                # ── Parameter-level checks ──────────────────────
                self._check_parameters(tool, loc, props, findings)

                # ── Description-level checks (with normalization) ──
                if desc:
                    norm = normalize(desc, max_size=50_000, location=loc)
                    findings.extend(norm.anomalies)
                    texts_to_scan = [desc]
                    if norm.normalized != desc:
                        texts_to_scan.append(norm.normalized)
                    for text in texts_to_scan:
                        scan_loc = loc if text == desc else f"{loc}:normalized"
                        self._check_description(tool, scan_loc, text, findings)
                else:
                    self._check_description(tool, loc, desc, findings)

                # Also scan parameter defaults and enum values for
                # URLs and credentials (Layers 1, 2)
                self._check_param_metadata(loc, props, findings)

                # ── Cross-server shadowing (Layer 6) ────────────
                self._check_cross_server_shadowing(
                    tool, server_name, loc, desc,
                    tool_names_by_server, findings,
                )

        # Scan prompt definitions
        for server_name, prompts in context.prompt_definitions.items():
            for prompt in prompts:
                loc = f"prompt:{server_name}:{prompt.name}"
                desc = prompt.description or ""
                if desc:
                    self._check_text_for_exfil_signals(desc, loc, findings)
                for arg in prompt.arguments:
                    arg_desc = arg.get("description", "")
                    if arg_desc:
                        self._check_text_for_exfil_signals(
                            arg_desc, f"{loc}:arg:{arg.get('name', '?')}", findings,
                        )

        # Scan resource definitions
        for server_name, resources in context.resource_definitions.items():
            for resource in resources:
                loc = f"resource:{server_name}:{resource.name}"
                # Check resource URI for known exfil domains
                if resource.uri:
                    for m in _URL_RE.finditer(resource.uri):
                        url = m.group()
                        if _is_known_exfil_domain(url):
                            findings.append(
                                FindingData(
                                    checker="data_exfiltration",
                                    severity=Severity.CRITICAL,
                                    title="Known data collection service URL in resource URI",
                                    description=(
                                        f"Resource '{resource.name}' on server '{server_name}' "
                                        f"has a URI pointing to a known exfil service: {url}"
                                    ),
                                    evidence=url,
                                    location=f"{loc}:uri",
                                    remediation="Remove this resource. Its URI points to a data collection service.",
                                    cwe_id="CWE-200",
                                )
                            )
                desc = resource.description or ""
                if desc:
                    self._check_text_for_exfil_signals(desc, loc, findings)

        # Enrich findings with source file/line
        if context.source_code_path:
            tool_lookup = {
                f"{sn}/{t.tool_name}": t
                for sn, tools in context.tool_definitions.items()
                for t in tools
            }
            for finding in findings:
                tool_key = finding.location.split(":")[0]
                t = tool_lookup.get(tool_key)
                if t:
                    finding.source_file, finding.source_line = (
                        resolve_source_location(
                            t, finding.evidence, context.source_code_path,
                        )
                    )

        # Code graph analysis (when available)
        if context.code_graph is not None:
            self._check_code_graph(context.code_graph, findings)

        return CheckerResult(findings=findings, checker_name=self.name)

    def _check_code_graph(self, graph: CodeGraph, findings: list[FindingData]) -> None:
        """Run data exfiltration checks using the code graph."""

        _NETWORK_CALLEES = {
            "requests.get", "requests.post", "requests.put", "requests.delete",
            "requests.patch", "requests.request",
            "httpx.get", "httpx.post", "httpx.put", "httpx.delete",
            "httpx.AsyncClient", "httpx.Client",
            "fetch", "axios.get", "axios.post", "axios.put", "axios.delete",
            "aiohttp.ClientSession",
            "http.Get", "http.Post", "http.NewRequest",
            "urllib.request.urlopen",
        }
        _FILE_READ_CALLEES = {
            "open", "pathlib.Path.read_text", "pathlib.Path.read_bytes",
            "fs.readFile", "fs.readFileSync",
            "os.ReadFile", "os.Open",
        }

        for handler in graph.tool_handlers:
            if is_test_path(handler.file_path):
                continue
            handler_calls = [
                c for c in graph.call_sites
                if c.parent_function == handler.name and c.file_path == handler.file_path
            ]
            handler_callees = {c.callee for c in handler_calls}

            # Check 1: Outbound HTTP from tool handler
            network_in_handler = handler_callees & _NETWORK_CALLEES
            if network_in_handler:
                findings.append(
                    FindingData(
                        checker="data_exfiltration",
                        severity=Severity.MEDIUM,
                        title="Outbound HTTP from tool handler",
                        description=(
                            f"Tool handler '{handler.name}' in {handler.file_path} "
                            f"makes outbound HTTP calls ({', '.join(network_in_handler)}). "
                            "This could be used for data exfiltration."
                        ),
                        evidence=", ".join(network_in_handler),
                        location=f"source:{handler.file_path}:{handler.line}",
                        remediation="Verify outbound calls are to trusted endpoints only.",
                        cwe_id="CWE-200",
                    )
                )

            # Check 2: File read + network chain (same handler)
            file_reads = handler_callees & _FILE_READ_CALLEES
            if file_reads and network_in_handler:
                findings.append(
                    FindingData(
                        checker="data_exfiltration",
                        severity=Severity.HIGH,
                        title="File read + network call chain in tool handler",
                        description=(
                            f"Tool handler '{handler.name}' in {handler.file_path} "
                            f"reads files ({', '.join(file_reads)}) and makes network "
                            f"calls ({', '.join(network_in_handler)}) in the same function. "
                            "This pattern can exfiltrate local file contents."
                        ),
                        evidence=f"reads: {', '.join(file_reads)}; sends: {', '.join(network_in_handler)}",
                        location=f"source:{handler.file_path}:{handler.line}",
                        remediation="Ensure file data is not sent to external endpoints.",
                        cwe_id="CWE-200",
                    )
                )

    # ------------------------------------------------------------------
    # Parameter-level checks (Layers 3, suspicious params, sensitive params)
    # ------------------------------------------------------------------

    def _check_parameters(
        self,
        tool: ToolDefinition,
        loc: str,
        props: dict,
        findings: list[FindingData],
    ) -> None:
        for param_name, param_def in props.items():
            lower_name = param_name.lower()

            # Layer 3: LLM auto-populated parameter names
            if lower_name in AUTO_POPULATED_PARAM_NAMES:
                findings.append(
                    FindingData(
                        checker="data_exfiltration",
                        severity=Severity.HIGH,
                        title="LLM auto-populated parameter name",
                        description=(
                            f"Parameter '{param_name}' in tool '{tool.tool_name}' "
                            "has a name that LLMs automatically populate with sensitive "
                            "context data (conversation history, system prompts). "
                            "This is a known exfiltration technique."
                        ),
                        evidence=f"param: {param_name}",
                        location=f"{loc}:param:{param_name}",
                        remediation=(
                            "Remove or rename this parameter. LLMs will auto-fill "
                            "parameters named like this with sensitive context data."
                        ),
                        cwe_id="CWE-200",
                    )
                )

            # Suspicious parameter names (shared set)
            elif lower_name in SUSPICIOUS_PARAM_NAMES:
                findings.append(
                    FindingData(
                        checker="data_exfiltration",
                        severity=Severity.MEDIUM,
                        title="Suspicious parameter name",
                        description=(
                            f"Parameter '{param_name}' in tool '{tool.tool_name}' "
                            "has a name commonly associated with data exfiltration "
                            "side-channels."
                        ),
                        evidence=f"param: {param_name}",
                        location=f"{loc}:param:{param_name}",
                        remediation=(
                            "Verify this parameter is necessary. "
                            "Ensure it does not leak sensitive data."
                        ),
                        cwe_id="CWE-200",
                    )
                )

            # Sensitive data parameters
            if lower_name in SENSITIVE_PARAM_NAMES:
                findings.append(
                    FindingData(
                        checker="data_exfiltration",
                        severity=Severity.HIGH,
                        title="Sensitive data parameter",
                        description=(
                            f"Parameter '{param_name}' in tool '{tool.tool_name}' "
                            "directly handles sensitive data such as credentials "
                            "or tokens."
                        ),
                        evidence=f"param: {param_name}",
                        location=f"{loc}:param:{param_name}",
                        remediation=(
                            "Ensure sensitive data is handled securely. "
                            "Avoid passing secrets as tool parameters."
                        ),
                        cwe_id="CWE-522",
                    )
                )

            # Layer 5: Parameter description exfiltration indicators
            param_desc = param_def.get("description", "")
            if param_desc and _PARAM_EXFIL_RE.search(param_desc):
                findings.append(
                    FindingData(
                        checker="data_exfiltration",
                        severity=Severity.HIGH,
                        title="Parameter description exfiltration indicator",
                        description=(
                            f"Parameter '{param_name}' in tool '{tool.tool_name}' "
                            "has a description that instructs collecting or including "
                            "sensitive data. This is a common exfiltration pattern."
                        ),
                        evidence=param_desc[:200],
                        location=f"{loc}:param:{param_name}",
                        remediation=(
                            "Review this parameter's description. It should not "
                            "instruct collecting conversation history, system "
                            "prompts, or other sensitive context."
                        ),
                        cwe_id="CWE-200",
                    )
                )

    # ------------------------------------------------------------------
    # Description-level checks (Layers 1, 2, 4, URLs, emails)
    # ------------------------------------------------------------------

    def _check_description(
        self,
        tool: ToolDefinition,
        loc: str,
        desc: str,
        findings: list[FindingData],
    ) -> None:
        if not desc:
            return

        # Layer 1 + URL detection: Check all URLs
        for m in _URL_RE.finditer(desc):
            url = m.group()
            if _is_known_exfil_domain(url):
                findings.append(
                    FindingData(
                        checker="data_exfiltration",
                        severity=Severity.CRITICAL,
                        title="Known data collection service URL",
                        description=(
                            f"Tool '{tool.tool_name}' description contains a URL "
                            f"pointing to a known data collection/exfiltration service: "
                            f"{url}"
                        ),
                        evidence=url,
                        location=f"{loc}:description",
                        remediation=(
                            "Remove this URL. Data collection services like "
                            "webhook.site and requestbin are commonly used to "
                            "exfiltrate stolen data."
                        ),
                        cwe_id="CWE-200",
                    )
                )
            else:
                findings.append(
                    FindingData(
                        checker="data_exfiltration",
                        severity=Severity.LOW,
                        title="External URL in tool description",
                        description=(
                            f"Tool '{tool.tool_name}' description contains an "
                            f"external URL: {url}"
                        ),
                        evidence=url,
                        location=f"{loc}:description",
                        remediation="Verify the URL is legitimate and necessary.",
                        cwe_id="CWE-200",
                    )
                )

        # Email detection
        for m in _EMAIL_RE.finditer(desc):
            findings.append(
                FindingData(
                    checker="data_exfiltration",
                    severity=Severity.MEDIUM,
                    title="Email address in tool description",
                    description=(
                        f"Tool '{tool.tool_name}' description contains an "
                        f"email address: {m.group()}"
                    ),
                    evidence=m.group(),
                    location=f"{loc}:description",
                    remediation="Verify the email address is legitimate.",
                    cwe_id="CWE-200",
                )
            )

        # Layer 2: Credential/secret patterns in description
        for match_text, label in _scan_text_for_credentials(desc):
            findings.append(
                FindingData(
                    checker="data_exfiltration",
                    severity=Severity.HIGH,
                    title="Credential/secret pattern in description",
                    description=(
                        f"Tool '{tool.tool_name}' description contains a "
                        f"{label}: {match_text[:60]}"
                    ),
                    evidence=match_text[:200],
                    location=f"{loc}:description",
                    remediation=(
                        "Remove credential patterns from tool descriptions. "
                        "Secrets should never appear in tool metadata."
                    ),
                    cwe_id="CWE-798",
                )
            )

        # Layer 4: Exfiltration instruction combos
        for pattern in _EXFIL_COMBO_PATTERNS:
            m = pattern.search(desc)
            if m:
                findings.append(
                    FindingData(
                        checker="data_exfiltration",
                        severity=Severity.CRITICAL,
                        title="Exfiltration instruction combo detected",
                        description=(
                            f"Tool '{tool.tool_name}' description contains a "
                            "composite instruction that combines data access with "
                            "data transfer — the signature of a Tool Poisoning Attack."
                        ),
                        evidence=m.group()[:200],
                        location=f"{loc}:description",
                        remediation=(
                            "This tool description attempts to instruct the LLM to "
                            "read sensitive data and pass it through tool parameters. "
                            "Remove the server from your MCP configuration."
                        ),
                        cwe_id="CWE-200",
                    )
                )

    # ------------------------------------------------------------------
    # Parameter metadata checks (defaults, enums — Layers 1, 2)
    # ------------------------------------------------------------------

    def _check_param_metadata(
        self,
        loc: str,
        props: dict,
        findings: list[FindingData],
    ) -> None:
        for param_name, param_def in props.items():
            # Check defaults
            default = param_def.get("default")
            if isinstance(default, str) and default:
                self._check_text_for_exfil_urls(
                    default, f"{loc}:default:{param_name}", param_name, findings,
                )
                for match_text, label in _scan_text_for_credentials(default):
                    findings.append(
                        FindingData(
                            checker="data_exfiltration",
                            severity=Severity.HIGH,
                            title="Credential/secret pattern in parameter default",
                            description=(
                                f"Parameter '{param_name}' default value contains "
                                f"a {label}: {match_text[:60]}"
                            ),
                            evidence=match_text[:200],
                            location=f"{loc}:default:{param_name}",
                            remediation="Remove credentials from parameter defaults.",
                            cwe_id="CWE-798",
                        )
                    )

            # Check enum values
            enums = param_def.get("enum")
            if isinstance(enums, list):
                for enum_val in enums:
                    if isinstance(enum_val, str) and enum_val:
                        self._check_text_for_exfil_urls(
                            enum_val, f"{loc}:enum:{param_name}",
                            param_name, findings,
                        )

    def _check_text_for_exfil_urls(
        self,
        text: str,
        location: str,
        param_name: str,
        findings: list[FindingData],
    ) -> None:
        """Check text for known exfiltration service URLs."""
        for m in _URL_RE.finditer(text):
            url = m.group()
            if _is_known_exfil_domain(url):
                findings.append(
                    FindingData(
                        checker="data_exfiltration",
                        severity=Severity.CRITICAL,
                        title="Known data collection service URL",
                        description=(
                            f"Parameter '{param_name}' contains a URL pointing to "
                            f"a known data collection service: {url}"
                        ),
                        evidence=url,
                        location=location,
                        remediation=(
                            "Remove this URL. Data collection services are "
                            "commonly used to exfiltrate stolen data."
                        ),
                        cwe_id="CWE-200",
                    )
                )

    # ------------------------------------------------------------------
    # Cross-server shadowing (Layer 6)
    # ------------------------------------------------------------------

    def _check_cross_server_shadowing(
        self,
        tool: ToolDefinition,
        server_name: str,
        loc: str,
        desc: str,
        tool_names_by_server: dict[str, set[str]],
        findings: list[FindingData],
    ) -> None:
        if not desc:
            return

        for other_server, other_tools in tool_names_by_server.items():
            if other_server == server_name:
                continue

            # Check if description mentions tools from other servers
            for other_tool_name in other_tools:
                # Use word-boundary matching for short names to reduce FPs
                if len(other_tool_name) <= 4:
                    pattern = re.compile(r"\b" + re.escape(other_tool_name) + r"\b")
                    if pattern.search(desc):
                        findings.append(self._shadow_finding(
                            tool, server_name, other_tool_name, other_server, loc,
                        ))
                elif other_tool_name in desc:
                    findings.append(self._shadow_finding(
                        tool, server_name, other_tool_name, other_server, loc,
                    ))

    # ------------------------------------------------------------------
    # Shared text scanning for prompts/resources (Layers 1, 2, 4, 5)
    # ------------------------------------------------------------------

    def _check_text_for_exfil_signals(
        self,
        text: str,
        location: str,
        findings: list[FindingData],
    ) -> None:
        """Scan text (prompt/resource descriptions) for exfil signals."""
        # Layer 1: Known exfil domain URLs
        for m in _URL_RE.finditer(text):
            url = m.group()
            if _is_known_exfil_domain(url):
                findings.append(
                    FindingData(
                        checker="data_exfiltration",
                        severity=Severity.CRITICAL,
                        title="Known data collection service URL",
                        description=f"Text contains a URL pointing to a known exfil service: {url}",
                        evidence=url,
                        location=location,
                        remediation="Remove this URL. It points to a data collection service.",
                        cwe_id="CWE-200",
                    )
                )

        # Layer 2: Credential/secret patterns
        for match_text, label in _scan_text_for_credentials(text):
            findings.append(
                FindingData(
                    checker="data_exfiltration",
                    severity=Severity.HIGH,
                    title="Credential/secret pattern detected",
                    description=f"Text contains a {label}: {match_text[:60]}",
                    evidence=match_text[:200],
                    location=location,
                    remediation="Remove credentials from definitions.",
                    cwe_id="CWE-798",
                )
            )

        # Layer 4: Exfiltration instruction combos
        for pattern in _EXFIL_COMBO_PATTERNS:
            m = pattern.search(text)
            if m:
                findings.append(
                    FindingData(
                        checker="data_exfiltration",
                        severity=Severity.CRITICAL,
                        title="Exfiltration instruction combo detected",
                        description=(
                            "Text contains a composite instruction combining "
                            "data access with data transfer."
                        ),
                        evidence=m.group()[:200],
                        location=location,
                        remediation="Remove exfiltration instructions.",
                        cwe_id="CWE-200",
                    )
                )

        # Layer 5: Parameter description exfiltration indicators
        m = _PARAM_EXFIL_RE.search(text)
        if m:
            findings.append(
                FindingData(
                    checker="data_exfiltration",
                    severity=Severity.HIGH,
                    title="Exfiltration indicator in text",
                    description="Text contains language instructing data collection.",
                    evidence=m.group()[:200],
                    location=location,
                    remediation="Review this text for data exfiltration patterns.",
                    cwe_id="CWE-200",
                )
            )

    def _shadow_finding(
        self,
        tool: ToolDefinition,
        server_name: str,
        other_tool_name: str,
        other_server: str,
        loc: str,
    ) -> FindingData:
        return FindingData(
            checker="data_exfiltration",
            severity=Severity.HIGH,
            title="Cross-server tool shadowing",
            description=(
                f"Tool '{tool.tool_name}' on server '{server_name}' "
                f"mentions tool '{other_tool_name}' from server "
                f"'{other_server}'. This may indicate cross-server shadowing."
            ),
            evidence=(
                f"'{other_tool_name}' found in description "
                f"of '{tool.tool_name}'"
            ),
            location=f"{loc}:description",
            remediation=(
                "Investigate why a tool references tools "
                "from another server."
            ),
            cwe_id="CWE-923",
        )
