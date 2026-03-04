"""Rug Pull Checker — detects tool definition changes, parameter mutations,
schema drift, tool removal, and cross-server name collisions.

Based on research from Invariant Labs, CyberArk (Full-Schema Poisoning),
and the broader MCP security ecosystem. A rug pull is a post-approval
bait-and-switch where a trusted MCP server silently rewrites its tool
definitions after the user has approved them.

Detection layers:
1. Hash-based definition change detection (baseline)
2. Granular change classification (description, params, schema)
3. Injection delta analysis (new malicious patterns in changed fields)
4. Parameter mutation analysis (suspicious additions, default/enum changes)
5. Tool removal tracking (tools disappearing from servers)
6. Cross-server name collision detection (tool squatting)
"""

import difflib
import json
import re
from mcp_scanner.checkers.base import BaseChecker, CheckerResult, FindingData, Severity
from mcp_scanner.checkers.normalizer import normalize
from mcp_scanner.checkers.patterns import SUSPICIOUS_PARAM_NAMES
from mcp_scanner.checkers.utils import resolve_source_location
from mcp_scanner.models.scan_context import ScanContext
from mcp_scanner.models.tool_snapshot import ToolSnapshot

# ---------------------------------------------------------------------------
# Patterns for injection delta analysis
# ---------------------------------------------------------------------------

# Injection markers that are CRITICAL when they appear in a definition change.
# These detect the bait-and-switch: clean description → poisoned description.
_INJECTION_MARKERS_RE = re.compile(
    r"<IMPORTANT>|<system>|</IMPORTANT>|</system>"
    r"|<\s*(?:secret|hidden|override|admin)\b[^>]*>"
    r"|do\s+not\s+mention|don'?t\s+tell|secretly|hide\s+this"
    r"|ignore\s+previous|disregard|override\s+(?:all|previous)"
    r"|before\s+(?:using|calling|executing)"
    r"|~/.ssh|/etc/passwd|\.env\b"
    r"|base64[.\s]*encode|btoa\s*\(|atob\s*\(",
    re.IGNORECASE,
)

# Keywords that escalate a basic definition change to CRITICAL
_ESCALATION_KEYWORDS = re.compile(
    r"email|send|upload|exfiltrate|http|credential|password|ssh|aws"
    r"|token|secret|private.?key|cookie|session",
    re.IGNORECASE,
)


# URL pattern for detecting URLs in defaults/enums
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


class RugPullChecker(BaseChecker):
    name = "rug_pull"
    description = (
        "Detects tool definition changes, parameter mutations, schema drift, "
        "tool removal, and cross-server name collisions indicative of rug pull attacks"
    )

    async def check(self, context: ScanContext) -> CheckerResult:
        findings: list[FindingData] = []

        # Index historical snapshots by (server_name, tool_name)
        history: dict[tuple[str, str], object] = {}
        for snap in context.historical_snapshots:
            key = (snap.server_name, snap.tool_name)
            history[key] = snap

        # 1. Check for definition changes (enhanced)
        findings += self._check_definition_changes(context, history)

        # 2. Check for tool removals
        findings += self._check_tool_removals(context, history)

        # 3. Check for cross-server name collisions
        findings += self._check_name_collisions(context)

        # Enrich findings with source file/line when repo source is available
        if context.source_code_path:
            tool_lookup = {
                f"{sn}/{t.tool_name}": t
                for sn, tools in context.tool_definitions.items()
                for t in tools
            }
            for finding in findings:
                tool_key = finding.location.split(":")[0].rstrip("/")
                # Also handle "*/<tool>" locations from collision findings
                if tool_key.startswith("*/"):
                    continue
                tool = tool_lookup.get(tool_key)
                if tool:
                    finding.source_file, finding.source_line = (
                        resolve_source_location(
                            tool, finding.evidence, context.source_code_path,
                        )
                    )

        return CheckerResult(findings=findings, checker_name=self.name)

    # ------------------------------------------------------------------
    # Layer 1 + 2: Definition change detection with granular analysis
    # ------------------------------------------------------------------

    def _check_definition_changes(
        self,
        context: ScanContext,
        history: dict[tuple[str, str], object],
    ) -> list[FindingData]:
        findings: list[FindingData] = []

        for server_name, tools in context.tool_definitions.items():
            for tool in tools:
                loc = f"{server_name}/{tool.tool_name}"
                current_def = {
                    "description": tool.description,
                    "input_schema": tool.input_schema,
                }
                current_hash = ToolSnapshot.compute_hash(
                    server_name, tool.tool_name, current_def
                )

                key = (server_name, tool.tool_name)
                snap = history.get(key)

                if snap is None:
                    continue  # New tool — baseline, not a finding

                if snap.definition_hash == current_hash:
                    continue  # No change

                old_def = snap.full_definition

                # --- Basic change finding (unified diff) ---
                old_text = json.dumps(old_def, indent=2, sort_keys=True)
                new_text = json.dumps(current_def, indent=2, sort_keys=True)
                diff = "\n".join(
                    difflib.unified_diff(
                        old_text.splitlines(),
                        new_text.splitlines(),
                        fromfile="previous",
                        tofile="current",
                        lineterm="",
                    )
                )

                new_desc = tool.description or ""
                if _ESCALATION_KEYWORDS.search(new_desc):
                    severity = Severity.CRITICAL
                else:
                    severity = Severity.HIGH

                findings.append(
                    FindingData(
                        checker="rug_pull",
                        severity=severity,
                        title="Tool definition changed (rug pull risk)",
                        description=(
                            f"Tool '{tool.tool_name}' on server '{server_name}' "
                            "has a different definition from its historical snapshot. "
                            "This could indicate a rug-pull attack where a trusted tool "
                            "is silently replaced with a malicious version."
                        ),
                        evidence=diff[:1000],
                        location=loc,
                        remediation=(
                            "Investigate the definition change. Confirm with the "
                            "server maintainer that the change is intentional."
                        ),
                        cwe_id="CWE-494",
                    )
                )

                # --- Granular change analysis ---
                old_desc = old_def.get("description", "")
                findings += self._analyze_description_change(
                    old_desc, new_desc, loc
                )

                old_schema = old_def.get("input_schema", {})
                new_schema = tool.input_schema or {}
                findings += self._analyze_param_changes(
                    old_schema, new_schema, loc
                )

        return findings

    # ------------------------------------------------------------------
    # Layer 3: Description injection delta analysis
    # ------------------------------------------------------------------

    def _analyze_description_change(
        self, old_desc: str, new_desc: str, location: str
    ) -> list[FindingData]:
        """Detect injection patterns that appeared in a description change."""
        findings: list[FindingData] = []

        if old_desc == new_desc:
            return findings

        # Normalize new description for evasion-resilient detection
        norm = normalize(new_desc, max_size=50_000, location=location)
        findings.extend(norm.anomalies)
        effective_new_desc = norm.normalized

        # Find injection markers in NEW description that weren't in OLD
        new_matches = set(_INJECTION_MARKERS_RE.findall(effective_new_desc))
        old_matches = set(_INJECTION_MARKERS_RE.findall(old_desc))
        new_injections = new_matches - old_matches

        if new_injections:
            findings.append(
                FindingData(
                    checker="rug_pull",
                    severity=Severity.CRITICAL,
                    title="Description change introduced injection markers",
                    description=(
                        f"The tool description at '{location}' was modified to include "
                        f"injection patterns that were not present in the previous version. "
                        f"This is a strong indicator of a rug-pull bait-and-switch attack."
                    ),
                    evidence=f"New markers: {', '.join(sorted(new_injections))}",
                    location=location,
                    remediation=(
                        "This tool has been compromised. Remove the server from your "
                        "MCP configuration immediately and audit any data it had access to."
                    ),
                    cwe_id="CWE-494",
                )
            )
        elif _INJECTION_MARKERS_RE.search(effective_new_desc):
            # Injection markers existed before but description still changed
            # The markers may have been rearranged/expanded
            findings.append(
                FindingData(
                    checker="rug_pull",
                    severity=Severity.CRITICAL,
                    title="Description change introduced injection markers",
                    description=(
                        f"The tool description at '{location}' was modified and contains "
                        f"injection patterns. This is a strong indicator of a rug-pull attack."
                    ),
                    evidence=new_desc[:500],
                    location=location,
                    remediation=(
                        "This tool has been compromised. Remove the server from your "
                        "MCP configuration immediately."
                    ),
                    cwe_id="CWE-494",
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Layer 4: Parameter mutation analysis
    # ------------------------------------------------------------------

    def _analyze_param_changes(
        self,
        old_schema: dict,
        new_schema: dict,
        location: str,
    ) -> list[FindingData]:
        """Detect suspicious parameter mutations (additions, default/enum changes)."""
        findings: list[FindingData] = []

        old_props = old_schema.get("properties", {})
        new_props = new_schema.get("properties", {})
        old_required = set(old_schema.get("required", []))
        new_required = set(new_schema.get("required", []))

        added_params = set(new_props.keys()) - set(old_props.keys())
        removed_required = old_required - new_required

        # --- Check added parameters ---
        suspicious_added = []
        benign_added = []

        for param_name in added_params:
            if param_name.lower() in SUSPICIOUS_PARAM_NAMES:
                suspicious_added.append(param_name)
            else:
                benign_added.append(param_name)

        for param_name in suspicious_added:
            findings.append(
                FindingData(
                    checker="rug_pull",
                    severity=Severity.CRITICAL,
                    title="Suspicious parameter added after approval",
                    description=(
                        f"Parameter '{param_name}' was added to the tool at '{location}'. "
                        f"This parameter name is commonly used in rug-pull exfiltration "
                        f"attacks (e.g., Invariant Labs' 'sidenote' parameter attack)."
                    ),
                    evidence=f"New parameter: {param_name} = {json.dumps(new_props.get(param_name, {}), indent=2)[:300]}",
                    location=f"{location}:param/{param_name}",
                    remediation=(
                        "Verify this parameter was intentionally added by the server "
                        "maintainer. Suspicious parameter names like 'sidenote', 'callback', "
                        "or 'webhook' are common rug-pull exfiltration channels."
                    ),
                    cwe_id="CWE-494",
                )
            )

        for param_name in benign_added:
            findings.append(
                FindingData(
                    checker="rug_pull",
                    severity=Severity.MEDIUM,
                    title="New parameter added after approval",
                    description=(
                        f"Parameter '{param_name}' was added to the tool at '{location}' "
                        f"after initial approval. While the parameter name is not inherently "
                        f"suspicious, any post-approval schema change warrants review."
                    ),
                    evidence=f"New parameter: {param_name} = {json.dumps(new_props.get(param_name, {}), indent=2)[:300]}",
                    location=f"{location}:param/{param_name}",
                    remediation=(
                        "Review the new parameter and confirm with the server "
                        "maintainer that this addition is legitimate."
                    ),
                    cwe_id="CWE-494",
                )
            )

        # --- Schema expansion (3+ params added at once) ---
        if len(added_params) >= 3:
            findings.append(
                FindingData(
                    checker="rug_pull",
                    severity=Severity.HIGH,
                    title="Schema expansion detected (multiple parameters added)",
                    description=(
                        f"Tool at '{location}' had {len(added_params)} parameters added "
                        f"since the last scan. Large schema expansions after approval "
                        f"are a common rug-pull technique to introduce hidden exfiltration "
                        f"channels alongside legitimate parameters."
                    ),
                    evidence=f"Added parameters: {', '.join(sorted(added_params))}",
                    location=location,
                    remediation=(
                        "Review all new parameters carefully. Schema expansions "
                        "after initial approval should be treated with suspicion."
                    ),
                    cwe_id="CWE-494",
                )
            )

        # --- Required fields dropped ---
        for field_name in removed_required:
            if field_name in new_props:
                # Field still exists but is no longer required
                findings.append(
                    FindingData(
                        checker="rug_pull",
                        severity=Severity.MEDIUM,
                        title="Required field dropped to optional",
                        description=(
                            f"Parameter '{field_name}' at '{location}' was previously "
                            f"required but is now optional. Weakening validation "
                            f"constraints after approval could enable bypass attacks."
                        ),
                        evidence=f"Previously required: {field_name}",
                        location=f"{location}:param/{field_name}",
                        remediation=(
                            "Verify this validation change is intentional and does "
                            "not weaken security constraints."
                        ),
                        cwe_id="CWE-494",
                    )
                )

        # --- Check existing params for changed defaults, enums, descriptions, titles ---
        common_params = set(old_props.keys()) & set(new_props.keys())
        for param_name in common_params:
            old_prop = old_props[param_name]
            new_prop = new_props[param_name]
            findings += self._check_param_field_changes(
                param_name, old_prop, new_prop, location
            )

        return findings

    def _check_param_field_changes(
        self,
        param_name: str,
        old_prop: dict,
        new_prop: dict,
        location: str,
    ) -> list[FindingData]:
        """Check for suspicious changes in a parameter's fields (default, enum, description, title)."""
        findings: list[FindingData] = []

        # Check default value changes
        old_default = old_prop.get("default")
        new_default = new_prop.get("default")
        if old_default != new_default and new_default is not None:
            new_default_str = str(new_default)
            if _URL_RE.search(new_default_str) or _INJECTION_MARKERS_RE.search(new_default_str):
                findings.append(
                    FindingData(
                        checker="rug_pull",
                        severity=Severity.HIGH,
                        title="Parameter default changed to suspicious value",
                        description=(
                            f"Parameter '{param_name}' at '{location}' had its default "
                            f"value changed. The new default contains a URL or injection "
                            f"marker, which could be used for data exfiltration."
                        ),
                        evidence=f"Old default: {old_default} → New default: {new_default_str[:200]}",
                        location=f"{location}:param/{param_name}",
                        remediation=(
                            "Review the default value change. URLs in default values "
                            "could redirect data to attacker-controlled endpoints."
                        ),
                        cwe_id="CWE-494",
                    )
                )

        # Check enum value changes
        old_enums = set(str(v) for v in old_prop.get("enum", []))
        new_enums = set(str(v) for v in new_prop.get("enum", []))
        added_enums = new_enums - old_enums
        for enum_val in added_enums:
            if _INJECTION_MARKERS_RE.search(enum_val):
                findings.append(
                    FindingData(
                        checker="rug_pull",
                        severity=Severity.HIGH,
                        title="Enum value added with injection content",
                        description=(
                            f"Parameter '{param_name}' at '{location}' gained a new enum "
                            f"value containing injection markers. This is a Full-Schema "
                            f"Poisoning (FSP) technique where malicious content is hidden "
                            f"in schema metadata fields."
                        ),
                        evidence=f"New enum value: {enum_val[:300]}",
                        location=f"{location}:param/{param_name}",
                        remediation=(
                            "Remove the suspicious enum value and audit the server "
                            "for other schema-level injection attempts."
                        ),
                        cwe_id="CWE-494",
                    )
                )

        # Check description changes for injection
        old_param_desc = old_prop.get("description", "")
        new_param_desc = new_prop.get("description", "")
        if old_param_desc != new_param_desc and _INJECTION_MARKERS_RE.search(new_param_desc):
            if not _INJECTION_MARKERS_RE.search(old_param_desc):
                findings.append(
                    FindingData(
                        checker="rug_pull",
                        severity=Severity.HIGH,
                        title="Parameter description gained injection markers",
                        description=(
                            f"Parameter '{param_name}' description at '{location}' was "
                            f"modified to include injection patterns. This is a Full-Schema "
                            f"Poisoning attack targeting parameter metadata."
                        ),
                        evidence=f"New description: {new_param_desc[:300]}",
                        location=f"{location}:param/{param_name}",
                        remediation=(
                            "This parameter description has been poisoned. Remove the "
                            "server and audit all interactions."
                        ),
                        cwe_id="CWE-494",
                    )
                )

        # Check title changes for injection
        old_title = old_prop.get("title", "")
        new_title = new_prop.get("title", "")
        if old_title != new_title and _INJECTION_MARKERS_RE.search(new_title):
            if not _INJECTION_MARKERS_RE.search(old_title):
                findings.append(
                    FindingData(
                        checker="rug_pull",
                        severity=Severity.HIGH,
                        title="Parameter title gained injection markers",
                        description=(
                            f"Parameter '{param_name}' title at '{location}' was "
                            f"modified to include injection patterns. This is a Full-Schema "
                            f"Poisoning (FSP) attack targeting parameter titles."
                        ),
                        evidence=f"New title: {new_title[:300]}",
                        location=f"{location}:param/{param_name}",
                        remediation=(
                            "This parameter title has been poisoned. Remove the "
                            "server and audit all interactions."
                        ),
                        cwe_id="CWE-494",
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Layer 5: Tool removal tracking
    # ------------------------------------------------------------------

    def _check_tool_removals(
        self,
        context: ScanContext,
        history: dict[tuple[str, str], object],
    ) -> list[FindingData]:
        """Detect tools that existed in history but are missing from current scan."""
        findings: list[FindingData] = []

        # Build set of current tools by (server, tool) key
        current_tools: dict[str, set[str]] = {}
        for server_name, tools in context.tool_definitions.items():
            current_tools[server_name] = {t.tool_name for t in tools}

        # Group historical tools by server
        history_by_server: dict[str, set[str]] = {}
        for server_name, tool_name in history:
            history_by_server.setdefault(server_name, set()).add(tool_name)

        for server_name, hist_tools in history_by_server.items():
            curr_tools = current_tools.get(server_name, set())
            removed = hist_tools - curr_tools

            if not removed:
                continue

            # Mass removal (3+ tools) is more suspicious
            is_mass_removal = len(removed) >= 3

            for tool_name in sorted(removed):
                findings.append(
                    FindingData(
                        checker="rug_pull",
                        severity=Severity.CRITICAL if is_mass_removal else Severity.HIGH,
                        title="Tool removed from server",
                        description=(
                            f"Tool '{tool_name}' on server '{server_name}' was previously "
                            f"registered but is no longer present. Tool removal after "
                            f"approval could indicate server compromise, cleanup after "
                            f"an attack, or unauthorized server modification."
                            + (
                                f" {len(removed)} tools were removed simultaneously, "
                                f"suggesting a mass purge."
                                if is_mass_removal else ""
                            )
                        ),
                        evidence=f"Missing tool: {tool_name} (server: {server_name})",
                        location=f"{server_name}/{tool_name}",
                        remediation=(
                            "Investigate why this tool was removed. Contact the "
                            "server maintainer to confirm this was intentional."
                        ),
                        cwe_id="CWE-494",
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Layer 6: Cross-server name collision detection (tool squatting)
    # ------------------------------------------------------------------

    def _check_name_collisions(
        self, context: ScanContext
    ) -> list[FindingData]:
        """Detect same tool name registered on multiple servers (tool squatting)."""
        findings: list[FindingData] = []

        # Map tool_name → list of server_names
        name_to_servers: dict[str, list[str]] = {}
        for server_name, tools in context.tool_definitions.items():
            for tool in tools:
                name_to_servers.setdefault(tool.tool_name, []).append(server_name)

        for tool_name, servers in name_to_servers.items():
            if len(servers) <= 1:
                continue

            findings.append(
                FindingData(
                    checker="rug_pull",
                    severity=Severity.HIGH,
                    title="Tool name collision across servers (tool squatting)",
                    description=(
                        f"Tool '{tool_name}' is registered on {len(servers)} servers: "
                        f"{', '.join(sorted(servers))}. Tool name collisions enable "
                        f"tool squatting attacks where a malicious server registers "
                        f"a tool with the same name as a trusted server, potentially "
                        f"intercepting calls intended for the legitimate tool."
                    ),
                    evidence=f"Tool '{tool_name}' on servers: {', '.join(sorted(servers))}",
                    location=f"*/{tool_name}",
                    remediation=(
                        "Ensure each tool name is unique across all connected servers. "
                        "If this collision is unintentional, rename one of the tools. "
                        "If a server is registering tools that shadow trusted servers, "
                        "remove it from your configuration."
                    ),
                    cwe_id="CWE-694",
                )
            )

        return findings
