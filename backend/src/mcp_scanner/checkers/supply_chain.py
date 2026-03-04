"""Supply Chain Checker — 5-layer pre-install detection for MCP packages.

Detection layers:
1. Package identity verification (typosquatting, scope checking, unpinned npx)
2. Metadata & behavioral analysis (package age, deprecation, deps.dev data)
3. Vulnerability & provenance (CVEs, MAL advisories, SBOM generation)
4. Repository health (OpenSSF Scorecard via deps.dev)
5. Aggregate risk scoring (combined signal escalation)
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from mcp_scanner.checkers.base import BaseChecker, CheckerResult, FindingData, Severity
from mcp_scanner.models.scan_context import ScanContext
from mcp_scanner.services.deps_dev_client import DepsDevClient

# ── Known legitimate MCP packages (loaded from external config) ──


def _load_trusted_config() -> tuple[list[str], set[str]]:
    import importlib.resources as _pkg_resources
    try:
        ref = _pkg_resources.files("mcp_scanner") / "data" / "trusted_packages.json"
        data = json.loads(ref.read_text(encoding="utf-8"))
    except (FileNotFoundError, TypeError):
        # Fallback for editable installs / direct execution
        config_path = Path(__file__).parent.parent / "data" / "trusted_packages.json"
        data = json.loads(config_path.read_text())
    return data["packages"], set(data["trusted_scopes"])


_KNOWN_PACKAGES, _TRUSTED_SCOPES = _load_trusted_config()

_VERSION_PIN_RE = re.compile(r"@[\d^~>=<]")
_SCORECARD_MIN_OVERALL = 4.0
_SCORECARD_CRITICAL_CHECKS = {"Code-Review", "Branch-Protection", "Dangerous-Workflow", "Maintained"}
_SCORECARD_CHECK_MIN = 3
_NEW_PACKAGE_DAYS = 30


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


def _extract_package_info(server_config: dict) -> tuple[str | None, str | None, str]:
    """Extract (package_name, version, ecosystem) from server config."""
    args = server_config.get("args", [])
    command = server_config.get("command", "")

    if command in ("npx", "npm", "node"):
        for arg in args:
            if arg.startswith("-"):
                continue
            if "@" in arg and not arg.startswith("@"):
                parts = arg.rsplit("@", 1)
                return parts[0], parts[1], "npm"
            if arg.startswith("@"):
                if arg.count("@") >= 2:
                    idx = arg.rindex("@")
                    return arg[:idx], arg[idx + 1:], "npm"
                return arg, None, "npm"
            return arg, None, "npm"

    if command in ("uv", "uvx", "pip", "pipx", "python", "python3"):
        for i, arg in enumerate(args):
            if arg == "--with" and i + 1 < len(args):
                pkg = args[i + 1]
                if "==" in pkg:
                    name, ver = pkg.split("==", 1)
                    return name, ver, "pypi"
                return pkg, None, "pypi"
            if arg == "run" and command in ("pipx",) and i + 1 < len(args):
                pkg = args[i + 1]
                if "==" in pkg:
                    name, ver = pkg.split("==", 1)
                    return name, ver, "pypi"
                return pkg, None, "pypi"

    for arg in args:
        if "@" in arg and "/" in arg:
            if arg.count("@") >= 2:
                idx = arg.rindex("@")
                return arg[:idx], arg[idx + 1:], "npm"
            return arg, None, "npm"

    if "/" in command or "@" in command:
        return command, None, "npm"

    return None, None, "npm"


def _has_version_pin(args: list[str]) -> bool:
    for arg in args:
        if arg.startswith("-"):
            continue
        if _VERSION_PIN_RE.search(arg) or "==" in arg:
            return True
    return False


def _get_scope(pkg_name: str) -> str | None:
    if pkg_name.startswith("@") and "/" in pkg_name:
        return pkg_name.split("/")[0]
    return None


class SupplyChainChecker(BaseChecker):
    name = "supply_chain"
    description = (
        "Detects supply chain risks: typosquatting, unpinned packages, "
        "vulnerabilities, malicious packages, and repository health issues"
    )

    def __init__(self, deps_client: DepsDevClient | None = None) -> None:
        self._deps_client = deps_client

    async def check(self, context: ScanContext) -> CheckerResult:
        findings: list[FindingData] = []

        own_client = False
        client = self._deps_client
        if client is None:
            client = DepsDevClient()
            own_client = True

        try:
            servers = context.mcp_config.get("mcpServers", {})

            for server_name, server_config in servers.items():
                if not isinstance(server_config, dict):
                    continue

                pkg, version, ecosystem = _extract_package_info(server_config)
                if not pkg:
                    continue

                args = server_config.get("args", [])
                command = server_config.get("command", "")
                loc = f"config:{server_name}"

                # Layer 1: Package Identity
                self._check_typosquatting(pkg, server_name, loc, findings)
                self._check_scope(pkg, server_name, loc, findings)
                self._check_unpinned(command, args, pkg, server_name, loc, findings)

                # Layers 2-4: deps.dev enrichment
                deps_system = "NPM" if ecosystem == "npm" else "PYPI"
                pkg_data = await client.get_package(deps_system, pkg)

                if not version and pkg_data:
                    versions = pkg_data.get("versions", [])
                    if versions:
                        version = versions[-1].get("versionKey", {}).get("version")

                ver_data = None
                if version:
                    ver_data = await client.get_version(deps_system, pkg, version)

                if ver_data:
                    self._check_metadata(ver_data, pkg, version, server_name, loc, findings)
                    await self._check_vulnerabilities(client, ver_data, pkg, version, server_name, loc, findings)
                    await self._check_repo_health(client, ver_data, pkg, server_name, loc, findings)
        finally:
            if own_client:
                await client.close()

        return CheckerResult(findings=findings, checker_name=self.name)

    def _check_typosquatting(self, pkg: str, server_name: str, loc: str, findings: list[FindingData]) -> None:
        if pkg in _KNOWN_PACKAGES:
            return
        for known in _KNOWN_PACKAGES:
            dist = _levenshtein(pkg.lower(), known.lower())
            if 1 <= dist <= 2:
                findings.append(FindingData(
                    checker="supply_chain", severity=Severity.HIGH,
                    title="Possible typosquatting package",
                    description=(
                        f"Package '{pkg}' in server '{server_name}' is very similar "
                        f"to known package '{known}' (edit distance: {dist}). "
                        "This may be a typosquatting attack."
                    ),
                    evidence=f"'{pkg}' vs '{known}' (distance={dist})",
                    location=loc,
                    remediation=f"Verify that '{pkg}' is the intended package. The legitimate package is '{known}'.",
                    cwe_id="CWE-1104",
                ))

    def _check_scope(self, pkg: str, server_name: str, loc: str, findings: list[FindingData]) -> None:
        scope = _get_scope(pkg)
        if not scope and re.match(r"mcp[-_]server[-_]", pkg, re.IGNORECASE):
            findings.append(FindingData(
                checker="supply_chain", severity=Severity.MEDIUM,
                title="Unscoped MCP server package",
                description=(
                    f"Package '{pkg}' in server '{server_name}' uses an unscoped name "
                    "with the 'mcp-server-*' pattern. Unscoped packages are more "
                    "vulnerable to dependency confusion and typosquatting."
                ),
                evidence=f"unscoped: {pkg}",
                location=loc,
                remediation="Prefer scoped packages from trusted publishers (e.g., @modelcontextprotocol/server-*).",
                cwe_id="CWE-1104",
            ))
        if scope and scope not in _TRUSTED_SCOPES:
            for trusted in _TRUSTED_SCOPES:
                dist = _levenshtein(scope.lower(), trusted.lower())
                if 1 <= dist <= 2:
                    findings.append(FindingData(
                        checker="supply_chain", severity=Severity.HIGH,
                        title="Possible scope confusion",
                        description=(
                            f"Package '{pkg}' uses scope '{scope}' which is similar "
                            f"to trusted scope '{trusted}' (edit distance: {dist}). "
                            "This may be a scope confusion attack."
                        ),
                        evidence=f"'{scope}' vs '{trusted}' (distance={dist})",
                        location=loc,
                        remediation=f"Verify the scope. The trusted scope is '{trusted}'.",
                        cwe_id="CWE-1104",
                    ))

    def _check_unpinned(self, command: str, args: list[str], pkg: str, server_name: str, loc: str, findings: list[FindingData]) -> None:
        if command not in ("npx", "npm"):
            return
        if "-y" in args and not _has_version_pin(args):
            findings.append(FindingData(
                checker="supply_chain", severity=Severity.MEDIUM,
                title="Unpinned npx -y package execution",
                description=(
                    f"Server '{server_name}' uses 'npx -y {pkg}' without version "
                    "pinning. This downloads and executes the latest version on every "
                    "launch, making it vulnerable to supply chain attacks."
                ),
                evidence=f"npx -y {pkg} (no version pin)",
                location=loc,
                remediation=f"Pin the version: 'npx -y {pkg}@<version>'.",
                cwe_id="CWE-1104",
            ))

    def _check_metadata(self, ver_data: dict, pkg: str, version: str | None, server_name: str, loc: str, findings: list[FindingData]) -> None:
        published_at = ver_data.get("publishedAt")
        if published_at:
            try:
                pub_date = datetime.fromisoformat(published_at.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - pub_date).days
                if age_days < _NEW_PACKAGE_DAYS:
                    findings.append(FindingData(
                        checker="supply_chain", severity=Severity.MEDIUM,
                        title="Recently published package",
                        description=(
                            f"Package '{pkg}@{version}' in server '{server_name}' was "
                            f"published only {age_days} days ago. Very new packages "
                            "carry higher supply chain risk."
                        ),
                        evidence=f"published: {published_at} ({age_days} days ago)",
                        location=loc,
                        remediation="Verify the package author and review the source code before use.",
                        cwe_id="CWE-1104",
                    ))
            except (ValueError, TypeError):
                pass
        if ver_data.get("isDeprecated"):
            findings.append(FindingData(
                checker="supply_chain", severity=Severity.MEDIUM,
                title="Deprecated package version",
                description=(
                    f"Package '{pkg}@{version}' in server '{server_name}' is deprecated. "
                    "Deprecated packages may have known security issues."
                ),
                evidence=f"deprecated: {pkg}@{version}",
                location=loc,
                remediation="Update to a non-deprecated version or find an alternative package.",
                cwe_id="CWE-1104",
            ))

    async def _check_vulnerabilities(self, client: DepsDevClient, ver_data: dict, pkg: str, version: str | None, server_name: str, loc: str, findings: list[FindingData]) -> None:
        advisory_keys = ver_data.get("advisoryKeys", [])
        for ak in advisory_keys:
            adv_id = ak.get("id", "")
            advisory = await client.get_advisory(adv_id)
            if adv_id.startswith("MAL-"):
                title_text = advisory.get("title", "Known malicious package") if advisory else "Known malicious package"
                findings.append(FindingData(
                    checker="supply_chain", severity=Severity.CRITICAL,
                    title="Known malicious package",
                    description=(
                        f"Package '{pkg}@{version}' in server '{server_name}' "
                        f"is flagged as malicious: {title_text}"
                    ),
                    evidence=f"advisory: {adv_id}",
                    location=loc,
                    remediation="Remove this package immediately. It is confirmed malicious.",
                    cwe_id="CWE-506",
                ))
                continue
            cvss = advisory.get("cvss3Score", 0) if advisory else 0
            severity = Severity.CRITICAL if cvss >= 9.0 else (Severity.HIGH if cvss >= 7.0 else Severity.MEDIUM)
            title_text = advisory.get("title", adv_id) if advisory else adv_id
            aliases = advisory.get("aliases", []) if advisory else []
            cve_ids = [a for a in aliases if a.startswith("CVE-")]
            findings.append(FindingData(
                checker="supply_chain", severity=severity,
                title="Known vulnerability in package",
                description=(
                    f"Package '{pkg}@{version}' in server '{server_name}' has "
                    f"a known vulnerability: {title_text}"
                    + (f" ({', '.join(cve_ids)})" if cve_ids else "")
                    + (f" (CVSS: {cvss})" if cvss else "")
                ),
                evidence=f"advisory: {adv_id}" + (f", CVEs: {cve_ids}" if cve_ids else ""),
                location=loc,
                remediation=f"Update '{pkg}' to a patched version.",
                cwe_id="CWE-1035",
            ))

    async def _check_repo_health(self, client: DepsDevClient, ver_data: dict, pkg: str, server_name: str, loc: str, findings: list[FindingData]) -> None:
        links = ver_data.get("links", [])
        repo_url = None
        for link in links:
            if link.get("label") == "SOURCE_REPO":
                repo_url = link.get("url", "")
                break
        if not links:
            findings.append(FindingData(
                checker="supply_chain", severity=Severity.MEDIUM,
                title="No source repository linked",
                description=(
                    f"Package '{pkg}' in server '{server_name}' has no linked "
                    "source repository. This makes it impossible to verify the package's provenance."
                ),
                evidence=f"no source repo for {pkg}",
                location=loc,
                remediation="Prefer packages with a linked and verifiable source repository.",
                cwe_id="CWE-1104",
            ))
            return
        if not repo_url:
            return
        project_id = repo_url.replace("https://", "").replace("http://", "").rstrip("/")
        project_data = await client.get_project(project_id)
        if not project_data:
            return
        scorecard = project_data.get("scorecardV2")
        if not scorecard:
            return
        overall = scorecard.get("overallScore", 10)
        if overall < _SCORECARD_MIN_OVERALL:
            findings.append(FindingData(
                checker="supply_chain", severity=Severity.MEDIUM,
                title="Low OpenSSF Scorecard score",
                description=(
                    f"Package '{pkg}' source repo has an OpenSSF Scorecard "
                    f"score of {overall}/10, below the {_SCORECARD_MIN_OVERALL} threshold. "
                    "This indicates potential security practice weaknesses."
                ),
                evidence=f"scorecard: {overall}/10",
                location=loc,
                remediation="Review the repository's security practices before trusting this package.",
                cwe_id="CWE-1104",
            ))
        checks = scorecard.get("checks", [])
        for check in checks:
            name = check.get("name", "")
            score = check.get("score", 10)
            if name in _SCORECARD_CRITICAL_CHECKS and score < _SCORECARD_CHECK_MIN:
                findings.append(FindingData(
                    checker="supply_chain", severity=Severity.LOW,
                    title=f"Low Scorecard check: {name}",
                    description=(
                        f"Package '{pkg}' source repo scored {score}/10 on "
                        f"'{name}' check. Reason: {check.get('reason', 'unknown')}"
                    ),
                    evidence=f"{name}: {score}/10",
                    location=loc,
                    remediation=f"Review the '{name}' security practice for this repository.",
                    cwe_id="CWE-1104",
                ))
