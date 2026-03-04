"""OWASP LLM Top 10 (2025) and OWASP MCP Top 10 compliance mapping."""

from __future__ import annotations
from dataclasses import dataclass
from mcp_scanner.checkers.base import FindingData


@dataclass(frozen=True)
class ComplianceRef:
    framework: str
    identifier: str
    name: str


LLM01 = ComplianceRef("OWASP_LLM_2025", "LLM01", "Prompt Injection")
LLM02 = ComplianceRef("OWASP_LLM_2025", "LLM02", "Sensitive Information Disclosure")
LLM04 = ComplianceRef("OWASP_LLM_2025", "LLM04", "Data and Model Poisoning")
LLM05 = ComplianceRef("OWASP_LLM_2025", "LLM05", "Improper Output Handling")
LLM06 = ComplianceRef("OWASP_LLM_2025", "LLM06", "Excessive Agency")

MCP01 = ComplianceRef("OWASP_MCP_2025", "MCP01", "Token Mismanagement & Secret Exposure")
MCP02 = ComplianceRef("OWASP_MCP_2025", "MCP02", "Excessive Privilege/Scope")
MCP03 = ComplianceRef("OWASP_MCP_2025", "MCP03", "Tool Poisoning")
MCP04 = ComplianceRef("OWASP_MCP_2025", "MCP04", "Command Injection")
MCP05 = ComplianceRef("OWASP_MCP_2025", "MCP05", "Context Over-Sharing")

_MAP: dict[tuple[str, str], list[ComplianceRef]] = {
    ("tool_poisoning", "CWE-1059"): [LLM01, MCP03],
    ("tool_poisoning", "CWE-451"):  [LLM01, MCP03],
    ("tool_poisoning", "CWE-77"):   [LLM01, MCP04],
    ("tool_poisoning", "CWE-78"):   [LLM01, MCP04],
    ("tool_poisoning", "CWE-200"):  [LLM02, MCP05],
    ("tool_poisoning", "CWE-506"):  [LLM04, MCP03],
    ("tool_poisoning", "CWE-22"):   [LLM02, MCP04],
    ("tool_poisoning", "CWE-20"):   [LLM06, MCP02],
    ("tool_poisoning", "CWE-290"):  [LLM01, MCP03],
    ("data_exfiltration", "CWE-200"): [LLM02, MCP05],
    ("data_exfiltration", "CWE-451"): [LLM02, MCP05],
    ("supply_chain", "*"): [LLM05, MCP03],
    ("rug_pull", "*"): [LLM04, MCP03],
    ("permission_scope", "*"): [LLM06, MCP02],
    ("infra_security", "CWE-798"): [LLM02, MCP01],
    ("infra_security", "CWE-319"): [LLM02, MCP01],
    ("normalizer", "CWE-451"): [LLM01],
    ("normalizer", "CWE-506"): [LLM01],
    ("normalizer", "CWE-77"):  [LLM01],
    ("normalizer", "CWE-400"): [LLM01],
}


def enrich_compliance(findings: list[FindingData]) -> None:
    for finding in findings:
        key = (finding.checker, finding.cwe_id)
        refs = _MAP.get(key)
        if refs is None:
            refs = _MAP.get((finding.checker, "*"))
        if refs:
            finding.compliance_refs = list(refs)
