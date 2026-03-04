from mcp_scanner.checkers.base import FindingData, Severity
from mcp_scanner.checkers.compliance import ComplianceRef, enrich_compliance


def _finding(checker: str, cwe_id: str) -> FindingData:
    return FindingData(
        checker=checker, severity=Severity.HIGH, title="test",
        description="test", evidence="test", location="test", cwe_id=cwe_id,
    )


def test_tool_poisoning_maps_to_mcp03():
    f = _finding("tool_poisoning", "CWE-1059")
    enrich_compliance([f])
    assert any(r.identifier == "MCP03" for r in f.compliance_refs)


def test_tool_poisoning_shell_maps_to_mcp04():
    f = _finding("tool_poisoning", "CWE-78")
    enrich_compliance([f])
    assert any(r.identifier == "MCP04" for r in f.compliance_refs)


def test_supply_chain_maps_to_llm05():
    f = _finding("supply_chain", "CWE-506")
    enrich_compliance([f])
    assert any(r.identifier == "LLM05" for r in f.compliance_refs)


def test_data_exfiltration_maps_to_mcp05():
    f = _finding("data_exfiltration", "CWE-200")
    enrich_compliance([f])
    assert any(r.identifier == "MCP05" for r in f.compliance_refs)


def test_infra_security_maps_to_mcp01():
    f = _finding("infra_security", "CWE-798")
    enrich_compliance([f])
    assert any(r.identifier == "MCP01" for r in f.compliance_refs)


def test_unknown_checker_gets_no_refs():
    f = _finding("unknown_checker", "CWE-999")
    enrich_compliance([f])
    assert f.compliance_refs == []


def test_normalizer_findings_get_mapped():
    f = _finding("normalizer", "CWE-451")
    enrich_compliance([f])
    assert any(r.identifier == "LLM01" for r in f.compliance_refs)


def test_multiple_findings_enriched():
    findings = [
        _finding("tool_poisoning", "CWE-200"),
        _finding("supply_chain", "CWE-506"),
        _finding("data_exfiltration", "CWE-200"),
    ]
    enrich_compliance(findings)
    assert all(len(f.compliance_refs) > 0 for f in findings)


def test_compliance_ref_fields():
    f = _finding("tool_poisoning", "CWE-1059")
    enrich_compliance([f])
    ref = f.compliance_refs[0]
    assert ref.framework in ("OWASP_LLM_2025", "OWASP_MCP_2025")
    assert ref.identifier
    assert ref.name
