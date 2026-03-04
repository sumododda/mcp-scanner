from mcp_scanner.checkers.base import FindingData, Severity, deduplicate_findings


def _finding(
    checker: str = "tool_poisoning",
    severity: Severity = Severity.HIGH,
    title: str = "Test finding",
    cwe_id: str = "CWE-77",
    location: str = "srv/tool:description",
    evidence: str = "test evidence",
) -> FindingData:
    return FindingData(
        checker=checker,
        severity=severity,
        title=title,
        description="desc",
        evidence=evidence,
        location=location,
        cwe_id=cwe_id,
    )


def test_dedup_keeps_highest_severity():
    findings = [
        _finding(severity=Severity.MEDIUM, title="low sev"),
        _finding(severity=Severity.CRITICAL, title="high sev"),
        _finding(severity=Severity.HIGH, title="mid sev"),
    ]
    result = deduplicate_findings(findings)
    assert len(result) == 1
    assert result[0].severity == Severity.CRITICAL


def test_dedup_merges_evidence():
    findings = [
        _finding(severity=Severity.CRITICAL, evidence="evidence A"),
        _finding(severity=Severity.HIGH, evidence="evidence B"),
    ]
    result = deduplicate_findings(findings)
    assert len(result) == 1
    assert "evidence A" in result[0].evidence
    assert "evidence B" in result[0].evidence


def test_dedup_different_cwe_kept_separate():
    findings = [
        _finding(cwe_id="CWE-77"),
        _finding(cwe_id="CWE-451"),
    ]
    result = deduplicate_findings(findings)
    assert len(result) == 2


def test_dedup_different_location_kept_separate():
    findings = [
        _finding(location="srv/tool:description"),
        _finding(location="srv/tool:param:name"),
    ]
    result = deduplicate_findings(findings)
    assert len(result) == 2


def test_dedup_normalized_suffix_merged():
    findings = [
        _finding(location="srv/tool:description"),
        _finding(location="srv/tool:description:normalized"),
    ]
    result = deduplicate_findings(findings)
    assert len(result) == 1


def test_dedup_cap_per_location():
    findings = [
        _finding(cwe_id=f"CWE-{i}", location="srv/tool:description")
        for i in range(20)
    ]
    result = deduplicate_findings(findings, max_per_location=10)
    same_loc = [f for f in result if f.location.startswith("srv/tool:description")]
    assert len(same_loc) <= 10


def test_dedup_sorted_by_severity():
    findings = [
        _finding(severity=Severity.LOW, cwe_id="CWE-1"),
        _finding(severity=Severity.CRITICAL, cwe_id="CWE-2"),
        _finding(severity=Severity.MEDIUM, cwe_id="CWE-3"),
    ]
    result = deduplicate_findings(findings)
    severities = [f.severity for f in result]
    assert severities == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]


def test_dedup_empty_list():
    assert deduplicate_findings([]) == []


def test_dedup_single_finding():
    f = _finding()
    assert deduplicate_findings([f]) == [f]


# --- Cross-tier deduplication tests ---


def test_cross_tier_dedup_same_tool_same_issue():
    """Findings from different checkers about same tool + CWE merge into one."""
    from mcp_scanner.checkers.base import deduplicate_across_tiers

    findings = [
        FindingData(
            checker="tool_poisoning",
            severity=Severity.HIGH,
            title="Exfiltration pattern",
            description="desc",
            evidence="send data to",
            location="srv/tool:description",
            cwe_id="CWE-200",
        ),
        FindingData(
            checker="data_exfiltration",
            severity=Severity.CRITICAL,
            title="Known exfil URL",
            description="desc",
            evidence="webhook.site",
            location="srv/tool:description",
            cwe_id="CWE-200",
        ),
    ]
    result = deduplicate_across_tiers(findings)
    assert len(result) == 1
    assert result[0].severity == Severity.CRITICAL
    assert "webhook.site" in result[0].evidence
    assert "send data to" in result[0].evidence


def test_cross_tier_dedup_different_tools_kept():
    """Findings about different tools are NOT merged."""
    from mcp_scanner.checkers.base import deduplicate_across_tiers

    findings = [
        FindingData(
            checker="tool_poisoning",
            severity=Severity.HIGH,
            title="Issue A",
            description="desc",
            evidence="ev1",
            location="srv/tool_a:description",
            cwe_id="CWE-200",
        ),
        FindingData(
            checker="data_exfiltration",
            severity=Severity.CRITICAL,
            title="Issue B",
            description="desc",
            evidence="ev2",
            location="srv/tool_b:description",
            cwe_id="CWE-200",
        ),
    ]
    result = deduplicate_across_tiers(findings)
    assert len(result) == 2


def test_cross_tier_dedup_different_cwes_kept():
    """Same tool but different CWE IDs are NOT merged."""
    from mcp_scanner.checkers.base import deduplicate_across_tiers

    findings = [
        FindingData(
            checker="tool_poisoning",
            severity=Severity.HIGH,
            title="Issue A",
            description="desc",
            evidence="ev1",
            location="srv/tool:description",
            cwe_id="CWE-200",
        ),
        FindingData(
            checker="data_exfiltration",
            severity=Severity.HIGH,
            title="Issue B",
            description="desc",
            evidence="ev2",
            location="srv/tool:description",
            cwe_id="CWE-78",
        ),
    ]
    result = deduplicate_across_tiers(findings)
    assert len(result) == 2
