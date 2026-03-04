"""Tests for SBOM export and vulnerability API endpoints."""

from __future__ import annotations

import json
import uuid

import pytest

from mcp_scanner.api.schemas import VulnerabilityResponse, VulnerabilitySummary


# ---------------------------------------------------------------------------
# Schema tests (no DB required)
# ---------------------------------------------------------------------------


def test_vulnerability_response_schema():
    """VulnerabilityResponse has all required fields."""
    vuln = VulnerabilityResponse(
        id="GHSA-1234-abcd-5678",
        package_name="express",
        package_version="4.18.2",
        severity="critical",
        cvss_score=9.6,
        summary="RCE in express",
        fixed_version="4.18.3",
        purl="pkg:npm/express@4.18.2",
        aliases=["CVE-2024-12345"],
    )
    assert vuln.id == "GHSA-1234-abcd-5678"
    assert vuln.package_name == "express"
    assert vuln.severity == "critical"
    assert vuln.cvss_score == 9.6
    assert vuln.fixed_version == "4.18.3"
    assert "CVE-2024-12345" in vuln.aliases


def test_vulnerability_response_defaults():
    """VulnerabilityResponse has sensible defaults."""
    vuln = VulnerabilityResponse(
        id="GHSA-test",
        package_name="pkg",
        package_version="1.0.0",
    )
    assert vuln.severity == ""
    assert vuln.cvss_score is None
    assert vuln.summary == ""
    assert vuln.fixed_version is None
    assert vuln.purl == ""
    assert vuln.aliases == []


def test_vulnerability_summary_schema():
    """VulnerabilitySummary aggregates vulnerability data."""
    summary = VulnerabilitySummary(
        total=3,
        by_severity={"critical": 1, "high": 1, "medium": 1},
        vulnerabilities=[
            VulnerabilityResponse(
                id="GHSA-1",
                package_name="express",
                package_version="4.18.2",
                severity="critical",
            ),
            VulnerabilityResponse(
                id="GHSA-2",
                package_name="lodash",
                package_version="4.17.20",
                severity="high",
            ),
            VulnerabilityResponse(
                id="GHSA-3",
                package_name="debug",
                package_version="2.6.0",
                severity="medium",
            ),
        ],
    )
    assert summary.total == 3
    assert summary.by_severity["critical"] == 1
    assert len(summary.vulnerabilities) == 3


def test_vulnerability_summary_defaults():
    """VulnerabilitySummary works with zero vulnerabilities."""
    summary = VulnerabilitySummary(total=0)
    assert summary.total == 0
    assert summary.by_severity == {}
    assert summary.vulnerabilities == []


# ---------------------------------------------------------------------------
# Export format tests (unit, no DB)
# ---------------------------------------------------------------------------


def test_sbom_generator_export_cyclonedx_json():
    """SbomGenerator.export produces valid CycloneDX JSON."""
    from mcp_scanner.services.sbom_generator import SbomGenerator, SbomResult

    bom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": "2026-03-03T00:00:00+00:00",
            "tools": {"components": [{"type": "application", "name": "mcp-scanner", "version": "1.0.0"}]},
            "component": {"type": "application", "name": "test", "version": "1.0.0"},
        },
        "components": [
            {"type": "library", "bom-ref": "pkg:npm/express@4.18.2", "name": "express", "version": "4.18.2", "purl": "pkg:npm/express@4.18.2"},
        ],
        "dependencies": [],
    }
    result = SbomResult(bom_json=bom, component_count=1, main_name="test", main_version="1.0.0")
    gen = SbomGenerator()

    output = gen.export(result, "cyclonedx-json")
    parsed = json.loads(output)
    assert parsed["bomFormat"] == "CycloneDX"
    assert parsed["specVersion"] == "1.6"
    assert len(parsed["components"]) == 1


def test_sbom_generator_export_spdx_json():
    """SbomGenerator.export produces valid SPDX 2.3 JSON."""
    from mcp_scanner.services.sbom_generator import SbomGenerator, SbomResult

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {
            "timestamp": "2026-03-03T00:00:00+00:00",
            "component": {"name": "test-app", "version": "1.0.0"},
        },
        "components": [
            {"name": "express", "version": "4.18.2", "purl": "pkg:npm/express@4.18.2"},
        ],
        "dependencies": [],
    }
    result = SbomResult(bom_json=bom, component_count=1, main_name="test-app", main_version="1.0.0")
    gen = SbomGenerator()

    output = gen.export(result, "spdx-json")
    parsed = json.loads(output)
    assert parsed["spdxVersion"] == "SPDX-2.3"
    assert parsed["dataLicense"] == "CC0-1.0"
    assert len(parsed["packages"]) == 1


def test_sbom_generator_export_invalid_format():
    """SbomGenerator.export raises ValueError for unsupported formats."""
    from mcp_scanner.services.sbom_generator import SbomGenerator, SbomResult

    result = SbomResult(bom_json={}, component_count=0)
    gen = SbomGenerator()

    with pytest.raises(ValueError, match="Unsupported export format"):
        gen.export(result, "invalid-format")
