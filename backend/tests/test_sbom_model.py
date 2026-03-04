import uuid

from mcp_scanner.models.sbom import Sbom


def test_sbom_model_fields():
    """Sbom model has all required fields."""
    sbom = Sbom(
        scan_id=uuid.uuid4(),
        server_name="test-server",
        package_name="@modelcontextprotocol/sdk",
        package_version="1.0.0",
        format="cyclonedx",
        sbom_data={"bomFormat": "CycloneDX", "components": []},
        dependency_count=5,
        vulnerability_count=0,
    )
    assert sbom.server_name == "test-server"
    assert sbom.package_name == "@modelcontextprotocol/sdk"
    assert sbom.format == "cyclonedx"
    assert sbom.dependency_count == 5


def test_sbom_default_format():
    """Format defaults to cyclonedx."""
    sbom = Sbom(
        scan_id=uuid.uuid4(),
        server_name="s",
        package_name="p",
        package_version="1.0.0",
        sbom_data={},
    )
    assert sbom.format == "cyclonedx"


def test_checker_result_sbom_entries():
    """CheckerResult can carry sbom_entries."""
    from mcp_scanner.checkers.base import CheckerResult
    result = CheckerResult(
        findings=[],
        checker_name="supply_chain",
        sbom_entries=[{"package_name": "pkg", "sbom_data": {}}],
    )
    assert len(result.sbom_entries) == 1


def test_sbom_model_new_fields():
    """Sbom model supports vulnerability and license fields."""
    vulns = [
        {"id": "GHSA-1234", "summary": "XSS", "aliases": ["CVE-2024-1234"],
         "purl": "pkg:npm/express@4.18.2", "fixed_version": "4.18.3"},
    ]
    license_summary = {"MIT": 5, "Apache-2.0": 3}

    sbom = Sbom(
        scan_id=uuid.uuid4(),
        server_name="test-server",
        package_name="test-pkg",
        package_version="1.0.0",
        sbom_data={"bomFormat": "CycloneDX", "components": []},
        dependency_count=8,
        vulnerability_count=1,
        vulnerabilities=vulns,
        license_summary=license_summary,
    )
    assert sbom.vulnerabilities == vulns
    assert sbom.license_summary == license_summary
    assert sbom.vulnerabilities[0]["id"] == "GHSA-1234"
    assert sbom.license_summary["MIT"] == 5


def test_sbom_model_new_fields_default_none():
    """New fields default to None when not provided."""
    sbom = Sbom(
        scan_id=uuid.uuid4(),
        server_name="s",
        package_name="p",
        package_version="1.0.0",
        sbom_data={},
    )
    assert sbom.vulnerabilities is None
    assert sbom.license_summary is None
