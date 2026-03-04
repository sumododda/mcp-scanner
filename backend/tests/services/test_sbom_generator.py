"""Tests for the SBOM generator service.

Covers CycloneDX 1.6 BOM generation from repo manifests and registry
dependency graphs, OSV vulnerability enrichment, and export to
CycloneDX JSON, CycloneDX XML, and SPDX 2.3 JSON formats.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from mcp_scanner.services.osv_client import OsvVulnerability
from mcp_scanner.services.sbom_generator import SbomGenerator, SbomResult


# ---------------------------------------------------------------------------
# Helpers: create temporary manifest repos
# ---------------------------------------------------------------------------


def _write_npm_lockfile(tmp_path: Path) -> None:
    """Write a minimal package-lock.json v3 with two packages."""
    lock = {
        "name": "test-app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "test-app", "version": "1.0.0"},
            "node_modules/express": {"version": "4.18.2"},
            "node_modules/lodash": {"version": "4.17.21"},
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))


def _write_requirements_txt(tmp_path: Path) -> None:
    """Write a minimal requirements.txt with two pinned packages."""
    (tmp_path / "requirements.txt").write_text(
        "flask==3.0.0\nrequests==2.31.0\n"
    )


def _make_vuln(vuln_id: str, purl: str) -> OsvVulnerability:
    """Build a test OsvVulnerability."""
    return OsvVulnerability(
        id=vuln_id,
        summary=f"Vuln {vuln_id}",
        aliases=[f"CVE-2024-{vuln_id[-4:]}"],
        severity_score=None,
        severity_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        affected_ranges=[],
        fixed_version="99.0.0",
        purl=purl,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def generator():
    """SbomGenerator with a mocked OsvClient that returns no vulns."""
    mock_osv = AsyncMock()
    mock_osv.query_batch = AsyncMock(return_value=[])
    gen = SbomGenerator(osv_client=mock_osv)
    return gen


# ---------------------------------------------------------------------------
# Test 1: generate_from_repo — npm lockfile
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_generate_from_repo_npm(tmp_path, generator):
    """npm lockfile produces a valid CycloneDX 1.6 BOM with components."""
    _write_npm_lockfile(tmp_path)

    result = await generator.generate_from_repo(tmp_path)

    assert result is not None
    assert isinstance(result, SbomResult)
    assert result.component_count == 2
    assert result.main_name == "test-app"
    assert result.main_version == "1.0.0"

    bom = result.bom_json
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert bom["$schema"] == "http://cyclonedx.org/schema/bom-1.6.schema.json"
    assert bom["version"] == 1
    assert bom["serialNumber"].startswith("urn:uuid:")

    # Metadata
    meta = bom["metadata"]
    assert "timestamp" in meta
    assert meta["tools"]["components"][0]["name"] == "mcp-scanner"
    assert meta["component"]["name"] == "test-app"

    # Components
    names = {c["name"] for c in bom["components"]}
    assert "express" in names
    assert "lodash" in names
    for comp in bom["components"]:
        assert comp["type"] == "library"
        assert "purl" in comp
        assert comp["bom-ref"] == comp["purl"]


# ---------------------------------------------------------------------------
# Test 2: generate_from_repo — Python requirements.txt
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_generate_from_repo_python(tmp_path, generator):
    """requirements.txt produces a valid SBOM with pypi PURLs."""
    _write_requirements_txt(tmp_path)

    result = await generator.generate_from_repo(tmp_path)

    assert result is not None
    assert result.component_count == 2

    names = {c["name"] for c in result.bom_json["components"]}
    assert "flask" in names
    assert "requests" in names

    # Verify PURLs use pypi type
    for comp in result.bom_json["components"]:
        assert "pkg:pypi/" in comp["purl"]


# ---------------------------------------------------------------------------
# Test 3: generate_from_repo — multi-ecosystem (npm + python)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_generate_from_repo_multi_ecosystem(tmp_path, generator):
    """npm + Python manifests in same repo are merged into one BOM."""
    _write_npm_lockfile(tmp_path)
    _write_requirements_txt(tmp_path)

    result = await generator.generate_from_repo(tmp_path)

    assert result is not None
    # 2 npm + 2 python = 4 components
    assert result.component_count == 4

    purls = {c["purl"] for c in result.bom_json["components"]}
    has_npm = any("pkg:npm/" in p for p in purls)
    has_pypi = any("pkg:pypi/" in p for p in purls)
    assert has_npm
    assert has_pypi


# ---------------------------------------------------------------------------
# Test 4: generate_from_repo — empty repo returns None
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_generate_from_repo_empty(tmp_path, generator):
    """A directory with no manifest files returns None."""
    result = await generator.generate_from_repo(tmp_path)
    assert result is None


# ---------------------------------------------------------------------------
# Test 5: generate_from_repo — with OSV vulnerabilities
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_generate_from_repo_with_vulns(tmp_path):
    """OSV vulnerabilities are included in the SbomResult."""
    _write_npm_lockfile(tmp_path)

    vuln = _make_vuln("GHSA-test-1234-abcd", "pkg:npm/express@4.18.2")

    mock_osv = AsyncMock()
    mock_osv.query_batch = AsyncMock(return_value=[vuln])
    gen = SbomGenerator(osv_client=mock_osv)

    result = await gen.generate_from_repo(tmp_path)

    assert result is not None
    assert result.vulnerability_count == 1
    assert len(result.vulnerabilities) == 1
    assert result.vulnerabilities[0].id == "GHSA-test-1234-abcd"
    assert result.vulnerabilities[0].purl == "pkg:npm/express@4.18.2"

    # OSV client was called with the component PURLs
    mock_osv.query_batch.assert_called_once()
    called_purls = mock_osv.query_batch.call_args[0][0]
    assert len(called_purls) == 2  # express + lodash


# ---------------------------------------------------------------------------
# Test 6: generate_from_registry — deps.dev graph
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_generate_from_registry(generator):
    """deps.dev dependency graph is converted to a CycloneDX BOM."""
    deps_client = AsyncMock()
    deps_client.get_dependencies = AsyncMock(return_value={
        "nodes": [
            {
                "versionKey": {"system": "NPM", "name": "my-lib", "version": "2.0.0"},
                "relation": "SELF",
            },
            {
                "versionKey": {"system": "NPM", "name": "dep-a", "version": "1.0.0"},
                "relation": "DIRECT",
            },
            {
                "versionKey": {"system": "NPM", "name": "dep-b", "version": "3.5.0"},
                "relation": "INDIRECT",
            },
        ],
        "edges": [
            {"fromNode": 0, "toNode": 1, "requirement": "^1.0.0"},
            {"fromNode": 0, "toNode": 2, "requirement": "^3.0.0"},
            {"fromNode": 1, "toNode": 2, "requirement": "^3.0.0"},
        ],
    })

    result = await generator.generate_from_registry(
        deps_client, "NPM", "my-lib", "2.0.0"
    )

    assert result is not None
    assert isinstance(result, SbomResult)
    assert result.main_name == "my-lib"
    assert result.main_version == "2.0.0"
    # Components exclude the SELF node
    assert result.component_count == 2

    bom = result.bom_json
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"

    # Metadata main component
    assert bom["metadata"]["component"]["name"] == "my-lib"

    # Components
    comp_names = {c["name"] for c in bom["components"]}
    assert "dep-a" in comp_names
    assert "dep-b" in comp_names

    # Dependencies contain edges
    assert len(bom["dependencies"]) > 0


# ---------------------------------------------------------------------------
# Test 7: export — CycloneDX JSON
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_export_cyclonedx_json(tmp_path, generator):
    """export(..., 'cyclonedx-json') returns valid JSON matching the BOM."""
    _write_npm_lockfile(tmp_path)
    result = await generator.generate_from_repo(tmp_path)
    assert result is not None

    output = generator.export(result, "cyclonedx-json")
    parsed = json.loads(output)
    assert parsed["bomFormat"] == "CycloneDX"
    assert parsed["specVersion"] == "1.6"
    assert len(parsed["components"]) == 2


# ---------------------------------------------------------------------------
# Test 8: export — SPDX 2.3 JSON
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_export_spdx_json(tmp_path, generator):
    """export(..., 'spdx-json') returns valid SPDX 2.3 structure."""
    _write_npm_lockfile(tmp_path)
    result = await generator.generate_from_repo(tmp_path)
    assert result is not None

    output = generator.export(result, "spdx-json")
    parsed = json.loads(output)

    assert parsed["spdxVersion"] == "SPDX-2.3"
    assert parsed["dataLicense"] == "CC0-1.0"
    assert parsed["SPDXID"] == "SPDXRef-DOCUMENT"
    assert "name" in parsed
    assert parsed["documentNamespace"].startswith("https://spdx.org/spdxdocs/")
    assert "creationInfo" in parsed
    assert "Tool: mcp-scanner-1.0.0" in parsed["creationInfo"]["creators"]

    # SPDX packages
    assert len(parsed["packages"]) == 2
    for pkg in parsed["packages"]:
        assert pkg["SPDXID"].startswith("SPDXRef-")
        assert "name" in pkg
        assert "versionInfo" in pkg
        assert pkg["downloadLocation"] == "NOASSERTION"
        assert pkg["filesAnalyzed"] is False
        assert len(pkg["externalRefs"]) >= 1
        purl_ref = next(
            r for r in pkg["externalRefs"]
            if r["referenceType"] == "purl"
        )
        assert purl_ref["referenceCategory"] == "PACKAGE-MANAGER"


# ---------------------------------------------------------------------------
# Test 9: export — CycloneDX XML
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_export_cyclonedx_xml(tmp_path, generator):
    """export(..., 'cyclonedx-xml') returns a valid XML string."""
    _write_npm_lockfile(tmp_path)
    result = await generator.generate_from_repo(tmp_path)
    assert result is not None

    output = generator.export(result, "cyclonedx-xml")
    assert output.startswith("<?xml")
    assert "<bom" in output
    assert "CycloneDX" in output or "cyclonedx" in output.lower()
    assert "<component" in output
    assert "express" in output
    assert "lodash" in output
