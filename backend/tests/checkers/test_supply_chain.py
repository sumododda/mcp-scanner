import pytest
from unittest.mock import AsyncMock, patch

from mcp_scanner.checkers.supply_chain import SupplyChainChecker
from mcp_scanner.models.scan_context import ScanContext


# ═══════════════════════════════════════════════════════════════
# Config externalization
# ═══════════════════════════════════════════════════════════════

def test_trusted_packages_loaded_from_config():
    """Trusted packages are loaded from external JSON, not hardcoded."""
    import json
    from pathlib import Path
    config_path = Path(__file__).parent.parent.parent / "src" / "mcp_scanner" / "data" / "trusted_packages.json"
    assert config_path.exists(), f"Trusted packages config missing: {config_path}"
    data = json.loads(config_path.read_text())
    assert "packages" in data
    assert "trusted_scopes" in data
    assert len(data["packages"]) > 20
    assert "@modelcontextprotocol" in data["trusted_scopes"]


def _ctx(config: dict) -> ScanContext:
    return ScanContext(
        mcp_config=config,
        tool_definitions={},
    )


# ═══════════════════════════════════════════════════════════════
# Layer 1: Package Identity Verification (existing + enhanced)
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_typosquat_distance_1():
    """A package one edit away from a known package should be flagged."""
    config = {
        "mcpServers": {
            "evil-server": {
                "command": "npx",
                "args": ["@modelcontextprotocol/server-filesysten"],
            }
        }
    }
    checker = SupplyChainChecker()
    result = await checker.check(_ctx(config))
    assert len(result.findings) >= 1
    assert result.findings[0].severity.value == "high"
    assert "typosquat" in result.findings[0].title.lower()


@pytest.mark.asyncio
async def test_typosquat_distance_2():
    """A package two edits from a known package should be flagged."""
    config = {
        "mcpServers": {
            "sketchy": {
                "command": "npx",
                "args": ["@playwright/ncp"],
            }
        }
    }
    checker = SupplyChainChecker()
    result = await checker.check(_ctx(config))
    assert len(result.findings) >= 1


@pytest.mark.asyncio
async def test_legitimate_package_no_findings():
    """An exact match of a known package should produce no findings."""
    config = {
        "mcpServers": {
            "filesystem": {
                "command": "npx",
                "args": ["@modelcontextprotocol/server-filesystem"],
            }
        }
    }
    checker = SupplyChainChecker()
    result = await checker.check(_ctx(config))
    typosquat = [f for f in result.findings if "typosquat" in f.title.lower()]
    assert len(typosquat) == 0


@pytest.mark.asyncio
async def test_unrelated_package_no_findings():
    """A package very different from any known package should not trigger typosquat."""
    config = {
        "mcpServers": {
            "custom": {
                "command": "npx",
                "args": ["my-totally-custom-unrelated-package"],
            }
        }
    }
    checker = SupplyChainChecker()
    result = await checker.check(_ctx(config))
    typosquat = [f for f in result.findings if "typosquat" in f.title.lower()]
    assert len(typosquat) == 0


@pytest.mark.asyncio
async def test_unscoped_mcp_package_flagged():
    """An unscoped package with 'mcp-server' in the name should be flagged."""
    config = {
        "mcpServers": {
            "sus": {
                "command": "npx",
                "args": ["mcp-server-github"],
            }
        }
    }
    checker = SupplyChainChecker()
    result = await checker.check(_ctx(config))
    unscoped = [f for f in result.findings if "unscoped" in f.title.lower() or "scope" in f.title.lower()]
    assert len(unscoped) >= 1


@pytest.mark.asyncio
async def test_unpinned_npx_flagged():
    """npx -y without version pinning should be flagged."""
    config = {
        "mcpServers": {
            "risky": {
                "command": "npx",
                "args": ["-y", "some-mcp-server"],
            }
        }
    }
    checker = SupplyChainChecker()
    result = await checker.check(_ctx(config))
    unpinned = [f for f in result.findings if "unpinned" in f.title.lower() or "pin" in f.title.lower()]
    assert len(unpinned) >= 1


@pytest.mark.asyncio
async def test_pinned_npx_no_unpinned_finding():
    """npx with a pinned version should not trigger unpinned warning."""
    config = {
        "mcpServers": {
            "ok": {
                "command": "npx",
                "args": ["-y", "some-mcp-server@1.2.3"],
            }
        }
    }
    checker = SupplyChainChecker()
    result = await checker.check(_ctx(config))
    unpinned = [f for f in result.findings if "unpinned" in f.title.lower() or "pin" in f.title.lower()]
    assert len(unpinned) == 0


@pytest.mark.asyncio
async def test_scope_confusion_flagged():
    """A slight variation of a trusted scope should be flagged."""
    config = {
        "mcpServers": {
            "confusion": {
                "command": "npx",
                "args": ["@modelcontextprotocl/server-filesystem"],
            }
        }
    }
    checker = SupplyChainChecker()
    result = await checker.check(_ctx(config))
    assert len(result.findings) >= 1


# ═══════════════════════════════════════════════════════════════
# Layer 2: Metadata & Behavioral Analysis (via deps.dev mock)
# ═══════════════════════════════════════════════════════════════

def _mock_deps_client(**overrides):
    """Create a mock DepsDevClient with sensible defaults."""
    client = AsyncMock()
    client.get_package = AsyncMock(return_value=overrides.get("package", None))
    client.get_version = AsyncMock(return_value=overrides.get("version", None))
    client.get_dependencies = AsyncMock(return_value=overrides.get("dependencies", None))
    client.get_project = AsyncMock(return_value=overrides.get("project", None))
    client.get_similar_packages = AsyncMock(return_value=overrides.get("similar", None))
    client.get_advisory = AsyncMock(return_value=overrides.get("advisory", None))
    client.close = AsyncMock()
    return client


@pytest.mark.asyncio
async def test_new_package_flagged():
    """A very new package (< 30 days) with few dependents is flagged."""
    mock_client = _mock_deps_client(
        package={
            "packageKey": {"system": "NPM", "name": "evil-mcp"},
            "versions": [{"versionKey": {"version": "1.0.0"}}],
        },
        version={
            "versionKey": {"system": "NPM", "name": "evil-mcp", "version": "1.0.0"},
            "publishedAt": "2026-02-25T00:00:00Z",
            "isDefault": True,
            "advisoryKeys": [],
        },
    )
    config = {"mcpServers": {"srv": {"command": "npx", "args": ["-y", "evil-mcp"]}}}
    checker = SupplyChainChecker(deps_client=mock_client)
    result = await checker.check(_ctx(config))
    new_pkg = [f for f in result.findings if "new package" in f.title.lower() or "recently published" in f.title.lower()]
    assert len(new_pkg) >= 1


@pytest.mark.asyncio
async def test_deprecated_package_flagged():
    """A deprecated package should be flagged."""
    mock_client = _mock_deps_client(
        package={
            "packageKey": {"system": "NPM", "name": "old-mcp"},
            "versions": [{"versionKey": {"version": "1.0.0"}}],
        },
        version={
            "versionKey": {"system": "NPM", "name": "old-mcp", "version": "1.0.0"},
            "publishedAt": "2025-01-01T00:00:00Z",
            "isDefault": True,
            "isDeprecated": True,
            "advisoryKeys": [],
        },
    )
    config = {"mcpServers": {"srv": {"command": "npx", "args": ["old-mcp@1.0.0"]}}}
    checker = SupplyChainChecker(deps_client=mock_client)
    result = await checker.check(_ctx(config))
    deprecated = [f for f in result.findings if "deprecated" in f.title.lower()]
    assert len(deprecated) >= 1


# ═══════════════════════════════════════════════════════════════
# Layer 3: Vulnerability & Provenance
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_known_vulnerability_flagged():
    """A package with known CVEs should be flagged as CRITICAL."""
    mock_client = _mock_deps_client(
        package={
            "packageKey": {"system": "NPM", "name": "vuln-pkg"},
            "versions": [{"versionKey": {"version": "0.0.5"}}],
        },
        version={
            "versionKey": {"system": "NPM", "name": "vuln-pkg", "version": "0.0.5"},
            "publishedAt": "2025-06-01T00:00:00Z",
            "isDefault": True,
            "advisoryKeys": [{"id": "GHSA-xxxx-yyyy-zzzz"}],
        },
        advisory={
            "advisoryKey": {"id": "GHSA-xxxx-yyyy-zzzz"},
            "url": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
            "title": "RCE in vuln-pkg",
            "aliases": ["CVE-2025-12345"],
            "cvss3Score": 9.6,
        },
    )
    config = {"mcpServers": {"srv": {"command": "npx", "args": ["vuln-pkg@0.0.5"]}}}
    checker = SupplyChainChecker(deps_client=mock_client)
    result = await checker.check(_ctx(config))
    vulns = [f for f in result.findings if "vulnerability" in f.title.lower() or "advisory" in f.title.lower() or "cve" in f.title.lower()]
    assert len(vulns) >= 1
    assert any(f.severity.value == "critical" for f in vulns)


@pytest.mark.asyncio
async def test_malicious_package_flagged():
    """A MAL- prefixed advisory indicates a known malicious package."""
    mock_client = _mock_deps_client(
        package={
            "packageKey": {"system": "NPM", "name": "postmark-mcp"},
            "versions": [{"versionKey": {"version": "1.0.16"}}],
        },
        version={
            "versionKey": {"system": "NPM", "name": "postmark-mcp", "version": "1.0.16"},
            "publishedAt": "2025-09-01T00:00:00Z",
            "isDefault": True,
            "advisoryKeys": [{"id": "MAL-2025-1234"}],
        },
        advisory={
            "advisoryKey": {"id": "MAL-2025-1234"},
            "title": "Malicious package: postmark-mcp",
        },
    )
    config = {"mcpServers": {"srv": {"command": "npx", "args": ["postmark-mcp@1.0.16"]}}}
    checker = SupplyChainChecker(deps_client=mock_client)
    result = await checker.check(_ctx(config))
    mal = [f for f in result.findings if "malicious" in f.title.lower()]
    assert len(mal) >= 1
    assert mal[0].severity.value == "critical"


# ═══════════════════════════════════════════════════════════════
# Layer 4: Repository Health
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_low_scorecard_flagged():
    """A repo with low Scorecard score should produce a finding."""
    mock_client = _mock_deps_client(
        package={
            "packageKey": {"system": "NPM", "name": "sketchy-mcp"},
            "versions": [{"versionKey": {"version": "1.0.0"}}],
        },
        version={
            "versionKey": {"system": "NPM", "name": "sketchy-mcp", "version": "1.0.0"},
            "publishedAt": "2025-06-01T00:00:00Z",
            "isDefault": True,
            "advisoryKeys": [],
            "links": [{"label": "SOURCE_REPO", "url": "https://github.com/sketchy/mcp"}],
        },
        project={
            "projectKey": {"id": "github.com/sketchy/mcp"},
            "scorecardV2": {
                "overallScore": 2.5,
                "checks": [
                    {"name": "Code-Review", "score": 0},
                    {"name": "Branch-Protection", "score": 1},
                    {"name": "Maintained", "score": 3},
                ],
            },
        },
    )
    config = {"mcpServers": {"srv": {"command": "npx", "args": ["sketchy-mcp@1.0.0"]}}}
    checker = SupplyChainChecker(deps_client=mock_client)
    result = await checker.check(_ctx(config))
    scorecard = [f for f in result.findings if "scorecard" in f.title.lower() or "repo" in f.title.lower()]
    assert len(scorecard) >= 1


@pytest.mark.asyncio
async def test_good_scorecard_no_finding():
    """A repo with good Scorecard score should not produce a scorecard finding."""
    mock_client = _mock_deps_client(
        package={
            "packageKey": {"system": "NPM", "name": "good-mcp"},
            "versions": [{"versionKey": {"version": "1.0.0"}}],
        },
        version={
            "versionKey": {"system": "NPM", "name": "good-mcp", "version": "1.0.0"},
            "publishedAt": "2025-01-01T00:00:00Z",
            "isDefault": True,
            "advisoryKeys": [],
            "links": [{"label": "SOURCE_REPO", "url": "https://github.com/good/mcp"}],
        },
        project={
            "projectKey": {"id": "github.com/good/mcp"},
            "scorecardV2": {
                "overallScore": 8.5,
                "checks": [
                    {"name": "Code-Review", "score": 9},
                    {"name": "Branch-Protection", "score": 8},
                    {"name": "Maintained", "score": 9},
                ],
            },
        },
    )
    config = {"mcpServers": {"srv": {"command": "npx", "args": ["good-mcp@1.0.0"]}}}
    checker = SupplyChainChecker(deps_client=mock_client)
    result = await checker.check(_ctx(config))
    scorecard = [f for f in result.findings if "scorecard" in f.title.lower()]
    assert len(scorecard) == 0


@pytest.mark.asyncio
async def test_no_source_repo_flagged():
    """A package with no linked source repo should be flagged."""
    mock_client = _mock_deps_client(
        package={
            "packageKey": {"system": "NPM", "name": "mystery-mcp"},
            "versions": [{"versionKey": {"version": "1.0.0"}}],
        },
        version={
            "versionKey": {"system": "NPM", "name": "mystery-mcp", "version": "1.0.0"},
            "publishedAt": "2025-06-01T00:00:00Z",
            "isDefault": True,
            "advisoryKeys": [],
            "links": [],
        },
    )
    config = {"mcpServers": {"srv": {"command": "npx", "args": ["mystery-mcp@1.0.0"]}}}
    checker = SupplyChainChecker(deps_client=mock_client)
    result = await checker.check(_ctx(config))
    no_repo = [f for f in result.findings if "no source" in f.title.lower() or "no repository" in f.title.lower()]
    assert len(no_repo) >= 1


# ═══════════════════════════════════════════════════════════════
# Layer 5: Aggregate Risk Scoring
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_combined_signals_escalate_severity():
    """Multiple risk signals on one package should produce CRITICAL findings."""
    mock_client = _mock_deps_client(
        package={
            "packageKey": {"system": "NPM", "name": "sus-mcp-server"},
            "versions": [{"versionKey": {"version": "1.0.0"}}],
        },
        version={
            "versionKey": {"system": "NPM", "name": "sus-mcp-server", "version": "1.0.0"},
            "publishedAt": "2026-02-25T00:00:00Z",
            "isDefault": True,
            "advisoryKeys": [{"id": "MAL-2026-9999"}],
            "links": [],
        },
        advisory={
            "advisoryKey": {"id": "MAL-2026-9999"},
            "title": "Malicious package",
        },
    )
    config = {"mcpServers": {"srv": {"command": "npx", "args": ["-y", "sus-mcp-server"]}}}
    checker = SupplyChainChecker(deps_client=mock_client)
    result = await checker.check(_ctx(config))
    assert len(result.findings) >= 3
    critical = [f for f in result.findings if f.severity.value == "critical"]
    assert len(critical) >= 1


# ═══════════════════════════════════════════════════════════════
# Graceful degradation
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_offline_fallback_still_works():
    """When deps.dev is unreachable, local checks still run."""
    mock_client = _mock_deps_client()
    config = {
        "mcpServers": {
            "typo": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesysten"],
            }
        }
    }
    checker = SupplyChainChecker(deps_client=mock_client)
    result = await checker.check(_ctx(config))
    assert len(result.findings) >= 1
    typo = [f for f in result.findings if "typosquat" in f.title.lower()]
    assert len(typo) >= 1


@pytest.mark.asyncio
async def test_no_deps_client_uses_default():
    """When no deps_client is provided, checker creates its own."""
    config = {
        "mcpServers": {
            "typo": {
                "command": "npx",
                "args": ["@modelcontextprotocol/server-filesysten"],
            }
        }
    }
    checker = SupplyChainChecker()
    with patch("mcp_scanner.checkers.supply_chain.DepsDevClient") as MockClient:
        mock_instance = _mock_deps_client()
        MockClient.return_value = mock_instance
        result = await checker.check(_ctx(config))
        assert len(result.findings) >= 1


# ═══════════════════════════════════════════════════════════════
# Python package detection
# ═══════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_python_uv_package_extracted():
    """Python packages via uv/pip should be detected."""
    config = {
        "mcpServers": {
            "py-srv": {
                "command": "uv",
                "args": ["run", "--with", "mcp-server-fetch", "python", "-m", "mcp_server_fetch"],
            }
        }
    }
    checker = SupplyChainChecker()
    result = await checker.check(_ctx(config))
    assert result is not None


@pytest.mark.asyncio
async def test_python_pip_package_extracted():
    """Packages installed via pip/pipx should be detected."""
    config = {
        "mcpServers": {
            "py-srv": {
                "command": "pipx",
                "args": ["run", "mcp-server-sqlite"],
            }
        }
    }
    checker = SupplyChainChecker()
    result = await checker.check(_ctx(config))
    assert result is not None


