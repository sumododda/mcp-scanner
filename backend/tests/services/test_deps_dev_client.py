import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import httpx

from mcp_scanner.services.deps_dev_client import DepsDevClient


@pytest.fixture
def client():
    return DepsDevClient()


@pytest.mark.asyncio
async def test_get_package_success(client):
    """Fetching a known package returns metadata."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "packageKey": {"system": "NPM", "name": "@modelcontextprotocol/sdk"},
        "versions": [{"versionKey": {"version": "1.0.0"}}],
    }
    mock_response.raise_for_status = MagicMock()

    with patch.object(client, "_http", new_callable=AsyncMock) as mock_http:
        mock_http.get = AsyncMock(return_value=mock_response)
        result = await client.get_package("npm", "@modelcontextprotocol/sdk")
        assert result is not None
        assert result["packageKey"]["name"] == "@modelcontextprotocol/sdk"
        mock_http.get.assert_called_once()


@pytest.mark.asyncio
async def test_get_package_not_found(client):
    """A 404 returns None instead of raising."""
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_response.raise_for_status = MagicMock(side_effect=httpx.HTTPStatusError(
        "Not Found", request=MagicMock(), response=mock_response
    ))

    with patch.object(client, "_http", new_callable=AsyncMock) as mock_http:
        mock_http.get = AsyncMock(return_value=mock_response)
        result = await client.get_package("npm", "nonexistent-fake-pkg-xyz")
        assert result is None


@pytest.mark.asyncio
async def test_get_version_returns_advisories(client):
    """GetVersion includes advisory references."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "versionKey": {"system": "NPM", "name": "mcp-remote", "version": "0.0.5"},
        "publishedAt": "2025-03-15T00:00:00Z",
        "advisoryKeys": [{"id": "GHSA-xxxx-yyyy-zzzz"}],
    }
    mock_response.raise_for_status = MagicMock()

    with patch.object(client, "_http", new_callable=AsyncMock) as mock_http:
        mock_http.get = AsyncMock(return_value=mock_response)
        result = await client.get_version("npm", "mcp-remote", "0.0.5")
        assert result is not None
        assert len(result["advisoryKeys"]) >= 1


@pytest.mark.asyncio
async def test_get_dependencies_returns_graph(client):
    """GetDependencies returns a dependency graph with nodes."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "nodes": [
            {"versionKey": {"system": "NPM", "name": "pkg-a", "version": "1.0.0"}, "relation": "SELF"},
            {"versionKey": {"system": "NPM", "name": "dep-b", "version": "2.0.0"}, "relation": "DIRECT"},
        ],
        "edges": [{"fromNode": 0, "toNode": 1, "requirement": "^2.0.0"}],
    }
    mock_response.raise_for_status = MagicMock()

    with patch.object(client, "_http", new_callable=AsyncMock) as mock_http:
        mock_http.get = AsyncMock(return_value=mock_response)
        result = await client.get_dependencies("npm", "pkg-a", "1.0.0")
        assert result is not None
        assert len(result["nodes"]) == 2


@pytest.mark.asyncio
async def test_get_project_returns_scorecard(client):
    """GetProject includes Scorecard data."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "projectKey": {"id": "github.com/modelcontextprotocol/servers"},
        "scorecardV2": {
            "overallScore": 7.5,
            "checks": [
                {"name": "Code-Review", "score": 8},
                {"name": "Branch-Protection", "score": 7},
            ],
        },
    }
    mock_response.raise_for_status = MagicMock()

    with patch.object(client, "_http", new_callable=AsyncMock) as mock_http:
        mock_http.get = AsyncMock(return_value=mock_response)
        result = await client.get_project("github.com/modelcontextprotocol/servers")
        assert result is not None
        assert "scorecardV2" in result


@pytest.mark.asyncio
async def test_get_similar_packages(client):
    """GetSimilarlyNamedPackages returns candidates."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "packages": [
            {"packageKey": {"system": "NPM", "name": "@modelcontextprotocol/server-filesystem"}},
        ],
    }
    mock_response.raise_for_status = MagicMock()

    with patch.object(client, "_http", new_callable=AsyncMock) as mock_http:
        mock_http.get = AsyncMock(return_value=mock_response)
        result = await client.get_similar_packages("npm", "modelcontextprotocol-server-filesystm")
        assert result is not None
        assert len(result["packages"]) >= 1


@pytest.mark.asyncio
async def test_timeout_returns_none(client):
    """Network timeout returns None gracefully."""
    with patch.object(client, "_http", new_callable=AsyncMock) as mock_http:
        mock_http.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
        result = await client.get_package("npm", "some-pkg")
        assert result is None


@pytest.mark.asyncio
async def test_caching_deduplicates_requests(client):
    """Same request twice only makes one HTTP call."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"packageKey": {"name": "pkg"}}
    mock_response.raise_for_status = MagicMock()

    with patch.object(client, "_http", new_callable=AsyncMock) as mock_http:
        mock_http.get = AsyncMock(return_value=mock_response)
        r1 = await client.get_package("npm", "pkg")
        r2 = await client.get_package("npm", "pkg")
        assert r1 == r2
        assert mock_http.get.call_count == 1
