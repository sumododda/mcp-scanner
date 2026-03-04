"""Tests for the OSV.dev async vulnerability client."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from mcp_scanner.services.osv_client import OsvClient, OsvVulnerability


@pytest.fixture
def client():
    return OsvClient()


# --- Sample OSV API response fragments ---

def _make_osv_vuln(vuln_id: str = "GHSA-1234-abcd-5678", purl: str = "pkg:npm/express@4.18.2"):
    """Build a realistic OSV vulnerability response dict."""
    return {
        "id": vuln_id,
        "summary": "Cross-site scripting in express",
        "aliases": ["CVE-2024-12345"],
        "severity": [
            {
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            }
        ],
        "affected": [
            {
                "package": {"purl": purl},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "4.0.0"},
                            {"fixed": "4.18.3"},
                        ],
                    }
                ],
            }
        ],
    }


def _make_batch_response(results_per_package: list[list[dict]]) -> dict:
    """Build a querybatch response. Each entry in the outer list corresponds
    to one queried package; inner list is its vulns (may be empty)."""
    results = []
    for vulns in results_per_package:
        if vulns:
            results.append({"vulns": vulns})
        else:
            results.append({})
    return {"results": results}


# --- Tests ---


@pytest.mark.asyncio
async def test_query_batch_single_vuln(client):
    """A single package with one vulnerability is parsed correctly."""
    purl = "pkg:npm/express@4.18.2"
    vuln_data = _make_osv_vuln("GHSA-1234-abcd-5678", purl)

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = _make_batch_response([[vuln_data]])
    mock_response.raise_for_status = MagicMock()

    with patch.object(client, "_http", new_callable=AsyncMock) as mock_http:
        mock_http.post = AsyncMock(return_value=mock_response)
        result = await client.query_batch([purl])

    assert len(result) == 1
    v = result[0]
    assert isinstance(v, OsvVulnerability)
    assert v.id == "GHSA-1234-abcd-5678"
    assert v.summary == "Cross-site scripting in express"
    assert v.aliases == ["CVE-2024-12345"]
    assert v.severity_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    assert v.fixed_version == "4.18.3"
    assert v.purl == purl
    assert len(v.affected_ranges) == 1


@pytest.mark.asyncio
async def test_query_batch_no_vulns(client):
    """Packages with no known vulnerabilities return an empty list."""
    purl = "pkg:npm/safe-package@1.0.0"

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = _make_batch_response([[]])
    mock_response.raise_for_status = MagicMock()

    with patch.object(client, "_http", new_callable=AsyncMock) as mock_http:
        mock_http.post = AsyncMock(return_value=mock_response)
        result = await client.query_batch([purl])

    assert result == []


@pytest.mark.asyncio
async def test_query_batch_multiple_packages(client):
    """Three packages queried: two with vulns, one clean."""
    purls = [
        "pkg:npm/express@4.18.2",
        "pkg:pypi/flask@2.0.0",
        "pkg:npm/safe-pkg@1.0.0",
    ]
    vuln_express = _make_osv_vuln("GHSA-1111-aaaa-1111", purls[0])
    vuln_flask = _make_osv_vuln("GHSA-2222-bbbb-2222", purls[1])

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = _make_batch_response([
        [vuln_express],
        [vuln_flask],
        [],
    ])
    mock_response.raise_for_status = MagicMock()

    with patch.object(client, "_http", new_callable=AsyncMock) as mock_http:
        mock_http.post = AsyncMock(return_value=mock_response)
        result = await client.query_batch(purls)

    assert len(result) == 2
    ids = {v.id for v in result}
    assert ids == {"GHSA-1111-aaaa-1111", "GHSA-2222-bbbb-2222"}
    # Verify the purl is correctly associated
    purl_map = {v.id: v.purl for v in result}
    assert purl_map["GHSA-1111-aaaa-1111"] == purls[0]
    assert purl_map["GHSA-2222-bbbb-2222"] == purls[1]


@pytest.mark.asyncio
async def test_query_batch_timeout_returns_empty(client):
    """Network timeout returns an empty list (graceful degradation)."""
    with patch.object(client, "_http", new_callable=AsyncMock) as mock_http:
        mock_http.post = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
        result = await client.query_batch(["pkg:npm/express@4.18.2"])

    assert result == []


@pytest.mark.asyncio
async def test_query_batch_http_error_returns_empty(client):
    """HTTP 500 from OSV returns empty list (graceful degradation)."""
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock(
        side_effect=httpx.HTTPStatusError(
            "500 Internal Server Error",
            request=MagicMock(),
            response=MagicMock(status_code=500),
        )
    )

    with patch.object(client, "_http", new_callable=AsyncMock) as mock_http:
        mock_http.post = AsyncMock(return_value=mock_response)
        result = await client.query_batch(["pkg:npm/express@4.18.2"])

    assert result == []


@pytest.mark.asyncio
async def test_query_batch_chunks_large_input(client):
    """1500 PURLs should be split into 2 HTTP calls (chunk size 1000)."""
    purls = [f"pkg:npm/pkg-{i}@1.0.0" for i in range(1500)]

    # Both chunks return no vulns
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()

    # First call: 1000 packages, second call: 500 packages
    response_1 = MagicMock()
    response_1.status_code = 200
    response_1.json.return_value = _make_batch_response([[] for _ in range(1000)])
    response_1.raise_for_status = MagicMock()

    response_2 = MagicMock()
    response_2.status_code = 200
    response_2.json.return_value = _make_batch_response([[] for _ in range(500)])
    response_2.raise_for_status = MagicMock()

    with patch.object(client, "_http", new_callable=AsyncMock) as mock_http:
        mock_http.post = AsyncMock(side_effect=[response_1, response_2])
        result = await client.query_batch(purls)

    assert result == []
    assert mock_http.post.call_count == 2

    # Verify the chunk sizes via the request bodies
    first_call_body = mock_http.post.call_args_list[0]
    second_call_body = mock_http.post.call_args_list[1]
    assert len(first_call_body.kwargs["json"]["queries"]) == 1000
    assert len(second_call_body.kwargs["json"]["queries"]) == 500


@pytest.mark.asyncio
async def test_close(client):
    """close() delegates to httpx.AsyncClient.aclose()."""
    with patch.object(client, "_http", new_callable=AsyncMock) as mock_http:
        mock_http.aclose = AsyncMock()
        await client.close()
        mock_http.aclose.assert_called_once()
