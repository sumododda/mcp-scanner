"""Async client for the OSV.dev vulnerability API.

Provides batch PURL-based vulnerability lookups to enrich SBOMs with
known vulnerability data. Uses the OSV querybatch endpoint for efficient
bulk queries, chunked at 1000 PURLs per request.

All methods return empty lists on error for graceful degradation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

_BASE = "https://api.osv.dev/v1"
_TIMEOUT = 15.0
_CHUNK_SIZE = 1000


@dataclass
class OsvVulnerability:
    """A single vulnerability record from OSV.dev."""

    id: str
    summary: str
    aliases: list[str]
    severity_score: float | None
    severity_vector: str | None
    affected_ranges: list[dict]
    fixed_version: str | None
    purl: str


class OsvClient:
    """Async client for OSV.dev batch vulnerability queries."""

    def __init__(self) -> None:
        self._http = httpx.AsyncClient(timeout=_TIMEOUT)

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._http.aclose()

    async def query_batch(self, purls: list[str]) -> list[OsvVulnerability]:
        """Query OSV.dev for vulnerabilities affecting the given PURLs.

        Splits large inputs into chunks of up to 1000 PURLs each.
        Returns an empty list on network/timeout errors (graceful degradation).
        """
        if not purls:
            return []

        all_vulns: list[OsvVulnerability] = []
        for i in range(0, len(purls), _CHUNK_SIZE):
            chunk = purls[i : i + _CHUNK_SIZE]
            chunk_vulns = await self._query_chunk(chunk)
            all_vulns.extend(chunk_vulns)
        return all_vulns

    async def _query_chunk(self, purls: list[str]) -> list[OsvVulnerability]:
        """Execute a single batch request for a chunk of PURLs."""
        body = {
            "queries": [{"package": {"purl": p}} for p in purls],
        }
        try:
            resp = await self._http.post(f"{_BASE}/querybatch", json=body)
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPStatusError, httpx.TimeoutException, httpx.ConnectError) as exc:
            logger.warning("OSV.dev batch query failed: %s", exc)
            return []

        vulns: list[OsvVulnerability] = []
        results = data.get("results", [])
        for idx, entry in enumerate(results):
            purl = purls[idx] if idx < len(purls) else "unknown"
            for vuln_data in entry.get("vulns", []):
                vulns.append(self._parse_vuln(vuln_data, purl))
        return vulns

    @staticmethod
    def _parse_vuln(data: dict, purl: str) -> OsvVulnerability:
        """Parse a single OSV vulnerability JSON object into a dataclass."""
        # Extract severity info from the first CVSS_V3 entry if available
        severity_score: float | None = None
        severity_vector: str | None = None
        for sev in data.get("severity", []):
            if sev.get("type") == "CVSS_V3":
                severity_vector = sev.get("score")
                # The OSV API puts the CVSS vector string in "score";
                # numeric score must be computed from the vector externally.
                break

        # Collect affected ranges across all affected entries
        affected_ranges: list[dict] = []
        fixed_version: str | None = None
        for affected in data.get("affected", []):
            for r in affected.get("ranges", []):
                affected_ranges.append(r)
                # Extract the first fixed version found
                if fixed_version is None:
                    for event in r.get("events", []):
                        if "fixed" in event:
                            fixed_version = event["fixed"]
                            break

        return OsvVulnerability(
            id=data.get("id", ""),
            summary=data.get("summary", ""),
            aliases=data.get("aliases", []),
            severity_score=severity_score,
            severity_vector=severity_vector,
            affected_ranges=affected_ranges,
            fixed_version=fixed_version,
            purl=purl,
        )
