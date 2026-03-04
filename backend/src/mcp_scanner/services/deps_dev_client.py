"""Async client for the deps.dev API (v3alpha).

Provides package metadata, vulnerability data, dependency graphs,
Scorecard information, and typosquat detection for supply chain analysis.
All methods return None on error for graceful degradation.
"""

from __future__ import annotations

import logging
from urllib.parse import quote

import httpx

logger = logging.getLogger(__name__)

_BASE = "https://api.deps.dev/v3alpha"
_TIMEOUT = 10.0


class DepsDevClient:
    def __init__(self) -> None:
        self._http = httpx.AsyncClient(timeout=_TIMEOUT)
        self._cache: dict[str, dict | None] = {}

    async def close(self) -> None:
        await self._http.aclose()

    async def _get(self, path: str) -> dict | None:
        if path in self._cache:
            return self._cache[path]
        try:
            resp = await self._http.get(f"{_BASE}{path}")
            resp.raise_for_status()
            data = resp.json()
            self._cache[path] = data
            return data
        except (httpx.HTTPStatusError, httpx.TimeoutException, httpx.ConnectError) as exc:
            logger.debug("deps.dev request failed for %s: %s", path, exc)
            self._cache[path] = None
            return None

    async def get_package(self, system: str, name: str) -> dict | None:
        encoded = quote(name, safe="")
        return await self._get(f"/systems/{system.upper()}/packages/{encoded}")

    async def get_version(self, system: str, name: str, version: str) -> dict | None:
        encoded_name = quote(name, safe="")
        encoded_ver = quote(version, safe="")
        return await self._get(
            f"/systems/{system.upper()}/packages/{encoded_name}/versions/{encoded_ver}"
        )

    async def get_dependencies(self, system: str, name: str, version: str) -> dict | None:
        encoded_name = quote(name, safe="")
        encoded_ver = quote(version, safe="")
        return await self._get(
            f"/systems/{system.upper()}/packages/{encoded_name}/versions/{encoded_ver}:dependencies"
        )

    async def get_project(self, project_id: str) -> dict | None:
        encoded = quote(project_id, safe="")
        return await self._get(f"/projects/{encoded}")

    async def get_similar_packages(self, system: str, name: str) -> dict | None:
        encoded = quote(name, safe="")
        return await self._get(
            f"/systems/{system.upper()}/packages/{encoded}:similarlyNamedPackages"
        )

    async def get_advisory(self, advisory_id: str) -> dict | None:
        encoded = quote(advisory_id, safe="")
        return await self._get(f"/advisories/{encoded}")
