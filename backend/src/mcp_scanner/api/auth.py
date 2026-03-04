"""API key authentication dependency."""

from __future__ import annotations

import logging
import secrets

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from mcp_scanner.config import settings

logger = logging.getLogger(__name__)

_bearer_scheme = HTTPBearer(auto_error=False)

_warned_no_key = False


async def require_api_key(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> None:
    """Validate the Bearer token against the configured API key.

    When ``settings.api_key`` is empty the check is skipped (dev mode)
    and a warning is logged once.
    """
    global _warned_no_key  # noqa: PLW0603

    if not settings.api_key:
        if not _warned_no_key:
            logger.warning(
                "MCP_SCANNER_API_KEY is not set -- API authentication is DISABLED. "
                "Set MCP_SCANNER_API_KEY to enable auth."
            )
            _warned_no_key = True
        return

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not secrets.compare_digest(credentials.credentials, settings.api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
