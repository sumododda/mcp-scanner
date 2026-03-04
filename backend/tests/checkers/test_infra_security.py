import pytest

from mcp_scanner.checkers.infra_security import InfraSecurityChecker
from mcp_scanner.models.scan_context import ScanContext


def _ctx(config: dict) -> ScanContext:
    return ScanContext(
        mcp_config=config,
        tool_definitions={},
    )


@pytest.mark.asyncio
async def test_http_transport_detected():
    config = {
        "mcpServers": {
            "insecure": {
                "url": "http://mcp.example.com/api",
                "command": "node",
                "args": [],
            }
        }
    }
    checker = InfraSecurityChecker()
    result = await checker.check(_ctx(config))
    http_findings = [f for f in result.findings if "http transport" in f.title.lower()]
    assert len(http_findings) >= 1
    assert http_findings[0].severity.value == "high"


@pytest.mark.asyncio
async def test_plaintext_secret_in_env():
    config = {
        "mcpServers": {
            "ai-server": {
                "command": "node",
                "args": ["server.js"],
                "env": {
                    "OPENAI_API_KEY": "sk-abcdefghijklmnopqrstuvwxyz1234567890",
                    "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
                },
            }
        }
    }
    checker = InfraSecurityChecker()
    result = await checker.check(_ctx(config))
    secret_findings = [f for f in result.findings if "plaintext secret" in f.title.lower()]
    assert len(secret_findings) >= 2


@pytest.mark.asyncio
async def test_sudo_privilege_detected():
    config = {
        "mcpServers": {
            "root-server": {
                "command": "sudo",
                "args": ["node", "server.js"],
            }
        }
    }
    checker = InfraSecurityChecker()
    result = await checker.check(_ctx(config))
    priv_findings = [f for f in result.findings if "privilege" in f.title.lower()]
    assert len(priv_findings) >= 1
    assert priv_findings[0].severity.value == "critical"


@pytest.mark.asyncio
async def test_plaintext_secret_in_headers():
    config = {
        "mcpServers": {
            "header-server": {
                "command": "node",
                "args": [],
                "headers": {
                    "Authorization": "Bearer ghp_abcdefghijklmnopqrstuvwxyz0123456789",
                },
            }
        }
    }
    checker = InfraSecurityChecker()
    result = await checker.check(_ctx(config))
    secret_findings = [f for f in result.findings if "plaintext secret" in f.title.lower()]
    assert len(secret_findings) >= 1


@pytest.mark.asyncio
async def test_clean_config_no_findings():
    config = {
        "mcpServers": {
            "safe-server": {
                "command": "node",
                "args": ["server.js"],
                "url": "https://secure.example.com/api",
                "env": {
                    "LOG_LEVEL": "info",
                    "NODE_ENV": "production",
                },
            }
        }
    }
    checker = InfraSecurityChecker()
    result = await checker.check(_ctx(config))
    assert len(result.findings) == 0
