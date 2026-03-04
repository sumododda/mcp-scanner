import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from mcp_scanner.api.auth import require_api_key
from mcp_scanner.api.schemas import validate_repo_url
from mcp_scanner.database import get_session
from mcp_scanner.main import app


@pytest.fixture
def client():
    mock_session = AsyncMock()
    mock_session.add = lambda x: None
    # Mock execute so scalar_one_or_none returns None (no existing scan)
    mock_exec_result = MagicMock()
    mock_exec_result.scalar_one_or_none.return_value = None
    mock_session.execute = AsyncMock(return_value=mock_exec_result)

    async def override_get_session():
        yield mock_session

    app.dependency_overrides[get_session] = override_get_session
    app.dependency_overrides[require_api_key] = lambda: None
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_scan_with_repo_url(client):
    resp = client.post(
        "/api/scan",
        json={"repo_url": "https://github.com/org/mcp-server"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["grade"] in ("A", "B", "C", "D", "F")
    assert isinstance(data["overall_score"], int)
    assert "findings" in data
    assert "summary" in data


def test_scan_missing_input(client):
    resp = client.post("/api/scan", json={})
    assert resp.status_code == 422


def test_get_settings(client):
    resp = client.get("/api/settings")
    assert resp.status_code == 200
    data = resp.json()
    assert "openrouter_model" in data
    assert "llm_judge_enabled" in data
    assert "openrouter_api_key" in data


def test_update_settings(client):
    resp = client.put(
        "/api/settings",
        json={"openrouter_model": "google/gemini-2.5-pro-preview", "llm_judge_enabled": True},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["openrouter_model"] == "google/gemini-2.5-pro-preview"
    assert data["llm_judge_enabled"] is True


# ── API Key Auth Tests ──


class TestApiKeyAuth:
    """Test the API key authentication middleware."""

    def _make_client(self, api_key: str = ""):
        """Create a TestClient with a specific api_key setting."""
        mock_session = AsyncMock()
        mock_session.add = lambda x: None
        mock_exec_result = MagicMock()
        mock_exec_result.scalar_one_or_none.return_value = None
        mock_session.execute = AsyncMock(return_value=mock_exec_result)

        async def override_get_session():
            yield mock_session

        app.dependency_overrides[get_session] = override_get_session
        # Do NOT override require_api_key — we want to test it
        app.dependency_overrides.pop(require_api_key, None)
        return TestClient(app)

    def teardown_method(self):
        app.dependency_overrides.clear()

    @patch("mcp_scanner.api.auth.settings")
    def test_no_key_configured_allows_access(self, mock_settings):
        mock_settings.api_key = ""
        client = self._make_client()
        resp = client.get("/api/settings")
        assert resp.status_code == 200

    @patch("mcp_scanner.api.auth.settings")
    def test_valid_key_allows_access(self, mock_settings):
        mock_settings.api_key = "test-secret-key"
        client = self._make_client()
        resp = client.get("/api/settings", headers={"Authorization": "Bearer test-secret-key"})
        assert resp.status_code == 200

    @patch("mcp_scanner.api.auth.settings")
    def test_invalid_key_returns_401(self, mock_settings):
        mock_settings.api_key = "test-secret-key"
        client = self._make_client()
        resp = client.get("/api/settings", headers={"Authorization": "Bearer wrong-key"})
        assert resp.status_code == 401

    @patch("mcp_scanner.api.auth.settings")
    def test_missing_header_returns_401(self, mock_settings):
        mock_settings.api_key = "test-secret-key"
        client = self._make_client()
        resp = client.get("/api/settings")
        assert resp.status_code == 401

    @patch("mcp_scanner.api.auth.settings")
    def test_health_always_public(self, mock_settings):
        mock_settings.api_key = "test-secret-key"
        client = self._make_client()
        resp = client.get("/health")
        assert resp.status_code == 200


# ── repo_url Validation Tests ──


class TestRepoUrlValidation:
    """Test the validate_repo_url function."""

    def test_https_url_passes(self):
        result = validate_repo_url("https://github.com/org/repo")
        assert result == "https://github.com/org/repo"

    def test_http_rejected(self):
        with pytest.raises(ValueError, match="Only https://"):
            validate_repo_url("http://github.com/org/repo")

    def test_ssh_rejected(self):
        with pytest.raises(ValueError, match="Only https://"):
            validate_repo_url("ssh://git@github.com/org/repo")

    def test_file_rejected(self):
        with pytest.raises(ValueError, match="Only https://"):
            validate_repo_url("file:///etc/passwd")

    def test_git_rejected(self):
        with pytest.raises(ValueError, match="Only https://"):
            validate_repo_url("git://github.com/org/repo")

    def test_ext_transport_rejected(self):
        with pytest.raises(ValueError, match="ext:: transport"):
            validate_repo_url("ext::sh -c cat% /etc/passwd")

    def test_no_hostname_rejected(self):
        with pytest.raises(ValueError, match="hostname"):
            validate_repo_url("https://")

    @patch("mcp_scanner.api.schemas.socket.getaddrinfo")
    def test_localhost_rejected(self, mock_dns):
        mock_dns.return_value = [(socket.AF_INET, 0, 0, "", ("127.0.0.1", 0))]
        with pytest.raises(ValueError, match="private/reserved"):
            validate_repo_url("https://localhost/repo")

    @patch("mcp_scanner.api.schemas.socket.getaddrinfo")
    def test_private_10_rejected(self, mock_dns):
        mock_dns.return_value = [(socket.AF_INET, 0, 0, "", ("10.0.0.1", 0))]
        with pytest.raises(ValueError, match="private/reserved"):
            validate_repo_url("https://evil.com/repo")

    @patch("mcp_scanner.api.schemas.socket.getaddrinfo")
    def test_private_172_rejected(self, mock_dns):
        mock_dns.return_value = [(socket.AF_INET, 0, 0, "", ("172.16.0.1", 0))]
        with pytest.raises(ValueError, match="private/reserved"):
            validate_repo_url("https://evil.com/repo")

    @patch("mcp_scanner.api.schemas.socket.getaddrinfo")
    def test_private_192_rejected(self, mock_dns):
        mock_dns.return_value = [(socket.AF_INET, 0, 0, "", ("192.168.1.1", 0))]
        with pytest.raises(ValueError, match="private/reserved"):
            validate_repo_url("https://evil.com/repo")

    @patch("mcp_scanner.api.schemas.socket.getaddrinfo")
    def test_link_local_rejected(self, mock_dns):
        mock_dns.return_value = [(socket.AF_INET, 0, 0, "", ("169.254.169.254", 0))]
        with pytest.raises(ValueError, match="private/reserved"):
            validate_repo_url("https://evil.com/repo")

    @patch("mcp_scanner.api.schemas.socket.getaddrinfo")
    def test_ipv6_loopback_rejected(self, mock_dns):
        mock_dns.return_value = [(socket.AF_INET6, 0, 0, "", ("::1", 0, 0, 0))]
        with pytest.raises(ValueError, match="private/reserved"):
            validate_repo_url("https://evil.com/repo")

    @patch("mcp_scanner.api.schemas.socket.getaddrinfo")
    def test_unresolvable_hostname_rejected(self, mock_dns):
        mock_dns.side_effect = socket.gaierror("Name or service not known")
        with pytest.raises(ValueError, match="Could not resolve"):
            validate_repo_url("https://nonexistent.invalid/repo")
