"""Pytest configuration and fixtures."""

import base64
import secrets
import sys
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Add src directory to path for testing
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))


# =============================================================================
# Test Data Constants
# =============================================================================

SAMPLE_API_URL = "https://api.example.com"
SAMPLE_JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test-payload.test-signature"
SAMPLE_PROJECT_ID = "test-project-id"


# =============================================================================
# Key and Crypto Fixtures
# =============================================================================


@pytest.fixture
def valid_any_llm_key() -> str:
    """Valid ANY_LLM_KEY for testing."""
    return "ANY.v1.12345678.abcdef01-YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3OA=="  # pragma: allowlist secret


@pytest.fixture
def sample_jwt_token() -> str:
    """Sample JWT token for testing."""
    return SAMPLE_JWT_TOKEN


@pytest.fixture
def sample_api_url() -> str:
    """Sample API URL for testing."""
    return SAMPLE_API_URL


@pytest.fixture
def sample_project_id() -> str:
    """Sample project ID for testing."""
    return SAMPLE_PROJECT_ID


def make_valid_32byte_key() -> str:
    """Generate a valid 32-byte base64-encoded key for testing."""
    return base64.b64encode(secrets.token_bytes(32)).decode("utf-8")


# =============================================================================
# HTTP Client Mocking Fixtures
# =============================================================================


@pytest.fixture
def mock_httpx_client():
    """Create a mocked httpx.Client context manager.

    Yields the inner mock client that can be used to set up responses.

    Example:
        def test_something(mock_httpx_client):
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"data": "test"}
            mock_httpx_client.get.return_value = mock_response

            # Your test code here
    """
    with patch("httpx.Client") as mock_client_class:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client_class.return_value = mock_client
        yield mock_client


@pytest.fixture
def mock_httpx_async_client():
    """Create a mocked httpx.AsyncClient context manager.

    Yields the inner mock client instance that can be used to set up async responses.

    Example:
        @pytest.mark.asyncio
        async def test_async_something(mock_httpx_async_client):
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"data": "test"}
            mock_httpx_async_client.get = AsyncMock(return_value=mock_response)

            # Your async test code here
    """
    with patch("any_llm_platform_client.client.httpx.AsyncClient") as mock_client_class:
        mock_client_instance = MagicMock()
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)
        yield mock_client_instance


# =============================================================================
# Response Factory Fixtures
# =============================================================================


@pytest.fixture
def make_mock_response():
    """Factory fixture for creating mock HTTP responses.

    Returns a function that creates mock responses with the given parameters.

    Example:
        def test_something(make_mock_response):
            success_response = make_mock_response(200, {"result": "ok"})
            error_response = make_mock_response(404, {"error": "Not found"})
    """

    def _make_response(status_code: int, json_data: dict) -> MagicMock:
        mock_response = MagicMock()
        mock_response.status_code = status_code
        mock_response.json.return_value = json_data
        return mock_response

    return _make_response


@pytest.fixture
def make_auth_response(make_mock_response):
    """Factory for creating authentication response mocks.

    Example:
        def test_login(make_auth_response):
            auth_response = make_auth_response("my-token-123")
    """

    def _make_auth_response(access_token: str = SAMPLE_JWT_TOKEN) -> MagicMock:
        return make_mock_response(200, {"access_token": access_token, "token_type": "bearer"})

    return _make_auth_response


@pytest.fixture
def make_challenge_response(make_mock_response):
    """Factory for creating challenge response mocks.

    Example:
        def test_challenge(make_challenge_response):
            challenge_response = make_challenge_response("encrypted-challenge-data")
    """

    def _make_challenge_response(encrypted_challenge: str) -> MagicMock:
        return make_mock_response(200, {"encrypted_challenge": encrypted_challenge})

    return _make_challenge_response


@pytest.fixture
def make_provider_key_response(make_mock_response):
    """Factory for creating provider key response mocks.

    Example:
        def test_key_fetch(make_provider_key_response):
            key_response = make_provider_key_response("openai", "encrypted-key-data")
    """

    def _make_provider_key_response(
        provider: str = "openai",
        encrypted_key: str = "encrypted-test-key",
        project_id: str | None = None,
        key_id: str | None = None,
    ) -> MagicMock:
        return make_mock_response(
            200,
            {
                "id": key_id or str(uuid.uuid4()),
                "encrypted_key": encrypted_key,
                "provider": provider,
                "project_id": project_id or str(uuid.uuid4()),
                "created_at": "2026-02-24T12:00:00",
            },
        )

    return _make_provider_key_response


@pytest.fixture
def make_error_response(make_mock_response):
    """Factory for creating error response mocks.

    Example:
        def test_error(make_error_response):
            error_response = make_error_response(404, "Not found")
    """

    def _make_error_response(status_code: int, detail: str) -> MagicMock:
        return make_mock_response(status_code, {"detail": detail})

    return _make_error_response
