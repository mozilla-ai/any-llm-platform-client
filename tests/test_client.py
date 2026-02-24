"""Tests for the AnyLLMPlatformClient with httpx."""

import uuid
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from any_llm_platform_client import AnyLLMPlatformClient, ChallengeCreationError, ProviderKeyFetchError


def test_client_default_url():
    client = AnyLLMPlatformClient()
    assert client.any_llm_platform_url == "http://localhost:8000/api/v1"


def test_client_custom_url():
    custom_url = "https://api.example.com/v1"
    client = AnyLLMPlatformClient(custom_url)
    assert client.any_llm_platform_url == custom_url


def test_create_challenge_success():
    client = AnyLLMPlatformClient("https://api.example.com")
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"encrypted_challenge": "test-challenge"}

    with patch("httpx.Client") as mock_client_class:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_response
        mock_client_class.return_value = mock_client

        result = client.create_challenge("test-public-key")

    assert result == {"encrypted_challenge": "test-challenge"}
    mock_client.post.assert_called_once_with(
        "https://api.example.com/auth/",
        json={"encryption_key": "test-public-key"},
    )


def test_create_challenge_error():
    client = AnyLLMPlatformClient("https://api.example.com")
    mock_response = MagicMock()
    mock_response.status_code = 400
    mock_response.json.return_value = {"error": "Bad request"}

    with patch("httpx.Client") as mock_client_class:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_response
        mock_client_class.return_value = mock_client

        with pytest.raises(ChallengeCreationError, match="status: 400"):
            client.create_challenge("test-public-key")


def test_create_challenge_no_project_error():
    client = AnyLLMPlatformClient("https://api.example.com")
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_response.json.return_value = {"error": "No project found"}

    with patch("httpx.Client") as mock_client_class:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_response
        mock_client_class.return_value = mock_client

        with pytest.raises(ChallengeCreationError, match="No project found"):
            client.create_challenge("test-public-key")


def test_fetch_provider_key_success():
    """Test fetching provider key with Bearer token."""
    client = AnyLLMPlatformClient("https://api.example.com")
    access_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "encrypted_key": "encrypted-api-key",
        "provider": "openai",
        "project_id": "proj-123",
    }

    with patch("httpx.Client") as mock_client_class:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_response
        mock_client_class.return_value = mock_client

        result = client.fetch_provider_key("openai", access_token)

    assert result == {
        "encrypted_key": "encrypted-api-key",
        "provider": "openai",
        "project_id": "proj-123",
    }
    mock_client.get.assert_called_once_with(
        "https://api.example.com/provider-keys/openai",
        headers={"Authorization": f"Bearer {access_token}"},
    )


def test_fetch_provider_key_error():
    """Test failed provider key fetch with Bearer token."""
    client = AnyLLMPlatformClient("https://api.example.com")
    access_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_response.json.return_value = {"error": "Unauthorized"}

    with patch("httpx.Client") as mock_client_class:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = mock_response
        mock_client_class.return_value = mock_client

        with pytest.raises(ProviderKeyFetchError, match="status: 401"):
            client.fetch_provider_key("openai", access_token)


@pytest.mark.asyncio
async def test_acreate_challenge_success():
    client = AnyLLMPlatformClient("https://api.example.com")
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"encrypted_challenge": "test-challenge"}

    with patch("any_llm_platform_client.client.httpx.AsyncClient") as mock_client_class:
        mock_client_instance = MagicMock()
        mock_client_instance.post = AsyncMock(return_value=mock_response)
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

        result = await client.acreate_challenge("test-public-key")

    assert result == {"encrypted_challenge": "test-challenge"}
    mock_client_instance.post.assert_called_once_with(
        "https://api.example.com/auth/",
        json={"encryption_key": "test-public-key"},
    )


@pytest.mark.asyncio
async def test_acreate_challenge_error():
    client = AnyLLMPlatformClient("https://api.example.com")
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.json.return_value = {"error": "Internal server error"}

    with patch("any_llm_platform_client.client.httpx.AsyncClient") as mock_client_class:
        mock_client_instance = MagicMock()
        mock_client_instance.post = AsyncMock(return_value=mock_response)
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

        with pytest.raises(ChallengeCreationError, match="status: 500"):
            await client.acreate_challenge("test-public-key")


@pytest.mark.asyncio
async def test_afetch_provider_key_success():
    """Test successful async provider key fetch with Bearer token."""
    client = AnyLLMPlatformClient("https://api.example.com")
    access_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "encrypted_key": "encrypted-api-key",
        "provider": "anthropic",
        "project_id": "proj-456",
    }

    with patch("any_llm_platform_client.client.httpx.AsyncClient") as mock_client_class:
        mock_client_instance = MagicMock()
        mock_client_instance.get = AsyncMock(return_value=mock_response)
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

        result = await client.afetch_provider_key("anthropic", access_token)

    assert result == {
        "encrypted_key": "encrypted-api-key",
        "provider": "anthropic",
        "project_id": "proj-456",
    }
    mock_client_instance.get.assert_called_once_with(
        "https://api.example.com/provider-keys/anthropic",
        headers={"Authorization": f"Bearer {access_token}"},
    )


@pytest.mark.asyncio
async def test_afetch_provider_key_error():
    """Test failed async provider key fetch with Bearer token."""
    client = AnyLLMPlatformClient("https://api.example.com")
    access_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    mock_response = MagicMock()
    mock_response.status_code = 403
    mock_response.json.return_value = {"error": "Forbidden"}

    with patch("any_llm_platform_client.client.httpx.AsyncClient") as mock_client_class:
        mock_client_instance = MagicMock()
        mock_client_instance.get = AsyncMock(return_value=mock_response)
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

        with pytest.raises(ProviderKeyFetchError, match="status: 403"):
            await client.afetch_provider_key("anthropic", access_token)


def test_request_access_token_success():
    """Test successful access token request."""
    client = AnyLLMPlatformClient("https://api.example.com")
    challenge_uuid = uuid.uuid4()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "token_type": "bearer",
    }

    with patch("httpx.Client") as mock_client_class:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_response
        mock_client_class.return_value = mock_client

        result = client.request_access_token(challenge_uuid)

    assert result == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    assert client.access_token == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    assert client.token_expires_at is not None
    mock_client.post.assert_called_once_with(
        "https://api.example.com/auth/token",
        json={"solved_challenge": str(challenge_uuid)},
    )


def test_request_access_token_error():
    """Test failed access token request."""
    client = AnyLLMPlatformClient("https://api.example.com")
    challenge_uuid = uuid.uuid4()
    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_response.json.return_value = {"error": "Invalid challenge"}

    with patch("httpx.Client") as mock_client_class:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_response
        mock_client_class.return_value = mock_client

        with pytest.raises(ChallengeCreationError, match="status: 401"):
            client.request_access_token(challenge_uuid)


@pytest.mark.asyncio
async def test_arequest_access_token_success():
    """Test successful async access token request."""
    client = AnyLLMPlatformClient("https://api.example.com")
    challenge_uuid = uuid.uuid4()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "token_type": "bearer",
    }

    with patch("any_llm_platform_client.client.httpx.AsyncClient") as mock_client_class:
        mock_client_instance = MagicMock()
        mock_client_instance.post = AsyncMock(return_value=mock_response)
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

        result = await client.arequest_access_token(challenge_uuid)

    assert result == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    assert client.access_token == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    assert client.token_expires_at is not None


def test_refresh_access_token_success():
    """Test successful token refresh."""

    client = AnyLLMPlatformClient("https://api.example.com")
    any_llm_key = "ANY.v1.12345678.abcdef01-dGVzdC1wcml2YXRlLWtleQ=="

    # Mock the challenge creation response
    challenge_response = MagicMock()
    challenge_response.status_code = 200
    challenge_response.json.return_value = {"encrypted_challenge": "test-encrypted-challenge"}

    # Mock the token response
    token_response = MagicMock()
    token_response.status_code = 200
    token_response.json.return_value = {
        "access_token": "new-token-12345",
        "token_type": "bearer",
    }

    with (
        patch("any_llm_platform_client.client.parse_any_llm_key") as mock_parse,
        patch("any_llm_platform_client.client.load_private_key") as mock_load_key,
        patch("any_llm_platform_client.client.extract_public_key") as mock_extract_key,
        patch("any_llm_platform_client.client.decrypt_data") as mock_decrypt,
        patch("httpx.Client") as mock_client_class,
    ):
        # Setup mocks
        mock_parse.return_value = MagicMock(base64_encoded_private_key="test-key")
        mock_load_key.return_value = MagicMock()
        mock_extract_key.return_value = "test-public-key"
        mock_decrypt.return_value = str(uuid.uuid4())

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        # First call is for challenge creation, second is for token request
        mock_client.post.side_effect = [challenge_response, token_response]
        mock_client_class.return_value = mock_client

        # Set an old token
        client.access_token = "old-token"

        # Refresh the token
        new_token = client.refresh_access_token(any_llm_key)

        # Verify the token was refreshed
        assert new_token == "new-token-12345"
        assert client.access_token == "new-token-12345"
        assert client.token_expires_at is not None


def test_refresh_access_token_updates_stored_token():
    """Test that refresh_access_token updates the client's stored token."""

    client = AnyLLMPlatformClient("https://api.example.com")
    any_llm_key = "ANY.v1.12345678.abcdef01-dGVzdC1wcml2YXRlLWtleQ=="

    # Store initial token
    client.access_token = "initial-token"
    initial_expiration = client.token_expires_at

    challenge_response = MagicMock()
    challenge_response.status_code = 200
    challenge_response.json.return_value = {"encrypted_challenge": "test-encrypted-challenge"}

    token_response = MagicMock()
    token_response.status_code = 200
    token_response.json.return_value = {
        "access_token": "refreshed-token",
        "token_type": "bearer",
    }

    with (
        patch("any_llm_platform_client.client.parse_any_llm_key") as mock_parse,
        patch("any_llm_platform_client.client.load_private_key") as mock_load_key,
        patch("any_llm_platform_client.client.extract_public_key") as mock_extract_key,
        patch("any_llm_platform_client.client.decrypt_data") as mock_decrypt,
        patch("httpx.Client") as mock_client_class,
    ):
        mock_parse.return_value = MagicMock(base64_encoded_private_key="test-key")
        mock_load_key.return_value = MagicMock()
        mock_extract_key.return_value = "test-public-key"
        mock_decrypt.return_value = str(uuid.uuid4())

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.side_effect = [challenge_response, token_response]
        mock_client_class.return_value = mock_client

        # Refresh
        client.refresh_access_token(any_llm_key)

        # Verify token was updated
        assert client.access_token == "refreshed-token"
        assert client.access_token != "initial-token"
        assert client.token_expires_at != initial_expiration


@pytest.mark.asyncio
async def test_arefresh_access_token_success():
    """Test successful async token refresh."""
    client = AnyLLMPlatformClient("https://api.example.com")
    any_llm_key = "ANY.v1.12345678.abcdef01-dGVzdC1wcml2YXRlLWtleQ=="

    challenge_response = MagicMock()
    challenge_response.status_code = 200
    challenge_response.json.return_value = {"encrypted_challenge": "test-encrypted-challenge"}

    token_response = MagicMock()
    token_response.status_code = 200
    token_response.json.return_value = {
        "access_token": "async-refreshed-token",
        "token_type": "bearer",
    }

    with (
        patch("any_llm_platform_client.client.parse_any_llm_key") as mock_parse,
        patch("any_llm_platform_client.client.load_private_key") as mock_load_key,
        patch("any_llm_platform_client.client.extract_public_key") as mock_extract_key,
        patch("any_llm_platform_client.client.decrypt_data") as mock_decrypt,
        patch("any_llm_platform_client.client.httpx.AsyncClient") as mock_client_class,
    ):
        mock_parse.return_value = MagicMock(base64_encoded_private_key="test-key")
        mock_load_key.return_value = MagicMock()
        mock_extract_key.return_value = "test-public-key"
        mock_decrypt.return_value = str(uuid.uuid4())

        mock_client_instance = MagicMock()
        # First call is for challenge creation, second is for token request
        mock_client_instance.post = AsyncMock(side_effect=[challenge_response, token_response])
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

        # Refresh
        new_token = await client.arefresh_access_token(any_llm_key)

        # Verify
        assert new_token == "async-refreshed-token"
        assert client.access_token == "async-refreshed-token"
        assert client.token_expires_at is not None


def test_refresh_access_token_error_handling():
    """Test that refresh_access_token properly handles errors."""
    client = AnyLLMPlatformClient("https://api.example.com")
    any_llm_key = "ANY.v1.12345678.abcdef01-dGVzdC1wcml2YXRlLWtleQ=="

    challenge_response = MagicMock()
    challenge_response.status_code = 200
    challenge_response.json.return_value = {"encrypted_challenge": "test-encrypted-challenge"}

    error_response = MagicMock()
    error_response.status_code = 401
    error_response.json.return_value = {"error": "Invalid challenge"}

    with (
        patch("any_llm_platform_client.client.parse_any_llm_key") as mock_parse,
        patch("any_llm_platform_client.client.load_private_key") as mock_load_key,
        patch("any_llm_platform_client.client.extract_public_key") as mock_extract_key,
        patch("any_llm_platform_client.client.decrypt_data") as mock_decrypt,
        patch("httpx.Client") as mock_client_class,
    ):
        mock_parse.return_value = MagicMock(base64_encoded_private_key="test-key")
        mock_load_key.return_value = MagicMock()
        mock_extract_key.return_value = "test-public-key"
        mock_decrypt.return_value = str(uuid.uuid4())

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        # Challenge succeeds, but token request fails
        mock_client.post.side_effect = [challenge_response, error_response]
        mock_client_class.return_value = mock_client

        # Should raise ChallengeCreationError
        with pytest.raises(ChallengeCreationError, match="status: 401"):
            client.refresh_access_token(any_llm_key)


class TestClientEdgeCases:
    """Additional edge case tests for AnyLLMPlatformClient."""

    def test_client_name_in_headers(self):
        """Test that client_name is included in headers when set."""
        client = AnyLLMPlatformClient("https://api.example.com", client_name="test-client")
        access_token = "test-token-123"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"encrypted_key": "test", "provider": "openai", "project_id": "proj-1"}

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client

            client.fetch_provider_key("openai", access_token)

        # Verify client name was included in headers
        call_args = mock_client.get.call_args
        assert "AnyLLM-Client-Name" in call_args[1]["headers"]
        assert call_args[1]["headers"]["AnyLLM-Client-Name"] == "test-client"

    def test_client_name_not_in_headers_when_none(self):
        """Test that client_name is not included in headers when None."""
        client = AnyLLMPlatformClient("https://api.example.com", client_name=None)
        access_token = "test-token-123"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"encrypted_key": "test", "provider": "openai", "project_id": "proj-1"}

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client

            client.fetch_provider_key("openai", access_token)

        # Verify client name was not included in headers
        call_args = mock_client.get.call_args
        assert "AnyLLM-Client-Name" not in call_args[1]["headers"]

    @pytest.mark.asyncio
    async def test_async_client_name_in_headers(self):
        """Test that client_name is included in headers for async methods."""
        client = AnyLLMPlatformClient("https://api.example.com", client_name="async-client")
        access_token = "test-token-123"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"encrypted_key": "test", "provider": "anthropic", "project_id": "proj-2"}

        with patch("any_llm_platform_client.client.httpx.AsyncClient") as mock_client_class:
            mock_client_instance = MagicMock()
            mock_client_instance.get = AsyncMock(return_value=mock_response)
            mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client_instance)
            mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

            await client.afetch_provider_key("anthropic", access_token)

        # Verify client name was included in headers
        call_args = mock_client_instance.get.call_args
        assert "AnyLLM-Client-Name" in call_args[1]["headers"]
        assert call_args[1]["headers"]["AnyLLM-Client-Name"] == "async-client"

    def test_solve_challenge_returns_uuid(self):
        """Test that solve_challenge returns a UUID."""
        client = AnyLLMPlatformClient()
        private_key = MagicMock()
        test_uuid = uuid.uuid4()

        with patch("any_llm_platform_client.client.decrypt_data") as mock_decrypt:
            mock_decrypt.return_value = str(test_uuid)
            result = client.solve_challenge("encrypted-challenge", private_key)

        assert isinstance(result, uuid.UUID)
        assert result == test_uuid

    def test_get_public_key_convenience_method(self):
        """Test get_public_key convenience method."""
        client = AnyLLMPlatformClient()
        any_llm_key = "ANY.v1.12345678.abcdef01-dGVzdC1wcml2YXRlLWtleQ=="

        with (
            patch("any_llm_platform_client.client.parse_any_llm_key") as mock_parse,
            patch("any_llm_platform_client.client.load_private_key") as mock_load,
            patch("any_llm_platform_client.client.extract_public_key") as mock_extract,
        ):
            mock_parse.return_value = MagicMock(base64_encoded_private_key="test-key")
            mock_load.return_value = MagicMock()
            mock_extract.return_value = "test-public-key-base64"

            result = client.get_public_key(any_llm_key)

        assert result == "test-public-key-base64"
        mock_parse.assert_called_once_with(any_llm_key)
        mock_load.assert_called_once()
        mock_extract.assert_called_once()

    def test_get_solved_challenge_convenience_method(self):
        """Test get_solved_challenge convenience method."""
        client = AnyLLMPlatformClient("https://api.example.com")
        any_llm_key = "ANY.v1.12345678.abcdef01-dGVzdC1wcml2YXRlLWtleQ=="
        test_uuid = uuid.uuid4()

        challenge_response = MagicMock()
        challenge_response.status_code = 200
        challenge_response.json.return_value = {"encrypted_challenge": "test-challenge"}

        with (
            patch("any_llm_platform_client.client.parse_any_llm_key") as mock_parse,
            patch("any_llm_platform_client.client.load_private_key") as mock_load,
            patch("any_llm_platform_client.client.extract_public_key") as mock_extract,
            patch("any_llm_platform_client.client.decrypt_data") as mock_decrypt,
            patch("httpx.Client") as mock_client_class,
        ):
            mock_parse.return_value = MagicMock(base64_encoded_private_key="test-key")
            mock_load.return_value = MagicMock()
            mock_extract.return_value = "test-public-key"
            mock_decrypt.return_value = str(test_uuid)

            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = challenge_response
            mock_client_class.return_value = mock_client

            result = client.get_solved_challenge(any_llm_key)

        assert isinstance(result, uuid.UUID)
        assert result == test_uuid

    def test_get_decrypted_provider_key_returns_dataclass(self):
        """Test that get_decrypted_provider_key returns DecryptedProviderKey dataclass."""
        client = AnyLLMPlatformClient("https://api.example.com")
        any_llm_key = "ANY.v1.12345678.abcdef01-dGVzdC1wcml2YXRlLWtleQ=="

        # Mock token already exists and is valid
        client.access_token = "test-token"
        client.token_expires_at = datetime.now() + timedelta(hours=1)

        key_uuid = str(uuid.uuid4())
        proj_uuid = str(uuid.uuid4())

        provider_key_response = {
            "id": key_uuid,
            "encrypted_key": "encrypted-value",
            "provider": "openai",
            "project_id": proj_uuid,
            "created_at": "2026-02-24T12:00:00",
            "updated_at": "2026-02-24T13:00:00",
        }

        with (
            patch("any_llm_platform_client.client.parse_any_llm_key") as mock_parse,
            patch("any_llm_platform_client.client.load_private_key") as mock_load,
            patch("any_llm_platform_client.client.decrypt_data") as mock_decrypt,
            patch("httpx.Client") as mock_client_class,
        ):
            mock_parse.return_value = MagicMock(base64_encoded_private_key="test-key")
            mock_load.return_value = MagicMock()
            mock_decrypt.return_value = "sk-decrypted-api-key"

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = provider_key_response

            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = client.get_decrypted_provider_key(any_llm_key, "openai")

        assert result.api_key == "sk-decrypted-api-key"  # pragma: allowlist secret
        assert result.provider_key_id == uuid.UUID(key_uuid)
        assert result.project_id == uuid.UUID(proj_uuid)
        assert result.provider == "openai"
        assert isinstance(result.created_at, datetime)
        assert isinstance(result.updated_at, datetime)

    def test_decrypt_provider_key_value(self):
        """Test decrypt_provider_key_value method."""
        client = AnyLLMPlatformClient()
        private_key = MagicMock()
        encrypted_key = "encrypted-base64-key"

        with patch("any_llm_platform_client.client.decrypt_data") as mock_decrypt:
            mock_decrypt.return_value = "sk-decrypted-key"
            result = client.decrypt_provider_key_value(encrypted_key, private_key)

        assert result == "sk-decrypted-key"
        mock_decrypt.assert_called_once_with(encrypted_key, private_key)

    def test_ensure_valid_token_refreshes_when_missing(self):
        """Test that _ensure_valid_token refreshes when no token is set."""
        client = AnyLLMPlatformClient("https://api.example.com")
        any_llm_key = "ANY.v1.12345678.abcdef01-dGVzdC1wcml2YXRlLWtleQ=="

        # No token set
        assert client.access_token is None

        def mock_refresh_side_effect(_key):
            client.access_token = "new-token"
            return "new-token"

        with patch.object(client, "refresh_access_token", side_effect=mock_refresh_side_effect) as mock_refresh:
            result = client._ensure_valid_token(any_llm_key)

        assert result == "new-token"
        mock_refresh.assert_called_once_with(any_llm_key)

    def test_ensure_valid_token_refreshes_when_expired(self):
        """Test that _ensure_valid_token refreshes when token is expired."""
        client = AnyLLMPlatformClient("https://api.example.com")
        any_llm_key = "ANY.v1.12345678.abcdef01-dGVzdC1wcml2YXRlLWtleQ=="

        # Set expired token
        client.access_token = "old-token"
        client.token_expires_at = datetime.now() - timedelta(hours=1)

        def mock_refresh_side_effect(_key):
            client.access_token = "new-token"
            return "new-token"

        with patch.object(client, "refresh_access_token", side_effect=mock_refresh_side_effect) as mock_refresh:
            result = client._ensure_valid_token(any_llm_key)

        assert result == "new-token"
        mock_refresh.assert_called_once_with(any_llm_key)

    def test_ensure_valid_token_returns_existing_when_valid(self):
        """Test that _ensure_valid_token returns existing token when valid."""
        client = AnyLLMPlatformClient("https://api.example.com")
        any_llm_key = "ANY.v1.12345678.abcdef01-dGVzdC1wcml2YXRlLWtleQ=="

        # Set valid token
        client.access_token = "valid-token"
        client.token_expires_at = datetime.now() + timedelta(hours=1)

        with patch.object(client, "refresh_access_token") as mock_refresh:
            result = client._ensure_valid_token(any_llm_key)

        assert result == "valid-token"
        mock_refresh.assert_not_called()

    @pytest.mark.asyncio
    async def test_aensure_valid_token_refreshes_when_missing(self):
        """Test that _aensure_valid_token refreshes when token is missing."""
        client = AnyLLMPlatformClient("https://api.example.com")
        any_llm_key = "ANY.v1.12345678.abcdef01-dGVzdC1wcml2YXRlLWtleQ=="

        # No token set
        assert client.access_token is None

        async def mock_refresh_side_effect(_key):
            client.access_token = "new-async-token"
            return "new-async-token"

        with patch.object(client, "arefresh_access_token", new_callable=AsyncMock) as mock_refresh:
            mock_refresh.side_effect = mock_refresh_side_effect
            result = await client._aensure_valid_token(any_llm_key)

        assert result == "new-async-token"
        mock_refresh.assert_called_once_with(any_llm_key)

    @pytest.mark.asyncio
    async def test_aget_decrypted_provider_key_returns_dataclass(self):
        """Test that async get_decrypted_provider_key returns DecryptedProviderKey."""
        client = AnyLLMPlatformClient("https://api.example.com")
        any_llm_key = "ANY.v1.12345678.abcdef01-dGVzdC1wcml2YXRlLWtleQ=="

        # Mock valid token
        client.access_token = "test-token"
        client.token_expires_at = datetime.now() + timedelta(hours=1)

        key_uuid = str(uuid.uuid4())
        proj_uuid = str(uuid.uuid4())

        provider_key_response = {
            "id": key_uuid,
            "encrypted_key": "encrypted-value",
            "provider": "anthropic",
            "project_id": proj_uuid,
            "created_at": "2026-02-24T12:00:00",
        }

        with (
            patch("any_llm_platform_client.client.parse_any_llm_key") as mock_parse,
            patch("any_llm_platform_client.client.load_private_key") as mock_load,
            patch("any_llm_platform_client.client.decrypt_data") as mock_decrypt,
            patch("any_llm_platform_client.client.httpx.AsyncClient") as mock_client_class,
        ):
            mock_parse.return_value = MagicMock(base64_encoded_private_key="test-key")
            mock_load.return_value = MagicMock()
            mock_decrypt.return_value = "sk-anthropic-key"

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = provider_key_response

            mock_client_instance = MagicMock()
            mock_client_instance.get = AsyncMock(return_value=mock_response)
            mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client_instance)
            mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

            result = await client.aget_decrypted_provider_key(any_llm_key, "anthropic")

        assert result.api_key == "sk-anthropic-key"  # pragma: allowlist secret
        assert result.provider == "anthropic"
        assert result.updated_at is None  # No updated_at in response

    def test_handle_challenge_error_with_no_project(self):
        """Test error handling for no project found."""
        client = AnyLLMPlatformClient("https://api.example.com")
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.json.return_value = {"detail": "No project found for the provided public key"}

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_client_class.return_value = mock_client

            with pytest.raises(ChallengeCreationError, match="No project found"):
                client.create_challenge("test-public-key")

    def test_handle_provider_key_error_with_detail(self):
        """Test error handling for provider key fetch with detail."""
        client = AnyLLMPlatformClient("https://api.example.com")
        access_token = "test-token"
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.json.return_value = {"detail": "Insufficient permissions"}

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client

            with pytest.raises(ProviderKeyFetchError, match="Insufficient permissions"):
                client.fetch_provider_key("openai", access_token)
