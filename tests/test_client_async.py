"""Additional unit tests for async client methods."""

import uuid
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from any_llm_platform_client import AnyLLMPlatformClient


@pytest.mark.asyncio
async def test_aget_solved_challenge_success():
    """Test async get_solved_challenge convenience method."""
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
        patch("any_llm_platform_client.client.httpx.AsyncClient") as mock_client_class,
    ):
        mock_parse.return_value = MagicMock(base64_encoded_private_key="test-key")
        mock_load.return_value = MagicMock()
        mock_extract.return_value = "test-public-key"
        mock_decrypt.return_value = str(test_uuid)

        mock_client_instance = MagicMock()
        mock_client_instance.post = AsyncMock(return_value=challenge_response)
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

        result = await client.aget_solved_challenge(any_llm_key)

    assert isinstance(result, uuid.UUID)
    assert result == test_uuid
    mock_client_instance.post.assert_called_once()


@pytest.mark.asyncio
async def test_aensure_valid_token_returns_existing_when_valid():
    """Test that _aensure_valid_token returns existing token when valid."""
    client = AnyLLMPlatformClient("https://api.example.com")
    any_llm_key = "ANY.v1.12345678.abcdef01-dGVzdC1wcml2YXRlLWtleQ=="

    # Set valid token
    client.access_token = "valid-async-token"
    client.token_expires_at = datetime.now() + timedelta(hours=1)

    with patch.object(client, "arefresh_access_token", new_callable=AsyncMock) as mock_refresh:
        result = await client._aensure_valid_token(any_llm_key)

    assert result == "valid-async-token"
    mock_refresh.assert_not_called()


@pytest.mark.asyncio
async def test_aensure_valid_token_refreshes_when_expired():
    """Test that _aensure_valid_token refreshes when token is expired."""
    client = AnyLLMPlatformClient("https://api.example.com")
    any_llm_key = "ANY.v1.12345678.abcdef01-dGVzdC1wcml2YXRlLWtleQ=="

    # Set expired token
    client.access_token = "old-async-token"
    client.token_expires_at = datetime.now() - timedelta(hours=1)

    async def mock_refresh_side_effect(_key):
        client.access_token = "new-async-token"
        return "new-async-token"

    with patch.object(client, "arefresh_access_token", new_callable=AsyncMock) as mock_refresh:
        mock_refresh.side_effect = mock_refresh_side_effect
        result = await client._aensure_valid_token(any_llm_key)

    assert result == "new-async-token"
    mock_refresh.assert_called_once_with(any_llm_key)


@pytest.mark.asyncio
async def test_aget_decrypted_provider_key_with_updated_at_none():
    """Test async get_decrypted_provider_key when updated_at is None."""
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
        "provider": "google",
        "project_id": proj_uuid,
        "created_at": "2026-02-24T12:00:00",
        # No updated_at field
    }

    with (
        patch("any_llm_platform_client.client.parse_any_llm_key") as mock_parse,
        patch("any_llm_platform_client.client.load_private_key") as mock_load,
        patch("any_llm_platform_client.client.decrypt_data") as mock_decrypt,
        patch("any_llm_platform_client.client.httpx.AsyncClient") as mock_client_class,
    ):
        mock_parse.return_value = MagicMock(base64_encoded_private_key="test-key")
        mock_load.return_value = MagicMock()
        mock_decrypt.return_value = "sk-google-key"

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = provider_key_response

        mock_client_instance = MagicMock()
        mock_client_instance.get = AsyncMock(return_value=mock_response)
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

        result = await client.aget_decrypted_provider_key(any_llm_key, "google")

    assert result.api_key == "sk-google-key"  # pragma: allowlist secret
    assert result.provider == "google"
    assert result.updated_at is None


@pytest.mark.asyncio
async def test_arefresh_access_token_error_handling():
    """Test that async refresh_access_token properly handles errors."""
    client = AnyLLMPlatformClient("https://api.example.com")
    any_llm_key = "ANY.v1.12345678.abcdef01-dGVzdC1wcml2YXRlLWtleQ=="

    challenge_response = MagicMock()
    challenge_response.status_code = 200
    challenge_response.json.return_value = {"encrypted_challenge": "test-encrypted-challenge"}

    error_response = MagicMock()
    error_response.status_code = 500
    error_response.json.return_value = {"error": "Server error"}

    with (
        patch("any_llm_platform_client.client.parse_any_llm_key") as mock_parse,
        patch("any_llm_platform_client.client.load_private_key") as mock_load,
        patch("any_llm_platform_client.client.extract_public_key") as mock_extract,
        patch("any_llm_platform_client.client.decrypt_data") as mock_decrypt,
        patch("any_llm_platform_client.client.httpx.AsyncClient") as mock_client_class,
    ):
        from any_llm_platform_client.exceptions import ChallengeCreationError

        mock_parse.return_value = MagicMock(base64_encoded_private_key="test-key")
        mock_load.return_value = MagicMock()
        mock_extract.return_value = "test-public-key"
        mock_decrypt.return_value = str(uuid.uuid4())

        mock_client_instance = MagicMock()
        # Challenge succeeds, but token request fails
        mock_client_instance.post = AsyncMock(side_effect=[challenge_response, error_response])
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

        # Should raise ChallengeCreationError
        with pytest.raises(ChallengeCreationError, match="status: 500"):
            await client.arefresh_access_token(any_llm_key)


@pytest.mark.asyncio
async def test_arequest_access_token_stores_token_and_expiry():
    """Test that async request_access_token stores token and expiration."""
    client = AnyLLMPlatformClient("https://api.example.com")
    challenge_uuid = uuid.uuid4()

    # Ensure no token is set initially
    client.access_token = None
    client.token_expires_at = None

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
    assert client.token_expires_at > datetime.now()


@pytest.mark.asyncio
async def test_arequest_access_token_error():
    """Test failed async access token request."""
    from any_llm_platform_client.exceptions import ChallengeCreationError

    client = AnyLLMPlatformClient("https://api.example.com")
    challenge_uuid = uuid.uuid4()
    mock_response = MagicMock()
    mock_response.status_code = 403
    mock_response.json.return_value = {"error": "Forbidden"}

    with patch("any_llm_platform_client.client.httpx.AsyncClient") as mock_client_class:
        mock_client_instance = MagicMock()
        mock_client_instance.post = AsyncMock(return_value=mock_response)
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

        with pytest.raises(ChallengeCreationError, match="status: 403"):
            await client.arequest_access_token(challenge_uuid)


@pytest.mark.asyncio
async def test_arefresh_access_token_updates_token():
    """Test that async refresh updates the stored token."""
    client = AnyLLMPlatformClient("https://api.example.com")
    any_llm_key = "ANY.v1.12345678.abcdef01-dGVzdC1wcml2YXRlLWtleQ=="

    # Store initial token
    client.access_token = "initial-async-token"
    initial_expiration = client.token_expires_at

    challenge_response = MagicMock()
    challenge_response.status_code = 200
    challenge_response.json.return_value = {"encrypted_challenge": "test-encrypted-challenge"}

    token_response = MagicMock()
    token_response.status_code = 200
    token_response.json.return_value = {
        "access_token": "refreshed-async-token",
        "token_type": "bearer",
    }

    with (
        patch("any_llm_platform_client.client.parse_any_llm_key") as mock_parse,
        patch("any_llm_platform_client.client.load_private_key") as mock_load,
        patch("any_llm_platform_client.client.extract_public_key") as mock_extract,
        patch("any_llm_platform_client.client.decrypt_data") as mock_decrypt,
        patch("any_llm_platform_client.client.httpx.AsyncClient") as mock_client_class,
    ):
        mock_parse.return_value = MagicMock(base64_encoded_private_key="test-key")
        mock_load.return_value = MagicMock()
        mock_extract.return_value = "test-public-key"
        mock_decrypt.return_value = str(uuid.uuid4())

        mock_client_instance = MagicMock()
        mock_client_instance.post = AsyncMock(side_effect=[challenge_response, token_response])
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

        # Refresh
        await client.arefresh_access_token(any_llm_key)

        # Verify token was updated
        assert client.access_token == "refreshed-async-token"
        assert client.access_token != "initial-async-token"
        assert client.token_expires_at != initial_expiration
