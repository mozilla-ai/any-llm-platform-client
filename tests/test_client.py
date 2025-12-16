"""Tests for the AnyLLMPlatformClient with httpx."""

import uuid
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
    client = AnyLLMPlatformClient("https://api.example.com")
    challenge_uuid = uuid.uuid4()
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

        result = client.fetch_provider_key("openai", "test-public-key", challenge_uuid)

    assert result == {
        "encrypted_key": "encrypted-api-key",
        "provider": "openai",
        "project_id": "proj-123",
    }
    mock_client.get.assert_called_once_with(
        "https://api.example.com/provider-keys/openai",
        headers={
            "encryption-key": "test-public-key",
            "AnyLLM-Challenge-Response": str(challenge_uuid),
        },
    )


def test_fetch_provider_key_error():
    client = AnyLLMPlatformClient("https://api.example.com")
    challenge_uuid = uuid.uuid4()
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
            client.fetch_provider_key("openai", "test-public-key", challenge_uuid)


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
    """Test successful async provider key fetch."""
    client = AnyLLMPlatformClient("https://api.example.com")
    challenge_uuid = uuid.uuid4()
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

        result = await client.afetch_provider_key("anthropic", "test-public-key", challenge_uuid)

    assert result == {
        "encrypted_key": "encrypted-api-key",
        "provider": "anthropic",
        "project_id": "proj-456",
    }
    mock_client_instance.get.assert_called_once_with(
        "https://api.example.com/provider-keys/anthropic",
        headers={
            "encryption-key": "test-public-key",
            "AnyLLM-Challenge-Response": str(challenge_uuid),
        },
    )


@pytest.mark.asyncio
async def test_afetch_provider_key_error():
    client = AnyLLMPlatformClient("https://api.example.com")
    challenge_uuid = uuid.uuid4()
    mock_response = MagicMock()
    mock_response.status_code = 403
    mock_response.json.return_value = {"error": "Forbidden"}

    with patch("any_llm_platform_client.client.httpx.AsyncClient") as mock_client_class:
        mock_client_instance = MagicMock()
        mock_client_instance.get = AsyncMock(return_value=mock_response)
        mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

        with pytest.raises(ProviderKeyFetchError, match="status: 403"):
            await client.afetch_provider_key("anthropic", "test-public-key", challenge_uuid)
