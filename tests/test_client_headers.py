"""Tests for client header handling."""

from unittest.mock import AsyncMock

import pytest

from any_llm_platform_client import AnyLLMPlatformClient


class TestClientHeaders:
    """Tests for client name header handling."""

    def test_client_name_in_headers(self, sample_api_url, mock_httpx_client, make_provider_key_response):
        """Test that client_name is included in headers when set."""
        client = AnyLLMPlatformClient(sample_api_url, client_name="test-client")
        access_token = "test-token-123"
        mock_httpx_client.get.return_value = make_provider_key_response("openai", "test-key", "proj-1")

        client.fetch_provider_key("openai", access_token)

        # Verify client name was included in headers
        call_args = mock_httpx_client.get.call_args
        assert "AnyLLM-Client-Name" in call_args[1]["headers"]
        assert call_args[1]["headers"]["AnyLLM-Client-Name"] == "test-client"

    def test_client_name_not_in_headers_when_none(self, sample_api_url, mock_httpx_client, make_provider_key_response):
        """Test that client_name is not included in headers when None."""
        client = AnyLLMPlatformClient(sample_api_url, client_name=None)
        access_token = "test-token-123"
        mock_httpx_client.get.return_value = make_provider_key_response("openai", "test-key", "proj-1")

        client.fetch_provider_key("openai", access_token)

        # Verify client name was not included in headers
        call_args = mock_httpx_client.get.call_args
        assert "AnyLLM-Client-Name" not in call_args[1]["headers"]

    @pytest.mark.asyncio
    async def test_async_client_name_in_headers(
        self, sample_api_url, mock_httpx_async_client, make_provider_key_response
    ):
        """Test that client_name is included in headers for async methods."""
        client = AnyLLMPlatformClient(sample_api_url, client_name="async-client")
        access_token = "test-token-123"
        mock_httpx_async_client.get = AsyncMock(
            return_value=make_provider_key_response("anthropic", "test-key", "proj-2")
        )

        await client.afetch_provider_key("anthropic", access_token)

        # Verify client name was included in headers
        call_args = mock_httpx_async_client.get.call_args
        assert "AnyLLM-Client-Name" in call_args[1]["headers"]
        assert call_args[1]["headers"]["AnyLLM-Client-Name"] == "async-client"
