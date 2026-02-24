"""Tests for client token management."""

from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from any_llm_platform_client import AnyLLMPlatformClient


class TestTokenManagement:
    """Tests for token caching, validation, and refresh."""

    def test_ensure_valid_token_refreshes_when_missing(self, sample_api_url, valid_any_llm_key):
        """Test that _ensure_valid_token refreshes when no token is set."""
        client = AnyLLMPlatformClient(sample_api_url)

        # No token set
        assert client.access_token is None

        def mock_refresh_side_effect(_key):
            client.access_token = "new-token"
            return "new-token"

        with patch.object(client, "refresh_access_token", side_effect=mock_refresh_side_effect) as mock_refresh:
            result = client._ensure_valid_token(valid_any_llm_key)

        assert result == "new-token"
        mock_refresh.assert_called_once_with(valid_any_llm_key)

    def test_ensure_valid_token_refreshes_when_expired(self, sample_api_url, valid_any_llm_key):
        """Test that _ensure_valid_token refreshes when token is expired."""
        client = AnyLLMPlatformClient(sample_api_url)

        # Set expired token
        client.access_token = "old-token"
        client.token_expires_at = datetime.now() - timedelta(hours=1)

        def mock_refresh_side_effect(_key):
            client.access_token = "new-token"
            return "new-token"

        with patch.object(client, "refresh_access_token", side_effect=mock_refresh_side_effect) as mock_refresh:
            result = client._ensure_valid_token(valid_any_llm_key)

        assert result == "new-token"
        mock_refresh.assert_called_once_with(valid_any_llm_key)

    def test_ensure_valid_token_returns_existing_when_valid(self, sample_api_url, valid_any_llm_key):
        """Test that _ensure_valid_token returns existing token when valid."""
        client = AnyLLMPlatformClient(sample_api_url)

        # Set valid token
        client.access_token = "valid-token"
        client.token_expires_at = datetime.now() + timedelta(hours=1)

        with patch.object(client, "refresh_access_token") as mock_refresh:
            result = client._ensure_valid_token(valid_any_llm_key)

        assert result == "valid-token"
        mock_refresh.assert_not_called()

    @pytest.mark.asyncio
    async def test_aensure_valid_token_refreshes_when_missing(self, sample_api_url, valid_any_llm_key):
        """Test that _aensure_valid_token refreshes when token is missing."""
        client = AnyLLMPlatformClient(sample_api_url)

        # No token set
        assert client.access_token is None

        async def mock_refresh_side_effect(_key):
            client.access_token = "new-async-token"
            return "new-async-token"

        with patch.object(client, "arefresh_access_token", side_effect=mock_refresh_side_effect) as mock_refresh:
            result = await client._aensure_valid_token(valid_any_llm_key)

        assert result == "new-async-token"
        mock_refresh.assert_called_once_with(valid_any_llm_key)
