"""Integration tests for complete key decryption flow."""

import uuid
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from any_llm_platform_client import AnyLLMPlatformClient
from any_llm_platform_client.crypto import (
    decrypt_data,
    encrypt_data,
    format_any_llm_key,
    generate_keypair,
    load_private_key,
    parse_any_llm_key,
)


class TestCompleteDecryptionFlow:
    """Integration tests for the complete key decryption flow."""

    def test_full_decryption_flow_with_real_crypto(self):
        """Test complete flow from keypair generation to decryption with real crypto."""
        # 1. Generate a keypair
        private_key, public_key = generate_keypair()

        # 2. Format as ANY_LLM_KEY
        any_llm_key = format_any_llm_key(private_key)

        # 3. Parse the key back
        components = parse_any_llm_key(any_llm_key)
        loaded_private_key = load_private_key(components.base64_encoded_private_key)

        # Verify the private key is the same
        assert bytes(loaded_private_key) == bytes(private_key)

        # 4. Simulate server encrypting a challenge
        challenge_uuid = uuid.uuid4()
        encrypted_challenge = encrypt_data(str(challenge_uuid), public_key)

        # 5. Decrypt the challenge
        decrypted_challenge_str = decrypt_data(encrypted_challenge, loaded_private_key)
        decrypted_challenge = uuid.UUID(decrypted_challenge_str)

        # Verify the challenge matches
        assert decrypted_challenge == challenge_uuid

        # 6. Encrypt a provider API key
        provider_api_key = "sk-test-api-key-12345"  # pragma: allowlist secret
        encrypted_api_key = encrypt_data(provider_api_key, public_key)

        # 7. Decrypt the provider API key
        decrypted_api_key = decrypt_data(encrypted_api_key, loaded_private_key)

        assert decrypted_api_key == provider_api_key

    def test_end_to_end_with_mocked_api(self):
        """Test end-to-end flow with mocked API calls."""
        # Generate real keypair
        private_key, public_key = generate_keypair()
        any_llm_key = format_any_llm_key(private_key)

        # Create client
        client = AnyLLMPlatformClient("https://api.example.com")

        # Mock challenge and token responses
        challenge_uuid = uuid.uuid4()
        encrypted_challenge = encrypt_data(str(challenge_uuid), public_key)

        challenge_response = MagicMock()
        challenge_response.status_code = 200
        challenge_response.json.return_value = {"encrypted_challenge": encrypted_challenge}

        token_response = MagicMock()
        token_response.status_code = 200
        token_response.json.return_value = {
            "access_token": "test-jwt-token",
            "token_type": "bearer",
        }

        # Mock provider key response
        provider_api_key = "sk-openai-12345"  # pragma: allowlist secret
        encrypted_provider_key = encrypt_data(provider_api_key, public_key)

        provider_key_response = MagicMock()
        provider_key_response.status_code = 200
        provider_key_response.json.return_value = {
            "id": str(uuid.uuid4()),
            "encrypted_key": encrypted_provider_key,
            "provider": "openai",
            "project_id": str(uuid.uuid4()),
            "created_at": datetime.now().isoformat(),
        }

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            # First POST is challenge, second POST is token request, GET is provider key
            mock_client.post.side_effect = [challenge_response, token_response]
            mock_client.get.return_value = provider_key_response
            mock_client_class.return_value = mock_client

            # Execute the complete flow
            result = client.get_decrypted_provider_key(any_llm_key, "openai")

        # Verify the result
        assert result.api_key == provider_api_key
        assert result.provider == "openai"
        assert isinstance(result.provider_key_id, uuid.UUID)
        assert isinstance(result.project_id, uuid.UUID)
        assert isinstance(result.created_at, datetime)

    @pytest.mark.asyncio
    async def test_async_end_to_end_with_mocked_api(self):
        """Test async end-to-end flow with mocked API calls."""
        # Generate real keypair
        private_key, public_key = generate_keypair()
        any_llm_key = format_any_llm_key(private_key)

        # Create client
        client = AnyLLMPlatformClient("https://api.example.com")

        # Mock challenge and token responses
        challenge_uuid = uuid.uuid4()
        encrypted_challenge = encrypt_data(str(challenge_uuid), public_key)

        challenge_response = MagicMock()
        challenge_response.status_code = 200
        challenge_response.json.return_value = {"encrypted_challenge": encrypted_challenge}

        token_response = MagicMock()
        token_response.status_code = 200
        token_response.json.return_value = {
            "access_token": "test-jwt-token-async",
            "token_type": "bearer",
        }

        # Mock provider key response
        provider_api_key = "sk-anthropic-67890"  # pragma: allowlist secret
        encrypted_provider_key = encrypt_data(provider_api_key, public_key)

        provider_key_response = MagicMock()
        provider_key_response.status_code = 200
        provider_key_response.json.return_value = {
            "id": str(uuid.uuid4()),
            "encrypted_key": encrypted_provider_key,
            "provider": "anthropic",
            "project_id": str(uuid.uuid4()),
            "created_at": datetime.now().isoformat(),
        }

        with patch("any_llm_platform_client.client.httpx.AsyncClient") as mock_client_class:
            mock_client_instance = MagicMock()
            mock_client_instance.post = AsyncMock(side_effect=[challenge_response, token_response])
            mock_client_instance.get = AsyncMock(return_value=provider_key_response)
            mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client_instance)
            mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

            # Execute the complete async flow
            result = await client.aget_decrypted_provider_key(any_llm_key, "anthropic")

        # Verify the result
        assert result.api_key == provider_api_key
        assert result.provider == "anthropic"
        assert isinstance(result.provider_key_id, uuid.UUID)
        assert isinstance(result.project_id, uuid.UUID)

    def test_token_caching_and_reuse(self):
        """Test that access token is cached and reused for multiple requests."""
        private_key, public_key = generate_keypair()
        any_llm_key = format_any_llm_key(private_key)

        client = AnyLLMPlatformClient("https://api.example.com")

        # Mock initial authentication
        challenge_uuid = uuid.uuid4()
        encrypted_challenge = encrypt_data(str(challenge_uuid), public_key)

        challenge_response = MagicMock()
        challenge_response.status_code = 200
        challenge_response.json.return_value = {"encrypted_challenge": encrypted_challenge}

        token_response = MagicMock()
        token_response.status_code = 200
        token_response.json.return_value = {
            "access_token": "cached-token-123",
            "token_type": "bearer",
        }

        # Mock provider key responses
        provider_key_response_1 = MagicMock()
        provider_key_response_1.status_code = 200
        provider_key_response_1.json.return_value = {
            "id": str(uuid.uuid4()),
            "encrypted_key": encrypt_data("sk-key-1", public_key),
            "provider": "openai",
            "project_id": str(uuid.uuid4()),
            "created_at": datetime.now().isoformat(),
        }

        provider_key_response_2 = MagicMock()
        provider_key_response_2.status_code = 200
        provider_key_response_2.json.return_value = {
            "id": str(uuid.uuid4()),
            "encrypted_key": encrypt_data("sk-key-2", public_key),
            "provider": "anthropic",
            "project_id": str(uuid.uuid4()),
            "created_at": datetime.now().isoformat(),
        }

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            # Authentication happens once
            mock_client.post.side_effect = [challenge_response, token_response]
            # Two provider key fetches
            mock_client.get.side_effect = [provider_key_response_1, provider_key_response_2]
            mock_client_class.return_value = mock_client

            # First request - should authenticate
            result1 = client.get_decrypted_provider_key(any_llm_key, "openai")
            assert result1.api_key == "sk-key-1"  # pragma: allowlist secret

            # Second request - should reuse token
            result2 = client.get_decrypted_provider_key(any_llm_key, "anthropic")
            assert result2.api_key == "sk-key-2"  # pragma: allowlist secret

        # Verify authentication only happened once
        assert mock_client.post.call_count == 2  # Challenge + token
        assert mock_client.get.call_count == 2  # Two provider key fetches

    def test_token_refresh_on_expiry(self):
        """Test that token is refreshed when expired."""
        private_key, public_key = generate_keypair()
        any_llm_key = format_any_llm_key(private_key)

        client = AnyLLMPlatformClient("https://api.example.com")

        # Set an expired token
        client.access_token = "expired-token"
        client.token_expires_at = datetime.now() - timedelta(hours=1)

        # Mock re-authentication
        challenge_uuid = uuid.uuid4()
        encrypted_challenge = encrypt_data(str(challenge_uuid), public_key)

        challenge_response = MagicMock()
        challenge_response.status_code = 200
        challenge_response.json.return_value = {"encrypted_challenge": encrypted_challenge}

        token_response = MagicMock()
        token_response.status_code = 200
        token_response.json.return_value = {
            "access_token": "refreshed-token-456",
            "token_type": "bearer",
        }

        provider_key_response = MagicMock()
        provider_key_response.status_code = 200
        provider_key_response.json.return_value = {
            "id": str(uuid.uuid4()),
            "encrypted_key": encrypt_data("sk-key-after-refresh", public_key),
            "provider": "openai",
            "project_id": str(uuid.uuid4()),
            "created_at": datetime.now().isoformat(),
        }

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.side_effect = [challenge_response, token_response]
            mock_client.get.return_value = provider_key_response
            mock_client_class.return_value = mock_client

            result = client.get_decrypted_provider_key(any_llm_key, "openai")

        assert result.api_key == "sk-key-after-refresh"  # pragma: allowlist secret
        assert client.access_token == "refreshed-token-456"
        assert client.token_expires_at > datetime.now()

    def test_multiple_different_keys(self):
        """Test that different keys can decrypt their own data."""
        # Generate two different keypairs
        private_key1, public_key1 = generate_keypair()
        private_key2, public_key2 = generate_keypair()

        # Encrypt data with different keys
        data1 = "secret-for-key1"
        data2 = "secret-for-key2"

        encrypted1 = encrypt_data(data1, public_key1)
        encrypted2 = encrypt_data(data2, public_key2)

        # Decrypt with correct keys
        decrypted1 = decrypt_data(encrypted1, private_key1)
        decrypted2 = decrypt_data(encrypted2, private_key2)

        assert decrypted1 == data1
        assert decrypted2 == data2

        # Verify cross-decryption fails
        with pytest.raises((ValueError, Exception)):
            decrypt_data(encrypted1, private_key2)

        with pytest.raises((ValueError, Exception)):
            decrypt_data(encrypted2, private_key1)


class TestClientManagementIntegration:
    """Integration tests for client management with authentication."""

    def test_login_then_list_projects(self):
        """Test login followed by listing projects."""
        client = AnyLLMPlatformClient("https://api.example.com")

        login_response = MagicMock()
        login_response.status_code = 200
        login_response.json.return_value = {
            "access_token": "mgmt-token-123",
            "token_type": "bearer",
        }

        projects_response = MagicMock()
        projects_response.status_code = 200
        projects_response.json.return_value = {
            "data": [
                {"id": "proj-1", "name": "Project 1"},
                {"id": "proj-2", "name": "Project 2"},
            ],
            "count": 2,
        }

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = login_response
            mock_client.get.return_value = projects_response
            mock_client_class.return_value = mock_client

            # Login
            token = client.login("user@example.com", "password")
            assert token == "mgmt-token-123"
            assert client.access_token == "mgmt-token-123"

            # List projects
            projects = client.list_projects()
            assert projects["count"] == 2
            assert len(projects["data"]) == 2

    def test_create_project_and_add_provider_key(self):
        """Test creating a project and adding a provider key."""
        client = AnyLLMPlatformClient("https://api.example.com")

        # Pre-authenticate
        client.access_token = "mgmt-token-456"
        client.token_expires_at = datetime.now() + timedelta(hours=1)

        # Generate keypair for encryption
        private_key, public_key = generate_keypair()
        api_key = "sk-test-api-key"  # pragma: allowlist secret
        encrypted_api_key = encrypt_data(api_key, public_key)

        project_response = MagicMock()
        project_response.status_code = 201
        project_response.json.return_value = {
            "id": "new-proj-123",
            "name": "New Project",
        }

        provider_key_response = MagicMock()
        provider_key_response.status_code = 201
        provider_key_response.json.return_value = {
            "id": "key-123",
            "provider": "openai",
            "encrypted_key": encrypted_api_key,
        }

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.side_effect = [project_response, provider_key_response]
            mock_client_class.return_value = mock_client

            # Create project
            project = client.create_project("New Project")
            assert project["id"] == "new-proj-123"

            # Add provider key
            key = client.create_provider_key_mgmt("new-proj-123", "openai", encrypted_api_key)
            assert key["provider"] == "openai"
