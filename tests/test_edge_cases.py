"""Edge case tests for improved coverage."""

from unittest.mock import MagicMock

import pytest

from any_llm_platform_client import AnyLLMPlatformClient
from any_llm_platform_client.client_management import AuthenticationError
from any_llm_platform_client.exceptions import ChallengeCreationError, ProviderKeyFetchError


class TestClientEdgeCasesAdditional:
    """Additional edge case tests for client module."""

    def test_create_challenge_invalid_json_response(self, sample_api_url, mock_httpx_client):
        """Test create_challenge with invalid JSON response."""
        client = AnyLLMPlatformClient(sample_api_url)
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_httpx_client.post.return_value = mock_response

        with pytest.raises(ChallengeCreationError):
            client.create_challenge("test-public-key")

    def test_fetch_provider_key_invalid_json_response(self, sample_api_url, sample_jwt_token, mock_httpx_client):
        """Test fetch_provider_key with invalid JSON response."""
        client = AnyLLMPlatformClient(sample_api_url)
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_httpx_client.get.return_value = mock_response

        with pytest.raises(ProviderKeyFetchError):
            client.fetch_provider_key("openai", sample_jwt_token)


class TestClientManagementEdgeCases:
    """Edge case tests for client_management module."""

    def test_create_project_not_authenticated(self, mock_httpx_client):
        """Test creating project without authentication raises error without making HTTP calls."""
        client = AnyLLMPlatformClient()

        with pytest.raises(AuthenticationError, match="Not authenticated"):
            client.create_project("Test Project")

        # Verify no HTTP request was made
        mock_httpx_client.post.assert_not_called()

    def test_get_project_not_authenticated(self, mock_httpx_client):
        """Test getting project without authentication raises error without making HTTP calls."""
        client = AnyLLMPlatformClient()

        with pytest.raises(AuthenticationError, match="Not authenticated"):
            client.get_project("proj-123")

        mock_httpx_client.get.assert_not_called()

    def test_update_project_not_authenticated(self, mock_httpx_client):
        """Test updating project without authentication raises error without making HTTP calls."""
        client = AnyLLMPlatformClient()

        with pytest.raises(AuthenticationError, match="Not authenticated"):
            client.update_project("proj-123", name="New Name")

        mock_httpx_client.put.assert_not_called()

    def test_delete_project_not_authenticated(self, mock_httpx_client):
        """Test deleting project without authentication raises error without making HTTP calls."""
        client = AnyLLMPlatformClient()

        with pytest.raises(AuthenticationError, match="Not authenticated"):
            client.delete_project("proj-123")

        mock_httpx_client.delete.assert_not_called()

    def test_list_provider_keys_not_authenticated(self):
        """Test listing provider keys without authentication."""
        client = AnyLLMPlatformClient()
        with pytest.raises(AuthenticationError, match="Not authenticated"):
            client.list_provider_keys("proj-123")

    def test_create_provider_key_mgmt_not_authenticated(self):
        """Test creating provider key without authentication."""
        client = AnyLLMPlatformClient()
        with pytest.raises(AuthenticationError, match="Not authenticated"):
            client.create_provider_key_mgmt("proj-123", "openai", "encrypted-key")

    def test_update_provider_key_mgmt_not_authenticated(self):
        """Test updating provider key without authentication."""
        client = AnyLLMPlatformClient()
        with pytest.raises(AuthenticationError, match="Not authenticated"):
            client.update_provider_key_mgmt("key-123", "new-encrypted-key")

    def test_delete_provider_key_mgmt_not_authenticated(self):
        """Test deleting provider key without authentication."""
        client = AnyLLMPlatformClient()
        with pytest.raises(AuthenticationError, match="Not authenticated"):
            client.delete_provider_key_mgmt("key-123")

    def test_unarchive_provider_key_not_authenticated(self):
        """Test unarchiving provider key without authentication."""
        client = AnyLLMPlatformClient()
        with pytest.raises(AuthenticationError, match="Not authenticated"):
            client.unarchive_provider_key("key-123")

    def test_list_project_budgets_not_authenticated(self):
        """Test listing project budgets without authentication."""
        client = AnyLLMPlatformClient()
        with pytest.raises(AuthenticationError, match="Not authenticated"):
            client.list_project_budgets("proj-123")

    def test_create_project_budget_not_authenticated(self):
        """Test creating project budget without authentication."""
        client = AnyLLMPlatformClient()
        with pytest.raises(AuthenticationError, match="Not authenticated"):
            client.create_project_budget("proj-123", 100.0)

    def test_get_project_budget_not_authenticated(self):
        """Test getting project budget without authentication."""
        client = AnyLLMPlatformClient()
        with pytest.raises(AuthenticationError, match="Not authenticated"):
            client.get_project_budget("proj-123", "monthly")

    def test_update_project_budget_not_authenticated(self):
        """Test updating project budget without authentication."""
        client = AnyLLMPlatformClient()
        with pytest.raises(AuthenticationError, match="Not authenticated"):
            client.update_project_budget("proj-123", "monthly", 200.0)

    def test_delete_project_budget_not_authenticated(self):
        """Test deleting project budget without authentication."""
        client = AnyLLMPlatformClient()
        with pytest.raises(AuthenticationError, match="Not authenticated"):
            client.delete_project_budget("proj-123", "monthly")

    def test_list_clients_not_authenticated(self):
        """Test listing clients without authentication."""
        client = AnyLLMPlatformClient()
        with pytest.raises(AuthenticationError, match="Not authenticated"):
            client.list_clients("proj-123")

    def test_create_client_not_authenticated(self):
        """Test creating client without authentication."""
        client = AnyLLMPlatformClient()
        with pytest.raises(AuthenticationError, match="Not authenticated"):
            client.create_client("proj-123", "Client Name")

    def test_get_client_not_authenticated(self):
        """Test getting client without authentication."""
        client = AnyLLMPlatformClient()
        with pytest.raises(AuthenticationError, match="Not authenticated"):
            client.get_client("proj-123", "client-123")

    def test_update_client_not_authenticated(self):
        """Test updating client without authentication."""
        client = AnyLLMPlatformClient()
        with pytest.raises(AuthenticationError, match="Not authenticated"):
            client.update_client("proj-123", "client-123", name="New Name")

    def test_delete_client_not_authenticated(self):
        """Test deleting client without authentication."""
        client = AnyLLMPlatformClient()
        with pytest.raises(AuthenticationError, match="Not authenticated"):
            client.delete_client("proj-123", "client-123")

    def test_set_default_client_not_authenticated(self):
        """Test setting default client without authentication."""
        client = AnyLLMPlatformClient()
        with pytest.raises(AuthenticationError, match="Not authenticated"):
            client.set_default_client("proj-123", "client-123")

    def test_list_client_budgets_not_authenticated(self):
        """Test listing client budgets without authentication."""
        client = AnyLLMPlatformClient()
        with pytest.raises(AuthenticationError, match="Not authenticated"):
            client.list_client_budgets("proj-123", "client-123")

    def test_create_client_budget_not_authenticated(self):
        """Test creating client budget without authentication."""
        client = AnyLLMPlatformClient()
        with pytest.raises(AuthenticationError, match="Not authenticated"):
            client.create_client_budget("proj-123", "client-123", 50.0, "daily")

    def test_get_client_budget_not_authenticated(self):
        """Test getting client budget without authentication."""
        client = AnyLLMPlatformClient()
        with pytest.raises(AuthenticationError, match="Not authenticated"):
            client.get_client_budget("proj-123", "client-123", "daily")

    def test_update_client_budget_not_authenticated(self):
        """Test updating client budget without authentication."""
        client = AnyLLMPlatformClient()
        with pytest.raises(AuthenticationError, match="Not authenticated"):
            client.update_client_budget("proj-123", "client-123", "daily", 75.0)

    def test_delete_client_budget_not_authenticated(self):
        """Test deleting client budget without authentication."""
        client = AnyLLMPlatformClient()
        with pytest.raises(AuthenticationError, match="Not authenticated"):
            client.delete_client_budget("proj-123", "client-123", "daily")
