"""Comprehensive unit tests for the client_management module."""

from unittest.mock import MagicMock, patch

import pytest

from any_llm_platform_client import AnyLLMPlatformClient
from any_llm_platform_client.client_management import AuthenticationError


@pytest.fixture
def client():
    """Create a test client."""
    return AnyLLMPlatformClient("https://api.example.com")


@pytest.fixture
def mock_success_response():
    """Create a mock successful HTTP response."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"success": True}
    return mock_response


@pytest.fixture
def mock_error_response():
    """Create a mock error HTTP response."""
    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_response.json.return_value = {"detail": "Unauthorized"}
    return mock_response


class TestAuthentication:
    """Tests for authentication methods."""

    def test_login_success(self, client):
        """Test successful login."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "test-token-123",
            "token_type": "bearer",
        }

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_client_class.return_value = mock_client

            token = client.login("test@example.com", "password123")

        assert token == "test-token-123"
        assert client.access_token == "test-token-123"
        assert client.token_expires_at is not None
        mock_client.post.assert_called_once()

    def test_login_failure(self, client):
        """Test login failure."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.json.return_value = {"detail": "Invalid credentials"}

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_client_class.return_value = mock_client

            with pytest.raises(AuthenticationError, match="Failed to login"):
                client.login("test@example.com", "wrongpassword")

    def test_login_invalid_response_json(self, client):
        """Test login with invalid JSON response."""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.json.side_effect = ValueError("Invalid JSON")

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_client_class.return_value = mock_client

            with pytest.raises(AuthenticationError, match="Failed to login"):
                client.login("test@example.com", "password123")


class TestProjectManagement:
    """Tests for project management methods."""

    def test_list_projects_success(self, client):
        """Test listing projects successfully."""
        client.access_token = "test-token"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [{"id": "proj-1", "name": "Project 1"}],
            "count": 1,
        }

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = client.list_projects()

        assert result["count"] == 1
        assert len(result["data"]) == 1
        mock_client.get.assert_called_once()

    def test_list_projects_not_authenticated(self, client):
        """Test that listing projects without authentication raises error."""
        with pytest.raises(AuthenticationError, match="Not authenticated"):
            client.list_projects()

    def test_create_project_success(self, client):
        """Test creating a project successfully."""
        client.access_token = "test-token"
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "id": "proj-123",
            "name": "New Project",
            "description": "Test project",
        }

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = client.create_project("New Project", description="Test project")

        assert result["id"] == "proj-123"
        assert result["name"] == "New Project"
        mock_client.post.assert_called_once()

    def test_create_project_with_encryption_key(self, client):
        """Test creating a project with encryption key."""
        client.access_token = "test-token"
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"id": "proj-123", "name": "New Project"}

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = client.create_project("New Project", encryption_key="test-key-123")

        assert result["id"] == "proj-123"
        # Verify encryption_key was included in the payload
        call_args = mock_client.post.call_args
        assert call_args[1]["json"]["encryption_key"] == "test-key-123"

    def test_get_project_success(self, client):
        """Test getting a specific project."""
        client.access_token = "test-token"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"id": "proj-123", "name": "Test Project"}

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = client.get_project("proj-123")

        assert result["id"] == "proj-123"
        assert "proj-123" in mock_client.get.call_args[0][0]

    def test_update_project_success(self, client):
        """Test updating a project."""
        client.access_token = "test-token"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id": "proj-123",
            "name": "Updated Project",
        }

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.patch.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = client.update_project("proj-123", name="Updated Project")

        assert result["name"] == "Updated Project"
        mock_client.patch.assert_called_once()

    def test_delete_project_success(self, client):
        """Test deleting a project."""
        client.access_token = "test-token"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"message": "Project deleted"}

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.delete.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = client.delete_project("proj-123")

        assert "message" in result
        mock_client.delete.assert_called_once()


class TestProviderKeyManagement:
    """Tests for provider key management methods."""

    def test_list_provider_keys_success(self, client):
        """Test listing provider keys."""
        client.access_token = "test-token"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [{"id": "key-1", "provider": "openai"}],
            "count": 1,
        }

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = client.list_provider_keys("proj-123")

        assert result["count"] == 1
        assert result["data"][0]["provider"] == "openai"

    def test_list_provider_keys_include_archived(self, client):
        """Test listing provider keys including archived."""
        client.access_token = "test-token"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": [], "count": 0}

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client

            client.list_provider_keys("proj-123", include_archived=True)

        # Verify include_archived param was passed
        call_args = mock_client.get.call_args
        assert call_args[1]["params"]["include_archived"] is True

    def test_create_provider_key_success(self, client):
        """Test creating a provider key."""
        client.access_token = "test-token"
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "id": "key-123",
            "provider": "openai",
            "encrypted_key": "encrypted-value",
        }

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = client.create_provider_key_mgmt("proj-123", "openai", "encrypted-value")

        assert result["id"] == "key-123"
        assert result["provider"] == "openai"

    def test_update_provider_key_success(self, client):
        """Test updating a provider key."""
        client.access_token = "test-token"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id": "key-123",
            "encrypted_key": "new-encrypted-value",
        }

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.patch.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = client.update_provider_key_mgmt("key-123", "new-encrypted-value")

        assert result["id"] == "key-123"
        mock_client.patch.assert_called_once()

    def test_delete_provider_key_archive(self, client):
        """Test archiving a provider key (soft delete)."""
        client.access_token = "test-token"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"message": "Provider key archived"}

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.delete.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = client.delete_provider_key_mgmt("key-123", permanent=False)

        assert "message" in result
        call_args = mock_client.delete.call_args
        assert call_args[1]["params"]["permanent"] is False

    def test_delete_provider_key_permanent(self, client):
        """Test permanently deleting a provider key."""
        client.access_token = "test-token"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"message": "Provider key deleted"}

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.delete.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = client.delete_provider_key_mgmt("key-123", permanent=True)

        assert "message" in result
        call_args = mock_client.delete.call_args
        assert call_args[1]["params"]["permanent"] is True

    def test_unarchive_provider_key_success(self, client):
        """Test unarchiving a provider key."""
        client.access_token = "test-token"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"id": "key-123", "is_archived": False}

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = client.unarchive_provider_key("key-123")

        assert result["is_archived"] is False
        assert "unarchive" in mock_client.post.call_args[0][0]


class TestBudgetManagement:
    """Tests for budget management methods."""

    def test_list_project_budgets_success(self, client):
        """Test listing project budgets."""
        client.access_token = "test-token"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [{"id": "budget-1", "spend_period": "monthly"}],
            "count": 1,
        }

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = client.list_project_budgets("proj-123")

        assert result["count"] == 1
        assert result["data"][0]["spend_period"] == "monthly"

    def test_create_project_budget_success(self, client):
        """Test creating a project budget."""
        client.access_token = "test-token"
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "id": "budget-123",
            "budget_limit": "100.0",
            "spend_period": "monthly",
        }

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = client.create_project_budget("proj-123", 100.0, "monthly")

        assert result["budget_limit"] == "100.0"
        assert result["spend_period"] == "monthly"

    def test_get_project_budget_success(self, client):
        """Test getting a specific project budget."""
        client.access_token = "test-token"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id": "budget-123",
            "spend_period": "daily",
        }

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = client.get_project_budget("proj-123", "daily")

        assert result["spend_period"] == "daily"
        assert "daily" in mock_client.get.call_args[0][0]

    def test_update_project_budget_success(self, client):
        """Test updating a project budget."""
        client.access_token = "test-token"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id": "budget-123",
            "budget_limit": "200.0",
        }

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.patch.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = client.update_project_budget("proj-123", "monthly", 200.0)

        assert result["budget_limit"] == "200.0"
        mock_client.patch.assert_called_once()

    def test_delete_project_budget_success(self, client):
        """Test deleting a project budget."""
        client.access_token = "test-token"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"message": "Budget deleted"}

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.delete.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = client.delete_project_budget("proj-123", "weekly")

        assert "message" in result
        assert "weekly" in mock_client.delete.call_args[0][0]


class TestClientManagement:
    """Tests for client management methods."""

    def test_list_clients_success(self, client):
        """Test listing clients."""
        client.access_token = "test-token"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [{"id": "client-1", "name": "Client 1"}],
            "count": 1,
        }

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = client.list_clients("proj-123")

        assert result["count"] == 1
        assert result["data"][0]["name"] == "Client 1"

    def test_create_client_success(self, client):
        """Test creating a client."""
        client.access_token = "test-token"
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "id": "client-123",
            "name": "New Client",
            "is_default": False,
        }

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = client.create_client("proj-123", "New Client", is_default=False)

        assert result["name"] == "New Client"
        assert result["is_default"] is False

    def test_get_client_success(self, client):
        """Test getting a specific client."""
        client.access_token = "test-token"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"id": "client-123", "name": "Test Client"}

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = client.get_client("proj-123", "client-123")

        assert result["id"] == "client-123"
        assert "client-123" in mock_client.get.call_args[0][0]

    def test_update_client_success(self, client):
        """Test updating a client."""
        client.access_token = "test-token"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id": "client-123",
            "name": "Updated Client",
        }

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.patch.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = client.update_client("proj-123", "client-123", name="Updated Client")

        assert result["name"] == "Updated Client"
        mock_client.patch.assert_called_once()

    def test_delete_client_success(self, client):
        """Test deleting a client."""
        client.access_token = "test-token"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"message": "Client deleted"}

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.delete.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = client.delete_client("proj-123", "client-123")

        assert "message" in result
        mock_client.delete.assert_called_once()

    def test_set_default_client_success(self, client):
        """Test setting a client as default."""
        client.access_token = "test-token"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id": "client-123",
            "is_default": True,
        }

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = client.set_default_client("proj-123", "client-123")

        assert result["is_default"] is True
        assert "set-default" in mock_client.post.call_args[0][0]

    def test_list_client_budgets_success(self, client):
        """Test listing client budgets."""
        client.access_token = "test-token"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [{"id": "budget-1", "spend_period": "monthly"}]

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = client.list_client_budgets("proj-123", "client-123")

        assert len(result) == 1
        assert result[0]["spend_period"] == "monthly"

    def test_create_client_budget_success(self, client):
        """Test creating a client budget."""
        client.access_token = "test-token"
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "id": "budget-123",
            "budget_limit": "50.0",
            "spend_period": "daily",
        }

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = client.create_client_budget("proj-123", "client-123", 50.0, "daily")

        assert result["budget_limit"] == "50.0"
        assert result["spend_period"] == "daily"

    def test_get_client_budget_success(self, client):
        """Test getting a specific client budget."""
        client.access_token = "test-token"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id": "budget-123",
            "spend_period": "weekly",
        }

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = client.get_client_budget("proj-123", "client-123", "weekly")

        assert result["spend_period"] == "weekly"

    def test_update_client_budget_success(self, client):
        """Test updating a client budget."""
        client.access_token = "test-token"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id": "budget-123",
            "budget_limit": "75.0",
        }

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.patch.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = client.update_client_budget("proj-123", "client-123", "monthly", 75.0)

        assert result["budget_limit"] == "75.0"

    def test_delete_client_budget_success(self, client):
        """Test deleting a client budget."""
        client.access_token = "test-token"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"message": "Budget deleted"}

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.delete.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = client.delete_client_budget("proj-123", "client-123", "monthly")

        assert "message" in result


class TestErrorHandling:
    """Tests for error handling across management methods."""

    def test_check_response_with_error_detail(self, client):
        """Test _check_response with error detail."""
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.json.return_value = {"detail": "Forbidden"}

        with pytest.raises(AuthenticationError, match="Forbidden"):
            client._check_response(mock_response, "test operation")

    def test_check_response_without_error_detail(self, client):
        """Test _check_response without error detail."""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.json.return_value = {"error": "Server error"}

        with pytest.raises(AuthenticationError, match="status: 500"):
            client._check_response(mock_response, "test operation")

    def test_check_response_invalid_json(self, client):
        """Test _check_response with invalid JSON."""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.json.side_effect = ValueError("Invalid JSON")

        with pytest.raises(AuthenticationError, match="status: 500"):
            client._check_response(mock_response, "test operation")

    def test_check_response_success(self, client):
        """Test _check_response with successful status."""
        mock_response = MagicMock()
        mock_response.status_code = 200

        # Should not raise any exception
        client._check_response(mock_response, "test operation")

    def test_check_response_multiple_expected_codes(self, client):
        """Test _check_response with multiple expected status codes."""
        mock_response = MagicMock()
        mock_response.status_code = 201

        # Should not raise any exception
        client._check_response(mock_response, "test operation", expected_codes=(200, 201))
