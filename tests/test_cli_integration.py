"""Integration tests for CLI commands with mocked API responses."""

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from any_llm_platform_client.cli import cli


@pytest.fixture
def runner():
    """Create a Click CLI test runner."""
    return CliRunner()


@pytest.fixture
def mock_auth():
    """Mock successful authentication."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"access_token": "test-token", "token_type": "bearer"}
    return mock_response


@pytest.fixture
def mock_project_list():
    """Mock project list response."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": [
            {
                "id": "test-project-id",
                "name": "Test Project",
                "description": "A test project",
                "created_at": "2026-02-23T12:00:00Z",
                "updated_at": "2026-02-23T12:00:00Z",
            }
        ],
        "count": 1,
    }
    return mock_response


def test_project_list_with_auth(runner, mock_auth, mock_project_list):
    """Test project list with authentication."""
    with patch("httpx.Client") as mock_client_class:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        # First call is login, second is list projects
        mock_client.post.return_value = mock_auth
        mock_client.get.return_value = mock_project_list
        mock_client_class.return_value = mock_client

        result = runner.invoke(cli, ["--username", "test@example.com", "--password", "test", "project", "list"])
        assert result.exit_code == 0
        assert "Test Project" in result.output


def test_project_list_json_format(runner, mock_auth, mock_project_list):
    """Test project list with JSON format."""
    with patch("httpx.Client") as mock_client_class:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_auth
        mock_client.get.return_value = mock_project_list
        mock_client_class.return_value = mock_client

        result = runner.invoke(
            cli, ["--username", "test@example.com", "--password", "test", "--format", "json", "project", "list"]
        )
        assert result.exit_code == 0
        assert '"name": "Test Project"' in result.output


def test_project_create(runner, mock_auth):
    """Test project create command."""
    mock_create_response = MagicMock()
    mock_create_response.status_code = 201
    mock_create_response.json.return_value = {
        "id": "new-project-id",
        "name": "New Project",
        "description": "A new test project",
        "created_at": "2026-02-23T12:00:00Z",
    }

    with patch("httpx.Client") as mock_client_class:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        # First call is login, second is create project
        mock_client.post.side_effect = [mock_auth, mock_create_response]
        mock_client_class.return_value = mock_client

        result = runner.invoke(
            cli,
            [
                "--username",
                "test@example.com",
                "--password",
                "test",
                "project",
                "create",
                "New Project",
                "--description",
                "A new test project",
            ],
        )
        assert result.exit_code == 0
        assert "Created project: new-project-id" in result.output


def test_key_list(runner, mock_auth):
    """Test key list command."""
    mock_keys_response = MagicMock()
    mock_keys_response.status_code = 200
    mock_keys_response.json.return_value = {
        "data": [
            {
                "id": "key-id-1",
                "provider": "openai",
                "encrypted_key": "encrypted-value",
                "is_archived": False,
                "created_at": "2026-02-23T12:00:00Z",
                "last_used_at": None,
            }
        ],
        "count": 1,
    }

    with patch("httpx.Client") as mock_client_class:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_auth
        mock_client.get.return_value = mock_keys_response
        mock_client_class.return_value = mock_client

        result = runner.invoke(
            cli, ["--username", "test@example.com", "--password", "test", "key", "list", "test-project-id"]
        )
        assert result.exit_code == 0
        assert "openai" in result.output


def test_budget_list(runner, mock_auth):
    """Test budget list command."""
    mock_budgets_response = MagicMock()
    mock_budgets_response.status_code = 200
    mock_budgets_response.json.return_value = {
        "data": [
            {
                "id": "budget-id-1",
                "budget_limit": "100.0000",
                "current_spend": "50.0000",
                "spend_period": "monthly",
                "created_at": "2026-02-23T12:00:00Z",
            }
        ],
        "count": 1,
    }

    with patch("httpx.Client") as mock_client_class:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_auth
        mock_client.get.return_value = mock_budgets_response
        mock_client_class.return_value = mock_client

        result = runner.invoke(
            cli, ["--username", "test@example.com", "--password", "test", "budget", "list", "test-project-id"]
        )
        assert result.exit_code == 0
        assert "monthly" in result.output


def test_client_list(runner, mock_auth):
    """Test client list command."""
    mock_clients_response = MagicMock()
    mock_clients_response.status_code = 200
    mock_clients_response.json.return_value = {
        "data": [
            {
                "id": "client-id-1",
                "name": "Test Client",
                "is_default": True,
                "created_at": "2026-02-23T12:00:00Z",
            }
        ],
        "count": 1,
    }

    with patch("httpx.Client") as mock_client_class:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_auth
        mock_client.get.return_value = mock_clients_response
        mock_client_class.return_value = mock_client

        result = runner.invoke(
            cli, ["--username", "test@example.com", "--password", "test", "client", "list", "test-project-id"]
        )
        assert result.exit_code == 0
        assert "Test Client" in result.output


def test_error_handling_auth_failure(runner):
    """Test that authentication failure is handled properly."""
    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_response.json.return_value = {"detail": "Invalid credentials"}

    with patch("httpx.Client") as mock_client_class:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = mock_response
        mock_client_class.return_value = mock_client

        result = runner.invoke(cli, ["--username", "test@example.com", "--password", "wrong", "project", "list"])
        assert result.exit_code == 1
        assert "Error: Authentication failed" in result.output


def test_consistent_output_formats_across_commands(runner, mock_auth):
    """Test that all list commands support JSON and YAML formats consistently."""
    commands = [
        (["project", "list"], {}),
        (["key", "list", "test-id"], {}),
        (["budget", "list", "test-id"], {}),
        (["client", "list", "test-id"], {}),
    ]

    for cmd_args, extra_data in commands:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": [{"id": "test", **extra_data}], "count": 1}

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_auth
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client

            # Test JSON format
            result = runner.invoke(
                cli, ["--username", "test@example.com", "--password", "test", "--format", "json"] + cmd_args
            )
            assert result.exit_code == 0
            assert '"id": "test"' in result.output

            # Test YAML format
            result = runner.invoke(
                cli, ["--username", "test@example.com", "--password", "test", "--format", "yaml"] + cmd_args
            )
            assert result.exit_code == 0
            assert "id: test" in result.output
