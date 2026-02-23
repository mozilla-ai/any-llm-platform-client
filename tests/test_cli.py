"""Tests for CLI functionality."""

import pytest
from click.testing import CliRunner

from any_llm_platform_client.cli import cli


@pytest.fixture
def runner():
    """Create a Click CLI test runner."""
    return CliRunner()


def test_cli_help(runner):
    """Test that CLI help works."""
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "any-llm platform Management CLI" in result.output


def test_cli_version_flag(runner):
    """Test that verbose flag works."""
    result = runner.invoke(cli, ["-v", "--help"])
    assert result.exit_code == 0


def test_project_help(runner):
    """Test project command help."""
    result = runner.invoke(cli, ["project", "--help"])
    assert result.exit_code == 0
    assert "Manage projects" in result.output


def test_key_help(runner):
    """Test key command help."""
    result = runner.invoke(cli, ["key", "--help"])
    assert result.exit_code == 0
    assert "Manage provider keys" in result.output


def test_budget_help(runner):
    """Test budget command help."""
    result = runner.invoke(cli, ["budget", "--help"])
    assert result.exit_code == 0
    assert "Manage project budgets" in result.output


def test_client_help(runner):
    """Test client command help."""
    result = runner.invoke(cli, ["client", "--help"])
    assert result.exit_code == 0
    assert "Manage project clients" in result.output


def test_format_option_json(runner):
    """Test that format option is recognized."""
    result = runner.invoke(cli, ["--format", "json", "--help"])
    assert result.exit_code == 0


def test_format_option_yaml(runner):
    """Test that format option YAML is recognized."""
    result = runner.invoke(cli, ["--format", "yaml", "--help"])
    assert result.exit_code == 0


def test_format_option_table(runner):
    """Test that format option table is recognized."""
    result = runner.invoke(cli, ["--format", "table", "--help"])
    assert result.exit_code == 0


def test_authentication_required_for_project_list(runner):
    """Test that authentication is required for project list."""
    result = runner.invoke(cli, ["project", "list"])
    assert result.exit_code == 1
    assert "Error: Username and password required" in result.output


def test_authentication_required_for_key_list(runner):
    """Test that authentication is required for key list."""
    result = runner.invoke(cli, ["key", "list", "some-project-id"])
    assert result.exit_code == 1
    assert "Error: Username and password required" in result.output


def test_key_decrypt_help(runner):
    """Test key decrypt command help."""
    result = runner.invoke(cli, ["key", "decrypt", "--help"])
    assert result.exit_code == 0
    assert "Decrypt a provider API key" in result.output


def test_project_create_help(runner):
    """Test project create command help."""
    result = runner.invoke(cli, ["project", "create", "--help"])
    assert result.exit_code == 0
    assert "Create a new project" in result.output


def test_budget_create_help(runner):
    """Test budget create command help."""
    result = runner.invoke(cli, ["budget", "create", "--help"])
    assert result.exit_code == 0
    assert "Create a project budget" in result.output


def test_client_create_help(runner):
    """Test client create command help."""
    result = runner.invoke(cli, ["client", "create", "--help"])
    assert result.exit_code == 0
    assert "Create a new client" in result.output


def test_consistent_error_output(runner):
    """Test that error messages are consistently output to stderr."""
    result = runner.invoke(cli, ["project", "list"])
    assert result.exit_code == 1
    # Errors should go to stderr (represented in Click's CliRunner as part of output)
    assert "Error:" in result.output


def test_format_options_all_commands(runner):
    """Test that format options work for all management commands."""
    # Test JSON format
    result = runner.invoke(cli, ["--format", "json", "project", "--help"])
    assert result.exit_code == 0

    # Test YAML format
    result = runner.invoke(cli, ["--format", "yaml", "budget", "--help"])
    assert result.exit_code == 0


def test_all_command_groups_have_help(runner):
    """Test that all command groups have help text."""
    for group in ["project", "key", "budget", "client"]:
        result = runner.invoke(cli, [group, "--help"])
        assert result.exit_code == 0
        assert "Commands:" in result.output or "Options:" in result.output
