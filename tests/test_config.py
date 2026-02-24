"""Tests for config module."""

from datetime import datetime, timedelta

import pytest

from any_llm_platform_client.config import (
    ConfigData,
    OAuthTokenData,
    clear_oauth_token,
    get_oauth_token,
    load_config,
    save_config,
    save_oauth_token,
)


@pytest.fixture
def temp_config_dir(tmp_path, monkeypatch):
    """Create temporary config directory for testing."""
    config_dir = tmp_path / ".any-llm"
    config_file = config_dir / "config.json"

    # Monkey patch the config paths
    monkeypatch.setattr("any_llm_platform_client.config.CONFIG_DIR", config_dir)
    monkeypatch.setattr("any_llm_platform_client.config.CONFIG_FILE", config_file)

    return config_dir, config_file


def test_oauth_token_data_not_expired():
    """Test OAuthTokenData.is_expired() when token is not expired."""
    future_time = datetime.now() + timedelta(hours=1)
    token = OAuthTokenData(
        provider="google",
        access_token="test_token",
        token_type="bearer",
        expires_at=future_time.isoformat(),
    )

    assert not token.is_expired()


def test_oauth_token_data_expired():
    """Test OAuthTokenData.is_expired() when token is expired."""
    past_time = datetime.now() - timedelta(hours=1)
    token = OAuthTokenData(
        provider="google",
        access_token="test_token",
        token_type="bearer",
        expires_at=past_time.isoformat(),
    )

    assert token.is_expired()


def test_oauth_token_data_no_expiry():
    """Test OAuthTokenData.is_expired() when expires_at is None."""
    token = OAuthTokenData(
        provider="google",
        access_token="test_token",
        token_type="bearer",
        expires_at=None,
    )

    assert not token.is_expired()


def test_load_config_no_file(temp_config_dir):  # noqa: ARG001
    """Test loading config when file doesn't exist."""
    config = load_config()

    assert isinstance(config, ConfigData)
    assert config.version == "1.0"
    assert config.auth_method is None
    assert config.oauth_token is None
    assert config.any_llm_platform_url is None


def test_save_and_load_config(temp_config_dir):
    """Test saving and loading config."""
    config_dir, config_file = temp_config_dir

    # Create config
    oauth_token = OAuthTokenData(
        provider="google",
        access_token="test_token_123",
        token_type="bearer",
        expires_at="2026-12-31T23:59:59",
        user_email="test@example.com",
    )

    config = ConfigData(
        version="1.0",
        auth_method="oauth",
        oauth_token=oauth_token,
        any_llm_platform_url="http://localhost:8100/api/v1",
    )

    # Save config
    save_config(config)

    # Verify file exists
    assert config_file.exists()

    # Load config
    loaded_config = load_config()

    assert loaded_config.version == "1.0"
    assert loaded_config.auth_method == "oauth"
    assert loaded_config.oauth_token is not None
    assert loaded_config.oauth_token.provider == "google"
    assert loaded_config.oauth_token.access_token == "test_token_123"
    assert loaded_config.oauth_token.token_type == "bearer"
    assert loaded_config.oauth_token.user_email == "test@example.com"
    assert loaded_config.any_llm_platform_url == "http://localhost:8100/api/v1"


def test_save_oauth_token(temp_config_dir):
    """Test saving OAuth token."""
    config_dir, config_file = temp_config_dir

    save_oauth_token(
        provider="github",
        access_token="github_token_456",
        token_type="bearer",
        expires_at="2026-12-31T23:59:59",
        user_email="github@example.com",
    )

    # Load and verify
    config = load_config()

    assert config.auth_method == "oauth"
    assert config.oauth_token is not None
    assert config.oauth_token.provider == "github"
    assert config.oauth_token.access_token == "github_token_456"
    assert config.oauth_token.user_email == "github@example.com"


def test_get_oauth_token(temp_config_dir):
    """Test getting OAuth token."""
    config_dir, config_file = temp_config_dir

    # No token initially
    token = get_oauth_token()
    assert token is None

    # Save a token
    future_time = datetime.now() + timedelta(hours=1)
    save_oauth_token(
        provider="google",
        access_token="test_token",
        token_type="bearer",
        expires_at=future_time.isoformat(),
    )

    # Get token
    token = get_oauth_token()
    assert token is not None
    assert token.provider == "google"
    assert token.access_token == "test_token"


def test_get_oauth_token_expired(temp_config_dir):
    """Test getting expired OAuth token returns None."""
    config_dir, config_file = temp_config_dir

    # Save an expired token
    past_time = datetime.now() - timedelta(hours=1)
    save_oauth_token(
        provider="google",
        access_token="expired_token",
        token_type="bearer",
        expires_at=past_time.isoformat(),
    )

    # Get token should return None
    token = get_oauth_token()
    assert token is None


def test_clear_oauth_token(temp_config_dir):
    """Test clearing OAuth token."""
    config_dir, config_file = temp_config_dir

    # Save a token
    save_oauth_token(
        provider="google",
        access_token="test_token",
        token_type="bearer",
    )

    # Verify token exists
    token = get_oauth_token()
    assert token is not None

    # Clear token
    clear_oauth_token()

    # Verify token is cleared
    token = get_oauth_token()
    assert token is None

    # Verify config is updated
    config = load_config()
    assert config.oauth_token is None
    assert config.auth_method is None


def test_config_file_permissions(temp_config_dir):
    """Test that config file has correct permissions."""
    config_dir, config_file = temp_config_dir

    save_oauth_token(
        provider="google",
        access_token="test_token",
        token_type="bearer",
    )

    # Check file permissions (0600 = owner read/write only)
    file_mode = config_file.stat().st_mode & 0o777
    assert file_mode == 0o600


def test_load_config_invalid_json(temp_config_dir):
    """Test loading config with invalid JSON."""
    config_dir, config_file = temp_config_dir

    # Create config directory
    config_dir.mkdir(parents=True, exist_ok=True)

    # Write invalid JSON
    config_file.write_text("invalid json {")

    # Should return default config
    config = load_config()
    assert isinstance(config, ConfigData)
    assert config.version == "1.0"
    assert config.oauth_token is None
