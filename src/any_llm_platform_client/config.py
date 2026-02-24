"""Configuration file management for any-llm CLI.

This module handles reading and writing the CLI configuration file stored at ~/.any-llm/config.json.
The configuration includes OAuth tokens, authentication method, and default settings.
"""

import json
import logging
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Configuration file location
CONFIG_DIR = Path.home() / ".any-llm"
CONFIG_FILE = CONFIG_DIR / "config.json"

# File permissions: owner read/write only (0600)
CONFIG_FILE_MODE = 0o600
CONFIG_DIR_MODE = 0o700


@dataclass
class OAuthTokenData:
    """OAuth token information."""

    provider: str  # "google" or "github"
    access_token: str
    token_type: str  # "bearer"
    expires_at: str | None = None  # ISO format timestamp
    user_email: str | None = None

    def is_expired(self) -> bool:
        """Check if token is expired.

        Returns:
            True if token is expired or expires_at is not set, False otherwise
        """
        if not self.expires_at:
            return False

        try:
            expiry = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
            # If expiry is naive (no timezone), assume UTC
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=UTC)
            return datetime.now(UTC) >= expiry
        except (ValueError, AttributeError):
            return False


@dataclass
class ConfigData:
    """CLI configuration data."""

    version: str = "1.0"
    auth_method: str | None = None  # "oauth" or "password"
    oauth_token: OAuthTokenData | None = None
    any_llm_platform_url: str | None = None


def ensure_config_dir() -> None:
    """Create config directory if it doesn't exist with proper permissions."""
    if not CONFIG_DIR.exists():
        logger.debug("Creating config directory: %s", CONFIG_DIR)
        CONFIG_DIR.mkdir(mode=CONFIG_DIR_MODE, parents=True, exist_ok=True)
    else:
        # Ensure permissions are correct
        current_mode = CONFIG_DIR.stat().st_mode & 0o777
        if current_mode != CONFIG_DIR_MODE:
            logger.debug("Updating config directory permissions to %s", oct(CONFIG_DIR_MODE))
            CONFIG_DIR.chmod(CONFIG_DIR_MODE)


def load_config() -> ConfigData:
    """Load configuration from file.

    Returns:
        ConfigData object with loaded configuration or default values
    """
    if not CONFIG_FILE.exists():
        logger.debug("Config file does not exist, returning default config")
        return ConfigData()

    try:
        with CONFIG_FILE.open(encoding="utf-8") as f:
            data = json.load(f)

        # Parse OAuth token if present
        oauth_token = None
        if data.get("oauth_token"):
            oauth_token = OAuthTokenData(**data["oauth_token"])

        config = ConfigData(
            version=data.get("version", "1.0"),
            auth_method=data.get("auth_method"),
            oauth_token=oauth_token,
            any_llm_platform_url=data.get("any_llm_platform_url"),
        )

        logger.debug("Loaded config from %s", CONFIG_FILE)
        return config

    except (json.JSONDecodeError, KeyError, TypeError) as e:
        logger.warning("Failed to load config file: %s, returning default config", e)
        return ConfigData()


def save_config(config: ConfigData) -> None:
    """Save configuration to file.

    Args:
        config: ConfigData object to save
    """
    ensure_config_dir()

    # Convert to dict
    data: dict[str, Any] = {
        "version": config.version,
        "auth_method": config.auth_method,
        "oauth_token": asdict(config.oauth_token) if config.oauth_token else None,
        "any_llm_platform_url": config.any_llm_platform_url,
    }

    # Write to file
    with CONFIG_FILE.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    # Set proper permissions
    CONFIG_FILE.chmod(CONFIG_FILE_MODE)

    logger.debug("Saved config to %s", CONFIG_FILE)


def get_oauth_token() -> OAuthTokenData | None:
    """Get stored OAuth token.

    Returns:
        OAuthTokenData if OAuth token exists and is not expired, None otherwise
    """
    config = load_config()

    if not config.oauth_token:
        return None

    if config.oauth_token.is_expired():
        logger.debug("OAuth token is expired")
        return None

    return config.oauth_token


def save_oauth_token(
    provider: str,
    access_token: str,
    token_type: str = "bearer",
    expires_at: str | None = None,
    user_email: str | None = None,
) -> None:
    """Save OAuth token to config.

    Args:
        provider: OAuth provider name ("google" or "github")
        access_token: JWT access token from backend
        token_type: Token type (usually "bearer")
        expires_at: Token expiration timestamp in ISO format
        user_email: User's email address
    """
    config = load_config()

    config.auth_method = "oauth"
    config.oauth_token = OAuthTokenData(
        provider=provider,
        access_token=access_token,
        token_type=token_type,
        expires_at=expires_at,
        user_email=user_email,
    )

    save_config(config)
    logger.debug("Saved OAuth token for provider: %s", provider)


def clear_oauth_token() -> None:
    """Remove OAuth token from config."""
    config = load_config()

    if config.oauth_token:
        config.oauth_token = None
        config.auth_method = None
        save_config(config)
        logger.debug("Cleared OAuth token from config")


def get_platform_url() -> str | None:
    """Get configured platform URL.

    Returns:
        Platform URL from config, or None if not set
    """
    config = load_config()
    return config.any_llm_platform_url


def set_platform_url(url: str) -> None:
    """Set platform URL in config.

    Args:
        url: Platform URL to save
    """
    config = load_config()
    config.any_llm_platform_url = url
    save_config(config)
    logger.debug("Set platform URL: %s", url)
