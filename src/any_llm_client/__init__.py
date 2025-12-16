"""ANY-LLM Client - Decrypt provider API keys using X25519 sealed box encryption.

This package provides tools to decrypt provider API keys using X25519 sealed box
encryption and challenge-response authentication with the ANY LLM backend.

Example:
    >>> from any_llm_client import decrypt_data, parse_any_llm_key
    >>> from any_llm_client.client import AnyLLMClient
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

try:
    # Prefer the installed package version (PEP 566 metadata)
    __version__ = _pkg_version("any-llm-client")
except PackageNotFoundError:
    try:
        from ._version import version as __version__  # type: ignore
    except Exception:
        __version__ = "0.0.0-dev"

# Export public API
from .client import AnyLLMClient
from .crypto import (
    KeyComponents,
    decrypt_data,
    extract_public_key,
    load_private_key,
    parse_any_llm_key,
)
from .exceptions import ChallengeCreationError, ProviderKeyFetchError

__all__ = [
    # Crypto functions
    "KeyComponents",
    "parse_any_llm_key",
    "load_private_key",
    "extract_public_key",
    "decrypt_data",
    # Client class
    "AnyLLMClient",
    # Exceptions
    "ChallengeCreationError",
    "ProviderKeyFetchError",
    # Version
    "__version__",
]
