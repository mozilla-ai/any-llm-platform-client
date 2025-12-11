"""ANY-LLM Crypto - Decrypt provider API keys using X25519 sealed box encryption.

This package provides tools to decrypt provider API keys using X25519 sealed box
encryption and challenge-response authentication with the ANY LLM backend.

Example:
    >>> from any_llm_crypto import decrypt_data, parse_any_llm_key
    >>> from any_llm_crypto.client import AnyLLMCryptoClient
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

try:
    # Prefer the installed package version (PEP 566 metadata)
    __version__ = _pkg_version("any-llm-crypto")
except PackageNotFoundError:
    try:
        from ._version import version as __version__  # type: ignore
    except Exception:
        __version__ = "0.0.0-dev"

# Export public API
from .client import AnyLLMCryptoClient
from .crypto import (
    KeyComponents,
    decrypt_data,
    extract_public_key,
    load_private_key,
    parse_any_llm_key,
)

__all__ = [
    # Crypto functions
    "KeyComponents",
    "parse_any_llm_key",
    "load_private_key",
    "extract_public_key",
    "decrypt_data",
    # Client class
    "AnyLLMCryptoClient",
    # Version
    "__version__",
]
