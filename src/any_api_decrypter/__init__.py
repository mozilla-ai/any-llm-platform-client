"""ANY API Decrypter - Decrypt provider API keys using X25519 sealed box encryption.

This package provides tools to decrypt provider API keys using X25519 sealed box
encryption and challenge-response authentication with the ANY LLM backend.

Example:
    >>> from any_api_decrypter import decrypt_data, parse_any_llm_key
    >>> from any_api_decrypter.client import fetch_provider_key, create_challenge
"""

__version__ = "0.1.0"
__author__ = "Mozilla AI"
__license__ = "MIT"

# Export public API
from .client import (
    create_challenge,
    decrypt_provider_key_value,
    fetch_provider_key,
    get_api_base_url,
    set_api_base_url,
    solve_challenge,
)
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
    # Client functions
    "create_challenge",
    "solve_challenge",
    "fetch_provider_key",
    "decrypt_provider_key_value",
    "set_api_base_url",
    "get_api_base_url",
    # Version
    "__version__",
]
