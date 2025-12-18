"""Cryptographic utilities for X25519 key handling and sealed box operations.

Copied and renamed from the original package to keep API stable.
"""

import base64
import hashlib
import re
from typing import NamedTuple

try:
    import nacl.bindings
    import nacl.public
except ImportError as err:
    raise ImportError("Missing required PyNaCl package. Install with: pip install PyNaCl") from err


class KeyComponents(NamedTuple):
    """Components of a parsed ANY_LLM_KEY.

    Attributes:
        key_id: The unique key identifier.
        public_key_fingerprint: Fingerprint of the public key.
        base64_encoded_private_key: Base64-encoded X25519 private key.
    """

    key_id: str
    public_key_fingerprint: str
    base64_encoded_private_key: str


def parse_any_llm_key(any_llm_key: str) -> KeyComponents:
    """Parse an ANY_LLM_KEY string into its components.

    Args:
        any_llm_key: The ANY_LLM_KEY string in format ANY.v1.<key_id>.<fingerprint>-<base64_key>.

    Returns:
        KeyComponents tuple containing the parsed key components.

    Raises:
        ValueError: If the key format is invalid.
    """
    match = re.match(r"^ANY\.v1\.([^.]+)\.([^-]+)-(.+)$", any_llm_key)
    if not match:
        raise ValueError("Invalid ANY_LLM_KEY format. Expected: ANY.v1.<key_id>.<fingerprint>-<base64_key>")
    key_id, public_key_fingerprint, base64_encoded_private_key = match.groups()
    return KeyComponents(
        key_id=key_id,
        public_key_fingerprint=public_key_fingerprint,
        base64_encoded_private_key=base64_encoded_private_key,
    )


def load_private_key(private_key_base64: str) -> nacl.public.PrivateKey:
    """Load an X25519 private key from a base64-encoded string.

    Args:
        private_key_base64: Base64-encoded X25519 private key (32 bytes).

    Returns:
        nacl.public.PrivateKey object for cryptographic operations.

    Raises:
        ValueError: If the decoded key is not exactly 32 bytes.
    """
    private_key_bytes = base64.b64decode(private_key_base64)
    if len(private_key_bytes) != 32:
        raise ValueError(f"X25519 private key must be 32 bytes, got {len(private_key_bytes)}")
    return nacl.public.PrivateKey(private_key_bytes)


def extract_public_key(private_key: nacl.public.PrivateKey) -> str:
    """Extract the public key from an X25519 private key.

    Args:
        private_key: X25519 private key object.

    Returns:
        Base64-encoded public key string.
    """
    public_key_bytes = bytes(private_key.public_key)
    return base64.b64encode(public_key_bytes).decode("utf-8")


def decrypt_data(encrypted_data_base64: str, private_key: nacl.public.PrivateKey) -> str:
    """Decrypt data using X25519 sealed box format.

    Args:
        encrypted_data_base64: Base64-encoded encrypted data.
        private_key: X25519 private key for decryption.

    Returns:
        Decrypted data as a UTF-8 string.

    Raises:
        ValueError: If the encrypted data format is invalid.
    """
    encrypted_data = base64.b64decode(encrypted_data_base64)
    if len(encrypted_data) < 32:
        raise ValueError("Invalid sealed box format: too short")

    ephemeral_public_key = encrypted_data[:32]
    ciphertext = encrypted_data[32:]
    recipient_public_key = bytes(private_key.public_key)
    shared_secret = nacl.bindings.crypto_scalarmult(bytes(private_key), ephemeral_public_key)
    combined = ephemeral_public_key + recipient_public_key
    nonce_hash = hashlib.sha512(combined).digest()[:24]
    decrypted_data = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
        ciphertext, None, nonce_hash, shared_secret
    )

    return decrypted_data.decode("utf-8")
