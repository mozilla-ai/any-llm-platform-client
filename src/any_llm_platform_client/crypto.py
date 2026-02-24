"""Cryptographic utilities for X25519 key handling and sealed box operations.

Copied and renamed from the original package to keep API stable.
"""

import base64
import hashlib
import re
import secrets
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


def generate_keypair() -> tuple[nacl.public.PrivateKey, nacl.public.PublicKey]:
    """Generate a new X25519 keypair.

    Returns:
        Tuple of (private_key, public_key) for cryptographic operations.
    """
    private_key = nacl.public.PrivateKey.generate()
    public_key = private_key.public_key
    return private_key, public_key


def format_any_llm_key(private_key: nacl.public.PrivateKey) -> str:
    """Format a private key as an ANY_LLM_KEY string.

    Args:
        private_key: X25519 private key object.

    Returns:
        Formatted ANY_LLM_KEY string: ANY.v1.<key_id>.<fingerprint>-<base64_key>
    """
    # Generate random 8-character hex key ID (4 bytes)
    key_id = secrets.token_hex(4)

    # Calculate fingerprint: SHA-256(public_key)[:4 bytes] as 8 hex chars
    public_key_bytes = bytes(private_key.public_key)
    fingerprint = hashlib.sha256(public_key_bytes).digest()[:4]
    fingerprint_hex = fingerprint.hex()

    # Encode private key as base64
    private_key_bytes = bytes(private_key)
    base64_encoded_private_key = base64.b64encode(private_key_bytes).decode("utf-8")

    # Format as ANY.v1.<key_id>.<fingerprint>-<base64_key>
    return f"ANY.v1.{key_id}.{fingerprint_hex}-{base64_encoded_private_key}"


def encrypt_data(plaintext: str, public_key: nacl.public.PublicKey) -> str:
    """Encrypt data using X25519 sealed box format.

    This implements the same sealed box encryption format as used by the backend:
    - Generate ephemeral keypair
    - Perform ECDH with recipient's public key
    - Derive nonce from SHA-512(ephemeral_public || recipient_public)[:24]
    - Encrypt with XChaCha20-Poly1305 AEAD
    - Return: ephemeral_public_key || ciphertext (base64-encoded)

    Args:
        plaintext: Data to encrypt (UTF-8 string).
        public_key: X25519 public key of the recipient.

    Returns:
        Base64-encoded encrypted data (sealed box format).
    """
    # Generate ephemeral keypair
    ephemeral_private_key = nacl.public.PrivateKey.generate()
    ephemeral_public_key = bytes(ephemeral_private_key.public_key)

    # Perform ECDH to get shared secret
    recipient_public_key = bytes(public_key)
    shared_secret = nacl.bindings.crypto_scalarmult(bytes(ephemeral_private_key), recipient_public_key)

    # Derive nonce from SHA-512(ephemeral_public || recipient_public)[:24]
    combined = ephemeral_public_key + recipient_public_key
    nonce = hashlib.sha512(combined).digest()[:24]

    # Encrypt plaintext with XChaCha20-Poly1305
    plaintext_bytes = plaintext.encode("utf-8")
    ciphertext = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext_bytes, None, nonce, shared_secret)

    # Combine ephemeral public key + ciphertext and encode as base64
    sealed_box = ephemeral_public_key + ciphertext
    return base64.b64encode(sealed_box).decode("utf-8")


def get_public_key_from_private(private_key: nacl.public.PrivateKey) -> nacl.public.PublicKey:
    """Derive public key from private key.

    Args:
        private_key: X25519 private key object.

    Returns:
        Corresponding X25519 public key object.
    """
    return private_key.public_key
