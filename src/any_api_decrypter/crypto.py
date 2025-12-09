"""Cryptographic utilities for X25519 key handling and sealed box operations."""

import base64
import hashlib
import re
from typing import NamedTuple

try:
    import nacl.bindings
    import nacl.public
except ImportError as err:
    raise ImportError(
        "Missing required PyNaCl package. Install with: pip install PyNaCl"
    ) from err


class KeyComponents(NamedTuple):
    """Components extracted from an ANY_LLM_KEY.

    The ANY_LLM_KEY format encodes a user's X25519 private key along with
    metadata for identification and verification.

    Format: ANY.v1.<key_id>.<public_key_fingerprint>-<base64_32byte_private_key>

    Attributes:
        key_id: Random 8-character hex identifier (4 bytes random data).
        public_key_fingerprint: SHA-256 hash of public key, truncated to 8 hex chars (4 bytes).
        base64_encoded_private_key: The actual X25519 private key (32 bytes, base64-encoded).
    """

    key_id: str
    public_key_fingerprint: str
    base64_encoded_private_key: str


def parse_any_llm_key(any_llm_key: str) -> KeyComponents:
    """Parse ANY_LLM_KEY format and extract components.

    The ANY_LLM_KEY format encodes a user's X25519 private key along with
    metadata for identification and verification. This function validates the
    format and extracts the individual components.

    Format: ANY.v1.<key_id>.<public_key_fingerprint>-<base64_32byte_private_key>

    Components:
        - key_id: Unique identifier for this key (UUID).
        - public_key_fingerprint: Hash of the public key for verification.
        - base64_encoded_private_key: The actual X25519 private key (32 bytes, base64-encoded).

    Args:
        any_llm_key: The ANY_LLM_KEY string to parse.

    Returns:
        KeyComponents: Named tuple containing the parsed components.

    Raises:
        ValueError: If the key format is invalid or version is not v1.

    Security Note:
        The private key component should be treated as highly sensitive.
        Never log, display, or transmit it in plaintext over insecure channels.
    """
    match = re.match(r"^ANY\.v1\.([^.]+)\.([^-]+)-(.+)$", any_llm_key)

    if not match:
        raise ValueError(
            "Invalid ANY_LLM_KEY format. Expected: ANY.v1.<key_id>.<fingerprint>-<base64_key>"
        )

    key_id, public_key_fingerprint, base64_encoded_private_key = match.groups()

    return KeyComponents(
        key_id=key_id,
        public_key_fingerprint=public_key_fingerprint,
        base64_encoded_private_key=base64_encoded_private_key,
    )


def load_private_key(private_key_base64: str) -> nacl.public.PrivateKey:
    """Load X25519 private key from base64 string.

    Args:
        private_key_base64: Base64-encoded X25519 private key (32 bytes).

    Returns:
        nacl.public.PrivateKey: The loaded X25519 private key object.

    Raises:
        ValueError: If the decoded key is not exactly 32 bytes.
        binascii.Error: If base64 decoding fails.
    """
    private_key_bytes = base64.b64decode(private_key_base64)
    if len(private_key_bytes) != 32:
        raise ValueError(
            f"X25519 private key must be 32 bytes, got {len(private_key_bytes)}"
        )
    return nacl.public.PrivateKey(private_key_bytes)


def extract_public_key(private_key: nacl.public.PrivateKey) -> str:
    """Extract public key as base64 from X25519 private key.

    Derives the corresponding public key from an X25519 private key using
    scalar multiplication on Curve25519. The public key is used for
    authentication and key agreement with the server.

    Args:
        private_key: X25519 private key object.

    Returns:
        str: Base64-encoded public key (32 bytes).
    """
    public_key_bytes = bytes(private_key.public_key)
    return base64.b64encode(public_key_bytes).decode("utf-8")


def decrypt_data(
    encrypted_data_base64: str, private_key: nacl.public.PrivateKey
) -> str:
    """Decrypt data using X25519 sealed box with XChaCha20-Poly1305.

    Format: ephemeral_public_key (32 bytes) + ciphertext

    This implements the ECIES (Elliptic Curve Integrated Encryption Scheme) pattern,
    commonly known as "sealed boxes" in libsodium. The construction provides:
    - Anonymous encryption (sender doesn't need a keypair)
    - Forward secrecy (ephemeral keys are destroyed after encryption)
    - AEAD security (confidentiality + authenticity)

    Security Properties:
    - Nonce reuse is IMPOSSIBLE by construction (derived from unique ephemeral keys)
    - XChaCha20-Poly1305 provides 192-bit nonces (collision-resistant)
    - Each message uses a fresh ephemeral keypair, guaranteeing nonce uniqueness

    Args:
        encrypted_data_base64: Base64-encoded sealed box (ephemeral_pubkey || ciphertext).
        private_key: Recipient's X25519 private key.

    Returns:
        Decrypted plaintext as UTF-8 string.

    Raises:
        ValueError: If the sealed box format is invalid.
        nacl.exceptions.CryptoError: If decryption or authentication fails.
    """
    encrypted_data = base64.b64decode(encrypted_data_base64)

    # Extract ephemeral public key (first 32 bytes) and ciphertext.
    if len(encrypted_data) < 32:
        raise ValueError("Invalid sealed box format: too short")

    ephemeral_public_key = encrypted_data[:32]
    ciphertext = encrypted_data[32:]

    # Get recipient's public key from private key.
    recipient_public_key = bytes(private_key.public_key)

    # Compute shared secret using X25519 ECDH.
    # This combines the ephemeral private key (held by sender, now destroyed)
    # with the recipient's public key to derive a shared symmetric key.
    shared_secret = nacl.bindings.crypto_scalarmult(
        bytes(private_key), ephemeral_public_key
    )

    # CRITICAL SECURITY: Derive nonce deterministically from public keys.
    #
    # Nonce derivation: SHA-512(ephemeral_pubkey || recipient_pubkey)[:24]
    #
    # Why this prevents nonce reuse:
    # 1. Sender generates a fresh random ephemeral X25519 keypair for EACH message
    # 2. ephemeral_public_key is statistically unique (2^256 keyspace)
    # 3. nonce = f(ephemeral_public_key, recipient_public_key) is therefore unique
    # 4. No state management or counters needed - nonce uniqueness guaranteed by math
    #
    # Why SHA-512 (not ECDH result directly):
    # - Domain separation: nonce must be cryptographically independent from shared_secret
    # - Even if nonce derivation is predictable, it doesn't leak key material
    # - Matches libsodium's sealed box specification
    #
    # Nonce reuse would be catastrophic for XChaCha20-Poly1305:
    # - Breaks confidentiality (plaintext recovery via XOR)
    # - Breaks authentication (Poly1305 key recovery, universal forgery)
    # This construction makes such reuse cryptographically impossible.
    combined = ephemeral_public_key + recipient_public_key
    nonce_hash = hashlib.sha512(combined).digest()[:24]  # 24 bytes for XChaCha20-Poly1305

    # Decrypt with XChaCha20-Poly1305 AEAD.
    # XChaCha20-Poly1305 provides:
    # - Confidentiality: XChaCha20 stream cipher (256-bit key)
    # - Authenticity: Poly1305 MAC (128-bit security)
    # - 192-bit nonces (vs 96-bit in standard ChaCha20) for collision resistance
    decrypted_data = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
        ciphertext, None, nonce_hash, shared_secret
    )

    return decrypted_data.decode("utf-8")
