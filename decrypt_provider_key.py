#!/usr/bin/env python3
"""Script to decrypt provider keys using the ANY_LLM_KEY format.

Installation:
    pip install -r requirements-decrypt.txt

Usage:
    python decrypt_provider_key.py                # Interactive mode (recommended)
    python decrypt_provider_key.py <provider>     # Direct mode

Example:
    python decrypt_provider_key.py                # Will prompt for ANY_LLM_KEY
    python decrypt_provider_key.py openai

The script expects ANY_LLM_KEY in the format:
    ANY.v1.<key_id>.<fingerprint>-<base64_32byte_private_key>
"""

import base64
import os
import sys
import uuid
from typing import NamedTuple

import requests

try:
    import hashlib

    import nacl.bindings
    import nacl.public
except ImportError:
    print("❌ Error: Missing required Python packages")
    print("\nPlease install dependencies:")
    print("  pip install PyNaCl requests")
    sys.exit(1)


# Configuration
# TODO: Change to HTTPS in production to prevent MITM attacks.
API_BASE_URL = "http://localhost:8000/api/v1"


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
    import re

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
        raise ValueError(f"X25519 private key must be 32 bytes, got {len(private_key_bytes)}")
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


def decrypt_data(encrypted_data_base64: str, private_key: nacl.public.PrivateKey) -> str:
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
    shared_secret = nacl.bindings.crypto_scalarmult(bytes(private_key), ephemeral_public_key)

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


def create_challenge(public_key: str) -> dict:
    """Create an authentication challenge with the server.

    The server generates a random UUID, encrypts it with the user's public key
    using a sealed box, and returns it. The client must decrypt this challenge
    to prove possession of the corresponding private key.

    Args:
        public_key: Base64-encoded X25519 public key.

    Returns:
        dict: Response containing 'encrypted_challenge' (sealed box format).

    Raises:
        SystemExit: If challenge creation fails or public key is not registered.
    """
    print("📝 Creating authentication challenge...")

    response = requests.post(f"{API_BASE_URL}/auth/", json={"encryption_key": public_key})

    if response.status_code != 200:
        print(f"❌ Error creating challenge: {response.status_code}")
        print(response.json())

        if "No project found" in str(response.json()):
            print("\n⚠️  The public key from your ANY_LLM_KEY doesn't match any project.")
            print("Solution: Go to your project page and generate a new API key.")
        sys.exit(1)

    data = response.json()
    print("✅ Challenge created")
    return data


def solve_challenge(encrypted_challenge: str, private_key: nacl.public.PrivateKey) -> uuid.UUID:
    """Decrypt the server's challenge to prove key possession.

    Decrypts the server's encrypted challenge using the sealed box construction.
    The decrypted UUID proves possession of the private key and is used for
    subsequent authenticated requests.

    Args:
        encrypted_challenge: Base64-encoded sealed box containing the challenge UUID.
        private_key: User's X25519 private key.

    Returns:
        uuid.UUID: The decrypted challenge UUID.

    Raises:
        ValueError: If decryption fails or UUID format is invalid.
        nacl.exceptions.CryptoError: If authentication tag verification fails.
    """
    print("🔐 Decrypting challenge...")

    decrypted_uuid_str = decrypt_data(encrypted_challenge, private_key)
    solved_challenge = uuid.UUID(decrypted_uuid_str)

    print(f"✅ Challenge solved: {solved_challenge}")
    return solved_challenge


def fetch_provider_key(provider: str, public_key: str, solved_challenge: uuid.UUID) -> dict:
    """Fetch the encrypted provider API key using the solved challenge.

    Authenticates using the solved challenge UUID and retrieves the encrypted
    provider API key from the server. The challenge-response proves the client
    possesses the private key without transmitting it.

    Args:
        provider: Provider name (e.g., "openai", "anthropic").
        public_key: Base64-encoded X25519 public key.
        solved_challenge: The decrypted challenge UUID.

    Returns:
        dict: Response containing provider key metadata and 'encrypted_key' field.

    Raises:
        SystemExit: If the request fails, authentication is invalid, or provider not found.
    """
    print(f"🔑 Fetching provider key for {provider}...")

    response = requests.get(
        f"{API_BASE_URL}/provider-keys/{provider}",
        headers={"encryption-key": public_key, "AnyLLM-Challenge-Response": str(solved_challenge)},
    )

    if response.status_code != 200:
        print(f"❌ Error fetching provider key: {response.status_code}")
        print(response.json())
        sys.exit(1)

    data = response.json()
    print("✅ Provider key fetched")
    return data


def decrypt_provider_key_value(encrypted_key: str, private_key: nacl.public.PrivateKey) -> str:
    """Decrypt the provider's API key to plaintext.

    Decrypts the provider's API key (e.g., OpenAI API key) using the sealed box
    construction. This reveals the plaintext API key that can be used to
    authenticate with the provider's services.

    Args:
        encrypted_key: Base64-encoded sealed box containing the provider API key.
        private_key: User's X25519 private key.

    Returns:
        str: The decrypted provider API key (plaintext).

    Raises:
        ValueError: If decryption fails.
        nacl.exceptions.CryptoError: If authentication tag verification fails.

    Security Note:
        The decrypted API key should be handled carefully and never logged or
        transmitted over insecure channels.
    """
    print("🔓 Decrypting provider API key...")

    decrypted_key = decrypt_data(encrypted_key, private_key)
    print("✅ Decrypted successfully!")
    return decrypted_key


def get_any_llm_key() -> str:
    """Get ANY_LLM_KEY from environment variable or prompt user."""
    any_llm_key = os.getenv("ANY_LLM_KEY")

    if any_llm_key:
        print("✅ Using ANY_LLM_KEY from environment variable")
        return any_llm_key

    print("\n🔑 ANY_LLM_KEY Required")
    print("=" * 60)
    print("Please paste your ANY_LLM_KEY (generated from the project page)")
    print("Format: ANY.v1.<kid>.<fingerprint>-<base64_key>")
    print()
    print("💡 TIP: Set as environment variable:")
    print("   export ANY_LLM_KEY='your-key-here'")
    print()

    try:
        any_llm_key = input("Paste key and press Enter: ").strip()
        if not any_llm_key:
            print("❌ ANY_LLM_KEY is required")
            sys.exit(1)
        return any_llm_key
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
        sys.exit(0)


def interactive_mode() -> str:
    """Interactive mode - asks for provider only."""
    print("\n🔐 Interactive Mode")
    print("=" * 60)
    print("💡 Find provider names in the web UI")
    print()

    try:
        provider = input("Enter Provider name (e.g., openai, anthropic): ").strip()
        if not provider:
            print("❌ Provider name is required")
            sys.exit(1)

        return provider

    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
        sys.exit(0)


def main() -> None:
    """Main entry point for the provider key decryption script.

    Supports both interactive and direct modes:
    - Interactive: Prompts for provider name
    - Direct: Accepts provider as command-line argument

    The script performs challenge-response authentication with the API,
    then decrypts and displays the provider API key.
    """
    # Parse command line arguments
    if len(sys.argv) == 2:
        provider = sys.argv[1]
        interactive = False
    elif len(sys.argv) == 1:
        provider = None
        interactive = True
    else:
        print("Usage:")
        print("  python decrypt_provider_key.py             # Interactive mode")
        print("  python decrypt_provider_key.py <provider>  # Direct mode")
        print("\nExample:")
        print("  python decrypt_provider_key.py openai")
        sys.exit(1)

    print("=" * 60)
    print("🔐 Provider Key Decryption Script")
    print("=" * 60)

    if not interactive:
        print(f"Provider: {provider}")

    print("=" * 60)
    print()

    try:
        # Get ANY_LLM_KEY
        any_llm_key = get_any_llm_key()
        print()

        # Parse ANY_LLM_KEY
        print("🔍 Parsing ANY_LLM_KEY...")
        kid, fingerprint, private_key_base64 = parse_any_llm_key(any_llm_key)
        print(f"✅ Key ID: {kid}")
        print(f"✅ Fingerprint: {fingerprint}")
        print()

        # Load private key
        print("🔑 Loading X25519 private key...")
        private_key = load_private_key(private_key_base64)
        print("✅ Private key loaded")
        print()

        # Extract public key
        print("🔑 Extracting public key...")
        public_key = extract_public_key(private_key)
        print("✅ Public key extracted")
        print()

        # Get provider if interactive mode
        if interactive:
            provider = interactive_mode()
            print()

        # Step 1: Create challenge
        challenge_data = create_challenge(public_key)
        print()

        # Step 2: Solve challenge
        solved_challenge = solve_challenge(challenge_data["encrypted_challenge"], private_key)
        print()

        # Step 3: Fetch provider key (encrypted)
        provider_key_data = fetch_provider_key(provider, public_key, solved_challenge)
        print()

        # Step 4: Decrypt the provider key
        decrypted_api_key = decrypt_provider_key_value(provider_key_data["encrypted_key"], private_key)
        print()

        # Display results
        print("=" * 60)
        print("🎉 SUCCESS!")
        print("=" * 60)
        print(f"Provider: {provider_key_data['provider']}")
        print(f"Project ID: {provider_key_data['project_id']}")
        print(f"Created: {provider_key_data['created_at']}")
        print()
        print("🔑 Decrypted API Key:")
        print(f"   {decrypted_api_key}")
        print("=" * 60)

    except requests.RequestException as e:
        print(f"❌ Network error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
