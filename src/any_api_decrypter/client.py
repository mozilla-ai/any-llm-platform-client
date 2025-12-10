"""API client for communicating with the ANY LLM backend."""

import sys
import uuid

import requests

from .crypto import decrypt_data

# Configuration
API_BASE_URL = "http://localhost:8000/api/v1"


def set_api_base_url(url: str) -> None:
    """Set the base URL for the API client.

    Args:
        url: The base URL to use for API requests.
    """
    global API_BASE_URL
    API_BASE_URL = url


def get_api_base_url() -> str:
    """Get the current base URL for the API client.

    Returns:
        str: The current API base URL.
    """
    return API_BASE_URL


def create_challenge(public_key: str, verbose: bool = True) -> dict:
    """Create an authentication challenge with the server.

    The server generates a random UUID, encrypts it with the user's public key
    using a sealed box, and returns it. The client must decrypt this challenge
    to prove possession of the corresponding private key.

    Args:
        public_key: Base64-encoded X25519 public key.
        verbose: Whether to print status messages. Defaults to True.

    Returns:
        dict: Response containing 'encrypted_challenge' (sealed box format).

    Raises:
        SystemExit: If challenge creation fails or public key is not registered.
        requests.RequestException: If the API request fails.
    """
    if verbose:
        print("📝 Creating authentication challenge...")

    response = requests.post(f"{API_BASE_URL}/auth/", json={"encryption_key": public_key})

    if response.status_code != 200:
        if verbose:
            print(f"❌ Error creating challenge: {response.status_code}")
            print(response.json())

            if "No project found" in str(response.json()):
                print("\n⚠️  The public key from your ANY_LLM_KEY doesn't match any project.")
                print("Solution: Go to your project page and generate a new API key.")
        sys.exit(1)

    data = response.json()
    if verbose:
        print("✅ Challenge created")
    return data


def solve_challenge(encrypted_challenge: str, private_key: object, verbose: bool = True) -> uuid.UUID:
    """Decrypt the server's challenge to prove key possession.

    Decrypts the server's encrypted challenge using the sealed box construction.
    The decrypted UUID proves possession of the private key and is used for
    subsequent authenticated requests.

    Args:
        encrypted_challenge: Base64-encoded sealed box containing the challenge UUID.
        private_key: User's X25519 private key (nacl.public.PrivateKey).
        verbose: Whether to print status messages. Defaults to True.

    Returns:
        uuid.UUID: The decrypted challenge UUID.

    Raises:
        ValueError: If decryption fails or UUID format is invalid.
        nacl.exceptions.CryptoError: If authentication tag verification fails.
    """
    if verbose:
        print("🔐 Decrypting challenge...")

    decrypted_uuid_str = decrypt_data(encrypted_challenge, private_key)
    solved_challenge = uuid.UUID(decrypted_uuid_str)

    if verbose:
        print(f"✅ Challenge solved: {solved_challenge}")
    return solved_challenge


def fetch_provider_key(
    provider: str,
    public_key: str,
    solved_challenge: uuid.UUID,
    verbose: bool = True,
) -> dict:
    """Fetch the encrypted provider API key using the solved challenge.

    Authenticates using the solved challenge UUID and retrieves the encrypted
    provider API key from the server. The challenge-response proves the client
    possesses the private key without transmitting it.

    Args:
        provider: Provider name (e.g., "openai", "anthropic").
        public_key: Base64-encoded X25519 public key.
        solved_challenge: The decrypted challenge UUID.
        verbose: Whether to print status messages. Defaults to True.

    Returns:
        dict: Response containing provider key metadata and 'encrypted_key' field.

    Raises:
        SystemExit: If the request fails, authentication is invalid, or provider not found.
        requests.RequestException: If the API request fails.
    """
    if verbose:
        print(f"🔑 Fetching provider key for {provider}...")

    response = requests.get(
        f"{API_BASE_URL}/provider-keys/{provider}",
        headers={
            "encryption-key": public_key,
            "AnyLLM-Challenge-Response": str(solved_challenge),
        },
    )

    if response.status_code != 200:
        if verbose:
            print(f"❌ Error fetching provider key: {response.status_code}")
            print(response.json())
        sys.exit(1)

    data = response.json()
    if verbose:
        print("✅ Provider key fetched")
    return data


def decrypt_provider_key_value(encrypted_key: str, private_key: object, verbose: bool = True) -> str:
    """Decrypt the provider's API key to plaintext.

    Decrypts the provider's API key (e.g., OpenAI API key) using the sealed box
    construction. This reveals the plaintext API key that can be used to
    authenticate with the provider's services.

    Args:
        encrypted_key: Base64-encoded sealed box containing the provider API key.
        private_key: User's X25519 private key (nacl.public.PrivateKey).
        verbose: Whether to print status messages. Defaults to True.

    Returns:
        str: The decrypted provider API key (plaintext).

    Raises:
        ValueError: If decryption fails.
        nacl.exceptions.CryptoError: If authentication tag verification fails.

    Security Note:
        The decrypted API key should be handled carefully and never logged or
        transmitted over insecure channels.
    """
    if verbose:
        print("🔓 Decrypting provider API key...")

    decrypted_key = decrypt_data(encrypted_key, private_key)
    if verbose:
        print("✅ Decrypted successfully!")
    return decrypted_key
