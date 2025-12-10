"""API client for communicating with the ANY LLM backend."""

import logging
import sys
import uuid

import requests

from .crypto import decrypt_data

logger = logging.getLogger(__name__)


class AnyApiClient:
    """Client for communicating with the ANY LLM backend.

    This class encapsulates the API base URL and provides methods for the
    challenge-response flow and provider key retrieval. Module-level helper
    functions delegate to a default instance to preserve the public API.
    """

    def __init__(self, api_base_url: str | None = None) -> None:
        """Create a new `AnyApiClient`.

        Args:
            api_base_url: Optional override for the backend API base URL.
        """
        self.api_base_url = api_base_url or "http://localhost:8000/api/v1"

    def set_api_base_url(self, url: str) -> None:
        """Set the base URL for the API client.

        Args:
            url: The base URL to use for API requests.
        """
        self.api_base_url = url

    def get_api_base_url(self) -> str:
        """Get the current base URL for the API client."""
        return self.api_base_url

    def create_challenge(self, public_key: str) -> dict:
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
            requests.RequestException: If the API request fails.
        """
        logger.info("📝 Creating authentication challenge...")

        response = requests.post(f"{self.api_base_url}/auth/", json={"encryption_key": public_key})

        if response.status_code != 200:
            logger.error("❌ Error creating challenge: %s", response.status_code)
            logger.debug(response.json())

            if "No project found" in str(response.json()):
                logger.warning("\n⚠️  The public key from your ANY_LLM_KEY doesn't match any project.")
                logger.warning("Solution: Go to your project page and generate a new API key.")
            sys.exit(1)

        logger.info("✅ Challenge created")
        return response.json()

    def solve_challenge(self, encrypted_challenge: str, private_key: object) -> uuid.UUID:
        """Decrypt the server's challenge to prove key possession.

        Decrypts the server's encrypted challenge using the sealed box construction.
        The decrypted UUID proves possession of the private key and is used for
        subsequent authenticated requests.

        Args:
            encrypted_challenge: Base64-encoded sealed box containing the challenge UUID.
            private_key: User's X25519 private key (nacl.public.PrivateKey).

        Returns:
            uuid.UUID: The decrypted challenge UUID.

        Raises:
            ValueError: If decryption fails or UUID format is invalid.
            nacl.exceptions.CryptoError: If authentication tag verification fails.
        """
        logger.info("🔐 Decrypting challenge...")

        decrypted_uuid_str = decrypt_data(encrypted_challenge, private_key)
        solved_challenge = uuid.UUID(decrypted_uuid_str)

        logger.info("✅ Challenge solved: %s", solved_challenge)
        return solved_challenge

    def fetch_provider_key(
        self,
        provider: str,
        public_key: str,
        solved_challenge: uuid.UUID,
    ) -> dict:
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
            requests.RequestException: If the API request fails.
        """
        logger.info("🔑 Fetching provider key for %s...", provider)

        response = requests.get(
            f"{self.api_base_url}/provider-keys/{provider}",
            headers={
                "encryption-key": public_key,
                "AnyLLM-Challenge-Response": str(solved_challenge),
            },
        )
        if response.status_code != 200:
            logger.error("❌ Error fetching provider key: %s", response.status_code)
            logger.debug(response.json())
            sys.exit(1)

        data = response.json()
        logger.info("✅ Provider key fetched")
        return data

    def decrypt_provider_key_value(self, encrypted_key: str, private_key: object) -> str:
        """Decrypt the provider's API key to plaintext.

        Decrypts the provider's API key (e.g., OpenAI API key) using the sealed box
        construction. This reveals the plaintext API key that can be used to
        authenticate with the provider's services.

        Args:
            encrypted_key: Base64-encoded sealed box containing the provider API key.
            private_key: User's X25519 private key (nacl.public.PrivateKey).

        Returns:
            str: The decrypted provider API key (plaintext).

        Raises:
            ValueError: If decryption fails.
            nacl.exceptions.CryptoError: If authentication tag verification fails.

        Security Note:
            The decrypted API key should be handled carefully and never logged or
            transmitted over insecure channels.
        """
        logger.info("🔓 Decrypting provider API key...")

        decrypted_key = decrypt_data(encrypted_key, private_key)
        logger.info("✅ Decrypted successfully!")
        return decrypted_key
