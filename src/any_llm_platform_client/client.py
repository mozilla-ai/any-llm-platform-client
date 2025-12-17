"""API client for communicating with the ANY LLM backend."""

import logging
import uuid

import httpx

from .crypto import decrypt_data, extract_public_key, load_private_key, parse_any_llm_key
from .exceptions import ChallengeCreationError, ProviderKeyFetchError

logger = logging.getLogger(__name__)


def _handle_challenge_error(response: httpx.Response) -> None:
    """Handle error response from challenge creation."""
    logger.error("❌ Error creating challenge: %s", response.status_code)
    try:
        response_json = response.json()
        logger.debug(response_json)
        if "No project found" in str(response_json):
            logger.warning("\n⚠️  The public key from your ANY_LLM_KEY doesn't match any project.")
            logger.warning("Solution: Go to your project page and generate a new API key.")
            raise ChallengeCreationError("No project found for the provided public key")
    except ValueError:
        pass
    raise ChallengeCreationError(f"Failed to create challenge (status: {response.status_code})")


def _handle_provider_key_error(response: httpx.Response) -> None:
    """Handle error response from provider key fetch."""
    logger.error("❌ Error fetching provider key: %s", response.status_code)
    try:
        logger.debug(response.json())
    except ValueError:
        logger.debug("Response content is not valid JSON")
    raise ProviderKeyFetchError(f"Failed to fetch provider key (status: {response.status_code})")


class AnyLLMPlatformClient:
    """Client for communicating with the ANY LLM backend.

    This class encapsulates the any llm platfrom url and provides methods for the
    challenge-response flow and provider key retrieval.

    Both synchronous and asynchronous methods are provided:
    - Sync: create_challenge, fetch_provider_key
    - Async: acreate_challenge, afetch_provider_key
    """

    def __init__(self, any_llm_platform_url: str | None = None) -> None:
        """Initialize the client with an optional platform URL.

        Args:
            any_llm_platform_url: Base URL for the ANY LLM platform API.
                Defaults to "http://localhost:8000/api/v1" if not provided.
        """
        self.any_llm_platform_url = any_llm_platform_url or "http://localhost:8000/api/v1"

    def create_challenge(self, public_key: str) -> dict:
        """Create an authentication challenge using the provided public key.

        Args:
            public_key: Base64-encoded X25519 public key.

        Returns:
            Dictionary containing the encrypted challenge from the server.
        """
        logger.info("📝 Creating authentication challenge...")

        with httpx.Client() as client:
            response = client.post(
                f"{self.any_llm_platform_url}/auth/",
                json={"encryption_key": public_key},
            )

        if response.status_code != 200:
            _handle_challenge_error(response)

        logger.info("✅ Challenge created")
        return response.json()

    async def acreate_challenge(self, public_key: str) -> dict:
        """Asynchronously create an authentication challenge using the provided public key.

        Args:
            public_key: Base64-encoded X25519 public key.

        Returns:
            Dictionary containing the encrypted challenge from the server.
        """
        logger.info("📝 Creating authentication challenge...")

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.any_llm_platform_url}/auth/",
                json={"encryption_key": public_key},
            )

        if response.status_code != 200:
            _handle_challenge_error(response)

        logger.info("✅ Challenge created")
        return response.json()

    def solve_challenge(self, encrypted_challenge: str, private_key: object) -> uuid.UUID:
        """Decrypt and solve the authentication challenge.

        Args:
            encrypted_challenge: Base64-encoded encrypted challenge from the server.
            private_key: X25519 private key for decryption.

        Returns:
            UUID representing the solved challenge.
        """
        logger.info("🔐 Decrypting challenge...")

        decrypted_uuid_str = decrypt_data(encrypted_challenge, private_key)
        solved_challenge = uuid.UUID(decrypted_uuid_str)

        logger.info("✅ Challenge solved: %s", solved_challenge)
        return solved_challenge

    def fetch_provider_key(self, provider: str, public_key: str, solved_challenge: uuid.UUID) -> dict:
        """Fetch the encrypted provider API key from the server.

        Args:
            provider: Provider name (e.g., "openai", "anthropic").
            public_key: Base64-encoded X25519 public key.
            solved_challenge: Solved challenge UUID for authentication.

        Returns:
            Dictionary containing the encrypted provider key and metadata.
        """
        logger.info("🔑 Fetching provider key for %s...", provider)

        with httpx.Client() as client:
            response = client.get(
                f"{self.any_llm_platform_url}/provider-keys/{provider}",
                headers={
                    "encryption-key": public_key,
                    "AnyLLM-Challenge-Response": str(solved_challenge),
                },
            )

        if response.status_code != 200:
            _handle_provider_key_error(response)

        data = response.json()
        logger.info("✅ Provider key fetched")
        return data

    async def afetch_provider_key(self, provider: str, public_key: str, solved_challenge: uuid.UUID) -> dict:
        """Asynchronously fetch the encrypted provider API key from the server.

        Args:
            provider: Provider name (e.g., "openai", "anthropic").
            public_key: Base64-encoded X25519 public key.
            solved_challenge: Solved challenge UUID for authentication.

        Returns:
            Dictionary containing the encrypted provider key and metadata.
        """
        logger.info("🔑 Fetching provider key for %s...", provider)

        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.any_llm_platform_url}/provider-keys/{provider}",
                headers={
                    "encryption-key": public_key,
                    "AnyLLM-Challenge-Response": str(solved_challenge),
                },
            )

        if response.status_code != 200:
            _handle_provider_key_error(response)

        data = response.json()
        logger.info("✅ Provider key fetched")
        return data

    def decrypt_provider_key_value(self, encrypted_key: str, private_key: object) -> str:
        """Decrypt the provider API key.

        Args:
            encrypted_key: Base64-encoded encrypted provider API key.
            private_key: X25519 private key for decryption.

        Returns:
            The decrypted provider API key as a string.
        """
        logger.info("🔓 Decrypting provider API key...")

        decrypted_key = decrypt_data(encrypted_key, private_key)
        logger.info("✅ Decrypted successfully!")
        return decrypted_key

    def get_decrypted_provider_key(self, any_llm_key: str, provider: str) -> str:
        """Get a decrypted provider API key using the complete authentication flow.

        This is a convenience method that handles the entire flow:
        1. Parse the ANY_LLM_KEY
        2. Extract public key from private key
        3. Create authentication challenge
        4. Solve the challenge
        5. Fetch the encrypted provider key
        6. Decrypt and return the provider key

        Args:
            any_llm_key: The ANY_LLM_KEY string (format: ANY.v1.<kid>.<fingerprint>-<base64_key>)
            provider: Provider name (e.g., "openai", "anthropic", "google")

        Returns:
            The decrypted provider API key as a string.

        Raises:
            ValueError: If the ANY_LLM_KEY format is invalid.
            ChallengeCreationError: If challenge creation fails.
            ProviderKeyFetchError: If fetching the provider key fails.

        Example:
            >>> client = AnyLLMPlatformClient()
            >>> api_key = client.get_decrypted_provider_key(
            ...     any_llm_key="ANY.v1.12345678.abcdef01-...",
            ...     provider="openai"
            ... )
            >>> print(api_key)
        """
        # Parse the ANY_LLM_KEY
        key_components = parse_any_llm_key(any_llm_key)

        # Load the private key
        private_key = load_private_key(key_components.base64_encoded_private_key)

        # Extract the public key from the private key
        public_key = extract_public_key(private_key)

        # Create and solve the challenge
        challenge_data = self.create_challenge(public_key)
        solved_challenge = self.solve_challenge(challenge_data["encrypted_challenge"], private_key)

        # Fetch the encrypted provider key
        provider_key_data = self.fetch_provider_key(provider, public_key, solved_challenge)

        # Decrypt and return the provider key
        decrypted_key = self.decrypt_provider_key_value(provider_key_data["encrypted_key"], private_key)

        return decrypted_key

    async def aget_decrypted_provider_key(self, any_llm_key: str, provider: str) -> str:
        """Asynchronously get a decrypted provider API key using the complete authentication flow.

        This is a convenience method that handles the entire flow asynchronously:
        1. Parse the ANY_LLM_KEY
        2. Extract public key from private key
        3. Create authentication challenge (async)
        4. Solve the challenge
        5. Fetch the encrypted provider key (async)
        6. Decrypt and return the provider key

        Args:
            any_llm_key: The ANY_LLM_KEY string (format: ANY.v1.<kid>.<fingerprint>-<base64_key>)
            provider: Provider name (e.g., "openai", "anthropic", "google")

        Returns:
            The decrypted provider API key as a string.

        Raises:
            ValueError: If the ANY_LLM_KEY format is invalid.
            ChallengeCreationError: If challenge creation fails.
            ProviderKeyFetchError: If fetching the provider key fails.

        Example:
            >>> client = AnyLLMPlatformClient()
            >>> api_key = await client.aget_decrypted_provider_key(
            ...     any_llm_key="ANY.v1.12345678.abcdef01-...",
            ...     provider="openai"
            ... )
            >>> print(api_key)
        """
        # Parse the ANY_LLM_KEY
        key_components = parse_any_llm_key(any_llm_key)

        # Load the private key
        private_key = load_private_key(key_components.base64_encoded_private_key)

        # Extract the public key from the private key
        public_key = extract_public_key(private_key)

        # Create and solve the challenge
        challenge_data = await self.acreate_challenge(public_key)
        solved_challenge = self.solve_challenge(challenge_data["encrypted_challenge"], private_key)

        # Fetch the encrypted provider key
        provider_key_data = await self.afetch_provider_key(provider, public_key, solved_challenge)

        # Decrypt and return the provider key
        decrypted_key = self.decrypt_provider_key_value(provider_key_data["encrypted_key"], private_key)

        return decrypted_key
