"""API client for communicating with the ANY LLM backend."""

import contextlib
import logging
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

import httpx
import nacl.public

from .client_management import ManagementMixin
from .crypto import decrypt_data, extract_public_key, load_private_key, parse_any_llm_key
from .exceptions import ChallengeCreationError, ProviderKeyFetchError

logger = logging.getLogger(__name__)

# Token expiry configuration
# JWT tokens last 24 hours, but we refresh 1 hour early to avoid expiry during operations
TOKEN_EXPIRY_SAFETY_MARGIN_HOURS = 23


@dataclass
class DecryptedProviderKey:
    """Container for decrypted provider key and metadata.

    Attributes:
        api_key: The decrypted API key for the provider
        provider_key_id: Unique identifier for the provider key
        project_id: Unique identifier for the project
        provider: Provider name (e.g., "openai", "anthropic")
        created_at: Timestamp when the provider key was created
        updated_at: Timestamp when the provider key was last updated (optional)
    """

    api_key: str
    provider_key_id: uuid.UUID
    project_id: uuid.UUID
    provider: str
    created_at: datetime
    updated_at: datetime | None = None


@dataclass
class KeyRotationResult:
    """Result of rotating a single provider key.

    Attributes:
        provider_key_id: Unique identifier for the provider key
        provider: Provider name (e.g., "openai", "anthropic")
        status: Status of the rotation: "migrated", "skipped", "archived", "failed"
        error: Optional error message if status is "failed" or "archived"
    """

    provider_key_id: str
    provider: str
    status: str
    error: str | None = None


@dataclass
class KeyRotationSummary:
    """Summary of key rotation operation.

    Attributes:
        total: Total number of provider keys processed
        migrated: Number of keys successfully migrated
        skipped: Number of keys skipped (e.g., local providers with empty keys)
        archived: Number of keys archived due to decryption failure
        failed: Number of keys that failed to update via API
        results: List of individual rotation results for each provider key
    """

    total: int
    migrated: int
    skipped: int
    archived: int
    failed: int
    results: list[KeyRotationResult]


def _handle_challenge_error(response: httpx.Response) -> None:
    """Handle error response from challenge creation."""
    logger.error("Error creating challenge: %s", response.status_code)
    try:
        response_json = response.json()
        logger.debug(response_json)
        if "No project found" in str(response_json):
            logger.warning("\nThe public key from your ANY_LLM_KEY doesn't match any project.")
            logger.warning("Solution: Go to your project page and generate a new API key.")
            raise ChallengeCreationError("No project found for the provided public key")
    except ValueError:
        pass
    raise ChallengeCreationError(f"Failed to create challenge (status: {response.status_code})")


def _handle_provider_key_error(response: httpx.Response) -> None:
    """Handle error response from provider key fetch."""
    logger.error("Error fetching provider key: %s", response.status_code)
    detail = None
    try:
        response_json = response.json()
        detail = response_json.get("detail")
        logger.debug(response_json)
    except ValueError:
        logger.debug("Response content is not valid JSON")
    raise ProviderKeyFetchError(f"Failed to fetch provider key (status: {response.status_code}, detail: {detail})")


class AnyLLMPlatformClient(ManagementMixin):
    """Client for communicating with the ANY LLM backend.

    This class encapsulates the any llm platfrom url and provides methods for the
    challenge-response flow and provider key retrieval.

    Both synchronous and asynchronous methods are provided:
    - Sync: create_challenge, fetch_provider_key
    - Async: acreate_challenge, afetch_provider_key

    Also includes management methods via ManagementMixin for projects, providers, budgets, and clients.
    """

    def __init__(self, any_llm_platform_url: str | None = None, client_name: str | None = None) -> None:
        """Initialize the client with an optional platform URL.

        Args:
            any_llm_platform_url: Base URL for the ANY LLM platform API.
                Defaults to "http://localhost:8000/api/v1" if not provided.
            client_name: Optional client name to identify this client to the platform.
                Used for budget enforcement and usage tracking.
        """
        self.any_llm_platform_url = any_llm_platform_url or "http://localhost:8000/api/v1"
        self.client_name = client_name
        self.access_token: str | None = None
        self.token_expires_at: datetime | None = None

    def create_challenge(self, public_key: str) -> dict:
        """Create an authentication challenge using the provided public key.

        Args:
            public_key: Base64-encoded X25519 public key.

        Returns:
            Dictionary containing the encrypted challenge from the server.
        """
        logger.debug("📝 Creating authentication challenge...")
        start_time = time.perf_counter()

        with httpx.Client() as client:
            response = client.post(
                f"{self.any_llm_platform_url}/auth/",
                json={"encryption_key": public_key},
            )

        if response.status_code != 200:
            _handle_challenge_error(response)

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        logger.debug("✅ Challenge created (%.2fms)", elapsed_ms)
        return response.json()

    async def acreate_challenge(self, public_key: str) -> dict:
        """Asynchronously create an authentication challenge using the provided public key.

        Args:
            public_key: Base64-encoded X25519 public key.

        Returns:
            Dictionary containing the encrypted challenge from the server.
        """
        logger.debug("📝 Creating authentication challenge...")
        start_time = time.perf_counter()

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.any_llm_platform_url}/auth/",
                json={"encryption_key": public_key},
            )

        if response.status_code != 200:
            _handle_challenge_error(response)

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        logger.debug("✅ Challenge created (%.2fms)", elapsed_ms)
        return response.json()

    def solve_challenge(self, encrypted_challenge: str, private_key: nacl.public.PrivateKey) -> uuid.UUID:
        """Decrypt and solve the authentication challenge.

        Args:
            encrypted_challenge: Base64-encoded encrypted challenge from the server.
            private_key: X25519 private key for decryption.

        Returns:
            UUID representing the solved challenge.
        """
        logger.debug("🔐 Decrypting challenge...")
        start_time = time.perf_counter()

        decrypted_uuid_str = decrypt_data(encrypted_challenge, private_key)
        solved_challenge = uuid.UUID(decrypted_uuid_str)

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        logger.debug("✅ Challenge solved: %s (%.2fms)", solved_challenge, elapsed_ms)
        return solved_challenge

    def request_access_token(self, solved_challenge: uuid.UUID) -> str:
        """Request an access token by submitting the solved challenge.

        Args:
            solved_challenge: Solved challenge UUID.

        Returns:
            JWT access token string.

        Raises:
            ChallengeCreationError: If token request fails.
        """
        logger.debug("🎫 Requesting access token...")
        start_time = time.perf_counter()

        with httpx.Client() as client:
            response = client.post(
                f"{self.any_llm_platform_url}/auth/token",
                json={"solved_challenge": str(solved_challenge)},
            )

        if response.status_code != 200:
            logger.error("❌ Error requesting access token: %s", response.status_code)
            with contextlib.suppress(ValueError):
                logger.debug(response.json())
            raise ChallengeCreationError(f"Failed to request access token (status: {response.status_code})")

        data = response.json()
        access_token = data["access_token"]

        # Store token and set expiration (24 hours minus 1 hour safety margin)
        self.access_token = access_token
        self.token_expires_at = datetime.now() + timedelta(hours=TOKEN_EXPIRY_SAFETY_MARGIN_HOURS)

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        logger.debug("✅ Access token obtained (%.2fms)", elapsed_ms)
        return access_token

    async def arequest_access_token(self, solved_challenge: uuid.UUID) -> str:
        """Asynchronously request an access token by submitting the solved challenge.

        Args:
            solved_challenge: Solved challenge UUID.

        Returns:
            JWT access token string.

        Raises:
            ChallengeCreationError: If token request fails.
        """
        logger.debug("🎫 Requesting access token...")
        start_time = time.perf_counter()

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.any_llm_platform_url}/auth/token",
                json={"solved_challenge": str(solved_challenge)},
            )

        if response.status_code != 200:
            logger.error("❌ Error requesting access token: %s", response.status_code)
            with contextlib.suppress(ValueError):
                logger.debug(response.json())
            raise ChallengeCreationError(f"Failed to request access token (status: {response.status_code})")

        data = response.json()
        access_token = data["access_token"]

        # Store token and set expiration (24 hours minus 1 hour safety margin)
        self.access_token = access_token
        self.token_expires_at = datetime.now() + timedelta(hours=TOKEN_EXPIRY_SAFETY_MARGIN_HOURS)

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        logger.debug("✅ Access token obtained (%.2fms)", elapsed_ms)
        return access_token

    def refresh_access_token(self, any_llm_key: str) -> str:
        """Refresh the access token by requesting a new one.

        This method forces a token refresh regardless of expiration status.
        Useful for manual token management or when you need to invalidate
        the current token and get a fresh one.

        Args:
            any_llm_key: The ANY_LLM_KEY string for authentication.

        Returns:
            New JWT access token string.

        Raises:
            ValueError: If the ANY_LLM_KEY format is invalid.
            ChallengeCreationError: If authentication fails.

        Example:
            >>> client = AnyLLMPlatformClient()
            >>> # Force refresh the token
            >>> new_token = client.refresh_access_token(any_llm_key)
            >>> # Use the new token
            >>> client.fetch_provider_key("openai", new_token)
        """
        logger.debug("🔄 Refreshing access token...")
        start_time = time.perf_counter()

        # Parse the ANY_LLM_KEY
        key_components = parse_any_llm_key(any_llm_key)

        # Load the private key
        private_key = load_private_key(key_components.base64_encoded_private_key)

        # Extract the public key from the private key
        public_key = extract_public_key(private_key)

        # Create and solve the challenge
        challenge_data = self.create_challenge(public_key)
        solved_challenge = self.solve_challenge(challenge_data["encrypted_challenge"], private_key)

        # Request access token
        token = self.request_access_token(solved_challenge)

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        logger.debug("✅ Token refresh complete (total: %.2fms)", elapsed_ms)
        return token

    async def arefresh_access_token(self, any_llm_key: str) -> str:
        """Asynchronously refresh the access token by requesting a new one.

        This method forces a token refresh regardless of expiration status.
        Useful for manual token management or when you need to invalidate
        the current token and get a fresh one.

        Args:
            any_llm_key: The ANY_LLM_KEY string for authentication.

        Returns:
            New JWT access token string.

        Raises:
            ValueError: If the ANY_LLM_KEY format is invalid.
            ChallengeCreationError: If authentication fails.

        Example:
            >>> client = AnyLLMPlatformClient()
            >>> # Force refresh the token
            >>> new_token = await client.arefresh_access_token(any_llm_key)
            >>> # Use the new token
            >>> await client.afetch_provider_key("openai", new_token)
        """
        logger.debug("🔄 Refreshing access token...")
        start_time = time.perf_counter()

        # Parse the ANY_LLM_KEY
        key_components = parse_any_llm_key(any_llm_key)

        # Load the private key
        private_key = load_private_key(key_components.base64_encoded_private_key)

        # Extract the public key from the private key
        public_key = extract_public_key(private_key)

        # Create and solve the challenge
        challenge_data = await self.acreate_challenge(public_key)
        solved_challenge = self.solve_challenge(challenge_data["encrypted_challenge"], private_key)

        # Request access token
        token = await self.arequest_access_token(solved_challenge)

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        logger.debug("✅ Token refresh complete (total: %.2fms)", elapsed_ms)
        return token

    def _ensure_valid_token(self, any_llm_key: str) -> str:
        """Ensure a valid access token exists, refreshing if necessary.

        Args:
            any_llm_key: The ANY_LLM_KEY string for authentication.

        Returns:
            Valid access token string.

        Raises:
            ValueError: If the ANY_LLM_KEY format is invalid.
            ChallengeCreationError: If authentication fails.
        """
        now = datetime.now()

        # Request new token if missing or expired
        if not self.access_token or not self.token_expires_at or now >= self.token_expires_at:
            logger.debug("Token missing or expired, requesting new token...")
            self.refresh_access_token(any_llm_key)

        return self.access_token  # type: ignore

    async def _aensure_valid_token(self, any_llm_key: str) -> str:
        """Asynchronously ensure a valid access token exists, refreshing if necessary.

        Args:
            any_llm_key: The ANY_LLM_KEY string for authentication.

        Returns:
            Valid access token string.

        Raises:
            ValueError: If the ANY_LLM_KEY format is invalid.
            ChallengeCreationError: If authentication fails.
        """
        now = datetime.now()

        # Request new token if missing or expired
        if not self.access_token or not self.token_expires_at or now >= self.token_expires_at:
            logger.debug("Token missing or expired, requesting new token...")
            await self.arefresh_access_token(any_llm_key)

        return self.access_token  # type: ignore

    def fetch_provider_key(self, provider: str, access_token: str) -> dict:
        """Fetch the encrypted provider API key from the server using Bearer token authentication.

        Args:
            provider: Provider name (e.g., "openai", "anthropic").
            access_token: JWT access token for authentication.

        Returns:
            Dictionary containing the encrypted provider key and metadata.
        """
        logger.debug("🔑 Fetching provider key for %s...", provider)
        start_time = time.perf_counter()

        headers = {"Authorization": f"Bearer {access_token}"}
        if self.client_name:
            headers["AnyLLM-Client-Name"] = self.client_name

        with httpx.Client() as client:
            response = client.get(
                f"{self.any_llm_platform_url}/provider-keys/{provider}",
                headers=headers,
            )

        if response.status_code != 200:
            _handle_provider_key_error(response)

        data = response.json()
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        logger.debug("✅ Provider key fetched (%.2fms)", elapsed_ms)
        return data

    async def afetch_provider_key(self, provider: str, access_token: str) -> dict:
        """Asynchronously fetch the encrypted provider API key from the server using Bearer token authentication.

        Args:
            provider: Provider name (e.g., "openai", "anthropic").
            access_token: JWT access token for authentication.

        Returns:
            Dictionary containing the encrypted provider key and metadata.
        """
        logger.debug("🔑 Fetching provider key for %s...", provider)
        start_time = time.perf_counter()

        headers = {"Authorization": f"Bearer {access_token}"}
        if self.client_name:
            headers["AnyLLM-Client-Name"] = self.client_name

        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.any_llm_platform_url}/provider-keys/{provider}",
                headers=headers,
            )

        if response.status_code != 200:
            _handle_provider_key_error(response)

        data = response.json()
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        logger.debug("✅ Provider key fetched (%.2fms)", elapsed_ms)
        return data

    def decrypt_provider_key_value(self, encrypted_key: str, private_key: nacl.public.PrivateKey) -> str:
        """Decrypt the provider API key.

        Args:
            encrypted_key: Base64-encoded encrypted provider API key.
            private_key: X25519 private key for decryption.

        Returns:
            The decrypted provider API key as a string.
        """
        logger.debug("🔓 Decrypting provider API key...")
        start_time = time.perf_counter()

        decrypted_key = decrypt_data(encrypted_key, private_key)

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        logger.debug("✅ Decrypted successfully! (%.2fms)", elapsed_ms)
        return decrypted_key

    def get_public_key(self, any_llm_key: str) -> str:
        """Extract the public key from an ANY_LLM_KEY.

        This convenience method handles:
        1. Parse the ANY_LLM_KEY
        2. Load the private key
        3. Extract and return the public key

        Args:
            any_llm_key: The ANY_LLM_KEY string (format: ANY.v1.<kid>.<fingerprint>-<base64_key>)

        Returns:
            Base64-encoded public key string

        Raises:
            ValueError: If the ANY_LLM_KEY format is invalid.

        Example:
            >>> client = AnyLLMPlatformClient()
            >>> public_key = client.get_public_key(
            ...     any_llm_key="ANY.v1.12345678.abcdef01-..."
            ... )
            >>> print(public_key)
        """
        # Parse the ANY_LLM_KEY
        key_components = parse_any_llm_key(any_llm_key)

        # Load the private key
        private_key = load_private_key(key_components.base64_encoded_private_key)

        # Extract and return the public key
        public_key = extract_public_key(private_key)

        return public_key

    def get_solved_challenge(self, any_llm_key: str) -> uuid.UUID:
        """Get a solved authentication challenge from an ANY_LLM_KEY.

        This convenience method handles:
        1. Parse the ANY_LLM_KEY
        2. Extract public key from private key
        3. Create authentication challenge
        4. Solve and return the challenge

        Args:
            any_llm_key: The ANY_LLM_KEY string (format: ANY.v1.<kid>.<fingerprint>-<base64_key>)

        Returns:
            UUID representing the solved challenge

        Raises:
            ValueError: If the ANY_LLM_KEY format is invalid.
            ChallengeCreationError: If challenge creation fails.

        Example:
            >>> client = AnyLLMPlatformClient()
            >>> solved_challenge = client.get_solved_challenge(
            ...     any_llm_key="ANY.v1.12345678.abcdef01-..."
            ... )
            >>> print(solved_challenge)
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

        return solved_challenge

    def get_decrypted_provider_key(self, any_llm_key: str, provider: str) -> DecryptedProviderKey:
        """Get a decrypted provider API key using the complete authentication flow.

        This is a convenience method that handles the entire flow with token-based auth:
        1. Parse the ANY_LLM_KEY
        2. Ensure valid access token (request if needed)
        3. Fetch the encrypted provider key using Bearer token
        4. Decrypt and return the provider key with metadata

        Args:
            any_llm_key: The ANY_LLM_KEY string (format: ANY.v1.<kid>.<fingerprint>-<base64_key>)
            provider: Provider name (e.g., "openai", "anthropic", "google")

        Returns:
            DecryptedProviderKey object containing the decrypted API key and metadata

        Raises:
            ValueError: If the ANY_LLM_KEY format is invalid.
            ChallengeCreationError: If challenge creation fails.
            ProviderKeyFetchError: If fetching the provider key fails.

        Example:
            >>> client = AnyLLMPlatformClient()
            >>> result = client.get_decrypted_provider_key(
            ...     any_llm_key="ANY.v1.12345678.abcdef01-...",
            ...     provider="openai"
            ... )
            >>> print(result.api_key)
            >>> print(result.provider_key_id)
        """
        # Ensure we have a valid access token
        access_token = self._ensure_valid_token(any_llm_key)

        # Load private key for decryption
        key_components = parse_any_llm_key(any_llm_key)
        private_key = load_private_key(key_components.base64_encoded_private_key)

        # Fetch the encrypted provider key using Bearer token
        provider_key_data = self.fetch_provider_key(provider, access_token=access_token)

        # Decrypt the provider key
        decrypted_key = self.decrypt_provider_key_value(provider_key_data["encrypted_key"], private_key)

        # Return structured data with metadata
        return DecryptedProviderKey(
            api_key=decrypted_key,
            provider_key_id=uuid.UUID(provider_key_data["id"]),
            project_id=uuid.UUID(provider_key_data["project_id"]),
            provider=provider_key_data["provider"],
            created_at=datetime.fromisoformat(provider_key_data["created_at"]),
            updated_at=(
                datetime.fromisoformat(provider_key_data["updated_at"]) if provider_key_data.get("updated_at") else None
            ),
        )

    async def aget_solved_challenge(self, any_llm_key: str) -> uuid.UUID:
        """Asynchronously get a solved authentication challenge from an ANY_LLM_KEY.

        This convenience method handles:
        1. Parse the ANY_LLM_KEY
        2. Extract public key from private key
        3. Create authentication challenge (async)
        4. Solve and return the challenge

        Args:
            any_llm_key: The ANY_LLM_KEY string (format: ANY.v1.<kid>.<fingerprint>-<base64_key>)

        Returns:
            UUID representing the solved challenge

        Raises:
            ValueError: If the ANY_LLM_KEY format is invalid.
            ChallengeCreationError: If challenge creation fails.

        Example:
            >>> client = AnyLLMPlatformClient()
            >>> solved_challenge = await client.aget_solved_challenge(
            ...     any_llm_key="ANY.v1.12345678.abcdef01-..."
            ... )
            >>> print(solved_challenge)
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

        return solved_challenge

    async def aget_decrypted_provider_key(self, any_llm_key: str, provider: str) -> DecryptedProviderKey:
        """Asynchronously get a decrypted provider API key using the complete authentication flow.

        This is a convenience method that handles the entire flow asynchronously with token-based auth:
        1. Parse the ANY_LLM_KEY
        2. Ensure valid access token (request if needed)
        3. Fetch the encrypted provider key using Bearer token (async)
        4. Decrypt and return the provider key with metadata

        Args:
            any_llm_key: The ANY_LLM_KEY string (format: ANY.v1.<kid>.<fingerprint>-<base64_key>)
            provider: Provider name (e.g., "openai", "anthropic", "google")

        Returns:
            DecryptedProviderKey object containing the decrypted API key and metadata

        Raises:
            ValueError: If the ANY_LLM_KEY format is invalid.
            ChallengeCreationError: If challenge creation fails.
            ProviderKeyFetchError: If fetching the provider key fails.

        Example:
            >>> client = AnyLLMPlatformClient()
            >>> result = await client.aget_decrypted_provider_key(
            ...     any_llm_key="ANY.v1.12345678.abcdef01-...",
            ...     provider="openai"
            ... )
            >>> print(result.api_key)
            >>> print(result.provider_key_id)
        """
        # Ensure we have a valid access token
        access_token = await self._aensure_valid_token(any_llm_key)

        # Parse the ANY_LLM_KEY and load private key for decryption
        key_components = parse_any_llm_key(any_llm_key)
        private_key = load_private_key(key_components.base64_encoded_private_key)

        # Fetch the encrypted provider key using Bearer token
        provider_key_data = await self.afetch_provider_key(provider, access_token=access_token)

        # Decrypt the provider key
        decrypted_key = self.decrypt_provider_key_value(provider_key_data["encrypted_key"], private_key)

        # Return structured data with metadata
        return DecryptedProviderKey(
            api_key=decrypted_key,
            provider_key_id=uuid.UUID(provider_key_data["id"]),
            project_id=uuid.UUID(provider_key_data["project_id"]),
            provider=provider_key_data["provider"],
            created_at=datetime.fromisoformat(provider_key_data["created_at"]),
            updated_at=(
                datetime.fromisoformat(provider_key_data["updated_at"]) if provider_key_data.get("updated_at") else None
            ),
        )
