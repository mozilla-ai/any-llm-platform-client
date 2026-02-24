"""Custom exceptions for the any_llm_platform_client package.

This module defines specific exceptions that can be raised during the authentication
and key retrieval process with the ANY LLM platform.
"""


class ChallengeCreationError(Exception):
    """Raised when authentication challenge creation fails.

    This exception is raised when the client cannot create a challenge with the
    ANY LLM platform, typically due to:
    - Invalid or unrecognized public key
    - No project found matching the provided credentials
    - Network or server errors during challenge creation

    The exception message will contain details about the specific failure.
    """


class ProviderKeyFetchError(Exception):
    """Raised when fetching a provider API key fails.

    This exception is raised when the client successfully authenticates but
    cannot retrieve the requested provider's API key, typically due to:
    - Invalid provider name
    - Missing or expired credentials
    - Network or server errors during key retrieval
    - Insufficient permissions for the requested provider

    The exception message will contain details about the specific failure,
    including the HTTP status code received from the server.
    """
