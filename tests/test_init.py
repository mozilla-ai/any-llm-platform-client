"""Tests for the __init__.py module exports."""

import pytest


def test_all_exports_available():
    """Test that all expected exports are available from the package."""
    import any_llm_platform_client

    # Check main classes
    assert hasattr(any_llm_platform_client, "AnyLLMPlatformClient")
    assert hasattr(any_llm_platform_client, "DecryptedProviderKey")

    # Check exceptions
    assert hasattr(any_llm_platform_client, "ChallengeCreationError")
    assert hasattr(any_llm_platform_client, "ProviderKeyFetchError")

    # Check crypto utilities (as documented in __all__)
    assert hasattr(any_llm_platform_client, "parse_any_llm_key")
    assert hasattr(any_llm_platform_client, "load_private_key")
    assert hasattr(any_llm_platform_client, "extract_public_key")
    assert hasattr(any_llm_platform_client, "decrypt_data")
    assert hasattr(any_llm_platform_client, "KeyComponents")


def test_client_import():
    """Test importing AnyLLMPlatformClient."""
    from any_llm_platform_client import AnyLLMPlatformClient

    # Should be able to instantiate
    client = AnyLLMPlatformClient()
    assert client.any_llm_platform_url == "http://localhost:8000/api/v1"


def test_decrypted_provider_key_import():
    """Test importing DecryptedProviderKey dataclass."""
    from any_llm_platform_client import DecryptedProviderKey

    # Should be a class
    assert isinstance(DecryptedProviderKey, type)


def test_exceptions_import():
    """Test importing exceptions."""
    from any_llm_platform_client import ChallengeCreationError, ProviderKeyFetchError

    # Should be exception classes
    assert issubclass(ChallengeCreationError, Exception)
    assert issubclass(ProviderKeyFetchError, Exception)


def test_crypto_functions_import():
    """Test importing crypto functions."""
    from any_llm_platform_client import (
        KeyComponents,
        decrypt_data,
        extract_public_key,
        load_private_key,
        parse_any_llm_key,
    )

    # Should be callable functions
    assert callable(parse_any_llm_key)
    assert callable(load_private_key)
    assert callable(extract_public_key)
    assert callable(decrypt_data)

    # KeyComponents should be a class
    assert isinstance(KeyComponents, type)


def test_version_import():
    """Test that __version__ is available."""
    from any_llm_platform_client import __version__

    # Should be a string
    assert isinstance(__version__, str)
    # Should follow semantic versioning pattern (at least x.y.z)
    parts = __version__.split(".")
    assert len(parts) >= 3


def test_all_attribute():
    """Test that __all__ is properly defined."""
    import any_llm_platform_client

    # __all__ should be a list
    assert hasattr(any_llm_platform_client, "__all__")
    assert isinstance(any_llm_platform_client.__all__, list)

    # All items in __all__ should be strings
    for item in any_llm_platform_client.__all__:
        assert isinstance(item, str)
        # All items should be accessible
        assert hasattr(any_llm_platform_client, item)


def test_package_metadata():
    """Test package metadata is accessible."""
    import any_llm_platform_client

    # Should have standard package attributes
    assert hasattr(any_llm_platform_client, "__version__")
    assert hasattr(any_llm_platform_client, "__all__")


def test_imports_dont_fail():
    """Test that importing the package doesn't raise errors."""
    # This test verifies no import-time errors
    try:
        import any_llm_platform_client  # noqa: F401

        assert True
    except ImportError as e:
        pytest.fail(f"Import failed: {e}")
