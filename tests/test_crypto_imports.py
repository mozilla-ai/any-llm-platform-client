"""Tests for crypto module import error handling."""

import sys
from unittest.mock import patch

import pytest


def test_missing_pynacl_import_error():
    """Test that missing PyNaCl raises informative ImportError."""
    # Remove nacl from sys.modules if present
    nacl_modules = [key for key in sys.modules if key.startswith("nacl")]
    original_modules = {key: sys.modules.pop(key) for key in nacl_modules}

    try:
        # Mock the import to raise ImportError
        with (
            patch.dict("sys.modules", {"nacl.bindings": None, "nacl.public": None}),
            pytest.raises(ImportError, match="Missing required PyNaCl package"),
        ):
            # Force reload of crypto module
            if "any_llm_platform_client.crypto" in sys.modules:
                del sys.modules["any_llm_platform_client.crypto"]
            import any_llm_platform_client.crypto  # noqa: F401
    finally:
        # Restore original modules
        sys.modules.update(original_modules)
        # Force reload to restore proper state
        if "any_llm_platform_client.crypto" in sys.modules:
            del sys.modules["any_llm_platform_client.crypto"]
        import any_llm_platform_client.crypto  # noqa: F401


def test_pynacl_import_success():
    """Test that PyNaCl import works when available."""
    # This should not raise any errors
    import nacl.bindings  # noqa: F401
    import nacl.public  # noqa: F401

    from any_llm_platform_client.crypto import decrypt_data, encrypt_data  # noqa: F401

    # If we got here, imports worked
    assert True
