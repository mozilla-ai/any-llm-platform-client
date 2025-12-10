"""Tests for the any_api_decrypter package."""

import pytest


def test_import():
    """Test that the package can be imported."""
    import any_api_decrypter

    # Version is provided by setuptools_scm during development or package metadata when installed.
    assert hasattr(any_api_decrypter, "__version__")
    assert isinstance(any_api_decrypter.__version__, str)
    assert len(any_api_decrypter.__version__) > 0


def test_parse_any_llm_key():
    """Test parsing a valid ANY_LLM_KEY."""
    from any_api_decrypter import parse_any_llm_key

    key = "ANY.v1.12345678.abcdef01-YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3OA=="
    components = parse_any_llm_key(key)

    assert components.key_id == "12345678"
    assert components.public_key_fingerprint == "abcdef01"
    assert components.base64_encoded_private_key == "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3OA=="


def test_parse_any_llm_key_invalid_format():
    """Test that invalid format raises ValueError."""
    from any_api_decrypter import parse_any_llm_key

    with pytest.raises(ValueError, match="Invalid ANY_LLM_KEY format"):
        parse_any_llm_key("invalid-key-format")


def test_parse_any_llm_key_missing_version():
    """Test that missing version raises ValueError."""
    from any_api_decrypter import parse_any_llm_key

    with pytest.raises(ValueError, match="Invalid ANY_LLM_KEY format"):
        parse_any_llm_key("ANY.v2.12345678.abcdef01-YWJj")
