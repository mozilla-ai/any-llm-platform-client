"""Unit tests for custom exceptions."""

import pytest

from any_llm_platform_client.exceptions import ChallengeCreationError, ProviderKeyFetchError


class TestChallengeCreationError:
    """Tests for ChallengeCreationError exception."""

    def test_raise_with_message(self):
        """Test raising exception with message."""
        with pytest.raises(ChallengeCreationError, match="Test error"):
            raise ChallengeCreationError("Test error")

    def test_exception_is_exception_subclass(self):
        """Test that ChallengeCreationError is an Exception."""
        assert issubclass(ChallengeCreationError, Exception)

    def test_exception_message_preserved(self):
        """Test that exception message is preserved."""
        error_msg = "Authentication failed with status 401"
        try:
            raise ChallengeCreationError(error_msg)
        except ChallengeCreationError as e:
            assert str(e) == error_msg

    def test_exception_with_complex_message(self):
        """Test exception with complex error message."""
        error_msg = "Failed to create challenge (status: 404, detail: No project found)"
        with pytest.raises(ChallengeCreationError, match="No project found"):
            raise ChallengeCreationError(error_msg)


class TestProviderKeyFetchError:
    """Tests for ProviderKeyFetchError exception."""

    def test_raise_with_message(self):
        """Test raising exception with message."""
        with pytest.raises(ProviderKeyFetchError, match="Test error"):
            raise ProviderKeyFetchError("Test error")

    def test_exception_is_exception_subclass(self):
        """Test that ProviderKeyFetchError is an Exception."""
        assert issubclass(ProviderKeyFetchError, Exception)

    def test_exception_message_preserved(self):
        """Test that exception message is preserved."""
        error_msg = "Failed to fetch provider key for openai"
        try:
            raise ProviderKeyFetchError(error_msg)
        except ProviderKeyFetchError as e:
            assert str(e) == error_msg

    def test_exception_with_status_code(self):
        """Test exception with status code in message."""
        error_msg = "Failed to fetch provider key (status: 403, detail: Insufficient permissions)"
        with pytest.raises(ProviderKeyFetchError, match="status: 403"):
            raise ProviderKeyFetchError(error_msg)


class TestExceptionInheritance:
    """Tests for exception inheritance and catching."""

    def test_catch_as_base_exception(self):
        """Test that custom exceptions can be caught as base Exception."""
        try:
            raise ChallengeCreationError("Test")
        except Exception as e:
            assert isinstance(e, ChallengeCreationError)

    def test_different_exceptions_are_distinct(self):
        """Test that the two custom exceptions are distinct types."""
        challenge_error = ChallengeCreationError("Challenge error")
        key_error = ProviderKeyFetchError("Key error")

        assert type(challenge_error) is not type(key_error)
        assert isinstance(challenge_error, ChallengeCreationError)
        assert isinstance(key_error, ProviderKeyFetchError)
        assert not isinstance(challenge_error, ProviderKeyFetchError)
        assert not isinstance(key_error, ChallengeCreationError)
