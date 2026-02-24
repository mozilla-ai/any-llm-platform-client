"""Unit tests for CLI helper functions."""

import pytest

from any_llm_platform_client.cli import (
    _config_for_budget_period,
    _config_for_date_column,
    _config_for_description_column,
    _config_for_hidden_field,
    _config_for_id_column,
    _config_for_name_column,
    _config_for_standard_field,
    _format_date,
    _get_column_config,
    _is_list_response,
    _is_provider_key_data,
    _transform_dates_in_data,
    _transform_provider_key_data,
    format_output,
    handle_error,
)
from any_llm_platform_client.exceptions import ChallengeCreationError, ProviderKeyFetchError


class TestFormatDate:
    """Tests for _format_date function."""

    def test_format_valid_date(self):
        """Test formatting a valid ISO date."""
        result = _format_date("2026-02-24T14:37:32")
        assert result == "Feb 24, 2026"

    def test_format_date_with_z_timezone(self):
        """Test formatting a date with Z timezone."""
        result = _format_date("2026-02-24T14:37:32Z")
        assert result == "Feb 24, 2026"

    def test_format_date_none(self):
        """Test formatting None returns N/A."""
        result = _format_date(None)
        assert result == "N/A"

    def test_format_date_last_used_none(self):
        """Test formatting None for last_used field."""
        result = _format_date(None, "last_used_at")
        assert result == "Never used"

    def test_format_date_invalid(self):
        """Test formatting invalid date returns original string."""
        result = _format_date("invalid-date")
        assert result == "invalid-date"

    def test_format_date_empty_string(self):
        """Test formatting empty string."""
        result = _format_date("")
        assert result == "N/A"


class TestTransformDatesInData:
    """Tests for _transform_dates_in_data function."""

    def test_transform_dates_in_single_item(self):
        """Test transforming dates in a single item."""
        items = [
            {
                "id": "123",
                "name": "Test",
                "created_at": "2026-02-24T14:37:32",
                "updated_at": "2026-02-25T10:00:00",
            }
        ]
        result = _transform_dates_in_data(items)
        assert result[0]["id"] == "123"
        assert result[0]["created"] == "Feb 24, 2026"
        assert result[0]["updated"] == "Feb 25, 2026"
        assert "created_at" not in result[0]
        assert "updated_at" not in result[0]

    def test_transform_dates_preserves_id_order(self):
        """Test that id field is always first."""
        items = [{"name": "Test", "id": "123", "created_at": "2026-02-24T14:37:32"}]
        result = _transform_dates_in_data(items)
        keys = list(result[0].keys())
        assert keys[0] == "id"

    def test_transform_dates_empty_list(self):
        """Test transforming empty list."""
        result = _transform_dates_in_data([])
        assert result == []

    def test_transform_dates_no_date_fields(self):
        """Test transforming items with no date fields."""
        items = [{"id": "123", "name": "Test", "value": 42}]
        result = _transform_dates_in_data(items)
        assert result[0]["name"] == "Test"
        assert result[0]["value"] == 42


class TestTransformProviderKeyData:
    """Tests for _transform_provider_key_data function."""

    def test_transform_provider_key_basic(self):
        """Test transforming basic provider key data."""
        items = [
            {
                "id": "key-123",
                "provider": "openai",
                "is_archived": False,
                "created_at": "2026-02-24T14:37:32",
                "last_used_at": "2026-02-25T10:00:00",
            }
        ]
        result = _transform_provider_key_data(items)
        assert result[0]["id"] == "key-123"
        assert result[0]["provider"] == "openai"
        assert result[0]["archived"] == "No"
        assert result[0]["created"] == "Feb 24, 2026"
        assert result[0]["last_used"] == "Feb 25, 2026"

    def test_transform_provider_key_archived_via_archived_at(self):
        """Test that archived_at field determines archived status."""
        items = [
            {
                "id": "key-123",
                "provider": "openai",
                "archived_at": "2026-02-24T14:37:32",
                "created_at": "2026-02-24T14:37:32",
                "last_used_at": None,
            }
        ]
        result = _transform_provider_key_data(items)
        assert result[0]["archived"] == "Yes"

    def test_transform_provider_key_never_used(self):
        """Test provider key that was never used."""
        items = [
            {
                "id": "key-123",
                "provider": "anthropic",
                "is_archived": False,
                "created_at": "2026-02-24T14:37:32",
                "last_used_at": None,
            }
        ]
        result = _transform_provider_key_data(items)
        assert result[0]["last_used"] == "Never used"

    def test_transform_provider_key_with_budget_dict(self):
        """Test provider key with budget as dictionary."""
        items = [
            {
                "id": "key-123",
                "provider": "openai",
                "is_archived": False,
                "created_at": "2026-02-24T14:37:32",
                "last_used_at": None,
                "budget": {"spent": 12.50, "limit": 100.0},
            }
        ]
        result = _transform_provider_key_data(items)
        assert result[0]["budget"] == "$12.50 / $100.00"

    def test_transform_provider_key_with_budget_string(self):
        """Test provider key with budget as string."""
        items = [
            {
                "id": "key-123",
                "provider": "openai",
                "is_archived": False,
                "created_at": "2026-02-24T14:37:32",
                "last_used_at": None,
                "budget": "custom_value",
            }
        ]
        result = _transform_provider_key_data(items)
        assert result[0]["budget"] == "custom_value"

    def test_transform_provider_key_no_budget(self):
        """Test provider key without budget field."""
        items = [
            {
                "id": "key-123",
                "provider": "openai",
                "is_archived": False,
                "created_at": "2026-02-24T14:37:32",
                "last_used_at": None,
            }
        ]
        result = _transform_provider_key_data(items)
        assert result[0]["budget"] == "N/A"


class TestColumnConfiguration:
    """Tests for column configuration functions."""

    def test_config_for_name_column(self):
        """Test name column configuration."""
        config = _config_for_name_column()
        assert config["show"] is True
        assert config["no_wrap"] is True
        assert config["overflow"] == "ellipsis"
        assert config["max_width"] == 20

    def test_config_for_id_column_narrow(self):
        """Test ID column in narrow terminal."""
        config = _config_for_id_column(80)
        assert config["max_width"] == 13

    def test_config_for_id_column_medium(self):
        """Test ID column in medium terminal."""
        config = _config_for_id_column(110)
        assert config["max_width"] == 20

    def test_config_for_id_column_wide(self):
        """Test ID column in wide terminal."""
        config = _config_for_id_column(150)
        assert config["max_width"] == 36

    def test_config_for_description_column_responsive(self):
        """Test description column adapts to terminal width."""
        narrow = _config_for_description_column(80)
        medium = _config_for_description_column(110)
        wide = _config_for_description_column(150)

        assert narrow["max_width"] == 35
        assert medium["max_width"] == 45
        assert wide["max_width"] == 60
        assert narrow["no_wrap"] is False
        assert narrow["overflow"] == "fold"

    def test_config_for_date_column_created(self):
        """Test created date column always shows."""
        config = _config_for_date_column("created", 80)
        assert config["show"] is True

    def test_config_for_date_column_updated_narrow(self):
        """Test updated date hidden in narrow terminals."""
        config = _config_for_date_column("updated", 80)
        assert config["show"] is False

    def test_config_for_date_column_updated_wide(self):
        """Test updated date shows in wide terminals."""
        config = _config_for_date_column("updated", 150)
        assert config["show"] is True

    def test_config_for_hidden_field(self):
        """Test hidden field configuration."""
        config = _config_for_hidden_field()
        assert config["show"] is False

    def test_config_for_standard_field(self):
        """Test standard field configuration."""
        config = _config_for_standard_field(30)
        assert config["show"] is True
        assert config["no_wrap"] is True
        assert config["max_width"] == 30

    def test_config_for_budget_period_narrow(self):
        """Test budget period hidden in narrow terminals."""
        config = _config_for_budget_period(80)
        assert config["show"] is False

    def test_config_for_budget_period_wide(self):
        """Test budget period shows in wide terminals."""
        config = _config_for_budget_period(150)
        assert config["show"] is True

    def test_get_column_config_provider(self):
        """Test provider column configuration."""
        config = _get_column_config("provider", 100)
        assert config["max_width"] == 20

    def test_get_column_config_encryption_key_hidden(self):
        """Test encryption_key is hidden."""
        config = _get_column_config("encryption_key", 100)
        assert config["show"] is False


class TestIsHelpers:
    """Tests for _is_* helper functions."""

    def test_is_provider_key_data_true(self):
        """Test identifying provider key data."""
        items = [{"provider": "openai", "encrypted_key": "abc123"}]
        assert _is_provider_key_data(items) is True

    def test_is_provider_key_data_false_empty(self):
        """Test empty list returns False."""
        assert _is_provider_key_data([]) is False

    def test_is_provider_key_data_false_missing_fields(self):
        """Test data without provider field."""
        items = [{"name": "test"}]
        assert _is_provider_key_data(items) is False

    def test_is_list_response_true(self):
        """Test identifying list response."""
        data = {"data": [{"id": "1"}], "count": 1}
        assert _is_list_response(data) is True

    def test_is_list_response_false_no_data(self):
        """Test dict without data field."""
        data = {"items": [{"id": "1"}]}
        assert _is_list_response(data) is False

    def test_is_list_response_false_data_not_list(self):
        """Test data field is not a list."""
        data = {"data": "not a list"}
        assert _is_list_response(data) is False


class TestFormatOutput:
    """Tests for format_output function."""

    def test_format_output_json(self, capsys):
        """Test JSON output format."""
        data = {"name": "test", "value": 42}
        format_output(data, "json")
        captured = capsys.readouterr()
        assert '"name": "test"' in captured.out
        assert '"value": 42' in captured.out

    def test_format_output_yaml(self, capsys):
        """Test YAML output format."""
        data = {"name": "test", "value": 42}
        format_output(data, "yaml")
        captured = capsys.readouterr()
        assert "name: test" in captured.out
        assert "value: 42" in captured.out

    def test_format_output_table_list(self):
        """Test table output format with list."""
        data = [{"id": "1", "name": "Test"}]
        # We can't easily capture rich console output, so just verify it doesn't error
        format_output(data, "table")

    def test_format_output_table_dict_with_data(self):
        """Test table output with dict containing data field."""
        data = {"data": [{"id": "1", "name": "Test"}], "count": 1}
        format_output(data, "table")

    def test_format_output_table_single_dict(self):
        """Test table output with single dict."""
        data = {"id": "123", "name": "Test", "created_at": "2026-02-24T14:37:32"}
        format_output(data, "table")


class TestHandleError:
    """Tests for handle_error function."""

    def test_handle_error_authentication_error(self):
        """Test handling AuthenticationError."""
        from any_llm_platform_client.client_management import AuthenticationError

        error = AuthenticationError("Invalid credentials")
        with pytest.raises(SystemExit):
            handle_error(error, "login")

    def test_handle_error_challenge_creation_error(self):
        """Test handling ChallengeCreationError."""
        error = ChallengeCreationError("No project found")
        with pytest.raises(SystemExit):
            handle_error(error, "create challenge")

    def test_handle_error_provider_key_fetch_error(self):
        """Test handling ProviderKeyFetchError."""
        error = ProviderKeyFetchError("Provider not found")
        with pytest.raises(SystemExit):
            handle_error(error, "fetch provider key")

    def test_handle_error_generic_exception(self):
        """Test handling generic exception."""
        error = ValueError("Something went wrong")
        with pytest.raises(SystemExit):
            handle_error(error, "operation")
