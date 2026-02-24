"""Click-based command-line interface for any-llm platform."""

import json
import logging
import os
import sys
from typing import Any

import click
import yaml
from rich import box
from rich.console import Console
from rich.table import Table

from .client import AnyLLMPlatformClient
from .client_management import AuthenticationError
from .crypto import (
    encrypt_data,
    extract_public_key,
    format_any_llm_key,
    generate_keypair,
    load_private_key,
    parse_any_llm_key,
)
from .exceptions import ChallengeCreationError, ProviderKeyFetchError

logger = logging.getLogger(__name__)
# Console that adapts to terminal width
console = Console()

# Terminal width breakpoints for responsive layout
TERMINAL_WIDTH_NARROW = 100
TERMINAL_WIDTH_MEDIUM = 120
TERMINAL_WIDTH_WIDE = 140

# Column width constants
ID_WIDTH_NARROW = 13  # Show first 8 and last 4 chars with ellipsis: "5f1e9b62…edd8"
ID_WIDTH_MEDIUM = 20
ID_WIDTH_FULL = 36  # Full UUID
NAME_WIDTH = 20
DESCRIPTION_WIDTH_NARROW = 35
DESCRIPTION_WIDTH_MEDIUM = 45
DESCRIPTION_WIDTH_WIDE = 60
DATE_WIDTH = 15  # Show formatted date: "Feb 23, 2026"

# Display constants
PROJECT_ID_DISPLAY_LENGTH = 8  # Show first 8 chars of project ID in messages


# ========== Custom Click Group ==========
# (Removed DefaultCommandGroup - all commands are now explicit)


# ========== Helper Functions ==========


def _get_any_llm_key(cli_key: str | None) -> str:
    if cli_key:
        return cli_key

    env_key = os.environ.get("ANY_LLM_KEY")
    if env_key:
        return env_key

    return click.prompt("Paste ANY_LLM_KEY (ANY.v1.<kid>.<fingerprint>-<base64_key>)", hide_input=True)


def _run_decryption(provider: str, any_llm_key: str, client: AnyLLMPlatformClient) -> str:
    # Use the convenience method which handles all the steps internally
    result = client.get_decrypted_provider_key(any_llm_key, provider)

    click.echo("")
    click.echo("Decrypted API Key:")
    click.echo(f"  {result.api_key}")

    return result.api_key


def get_authenticated_client(ctx: click.Context) -> AnyLLMPlatformClient:
    """Get or create an authenticated client for management commands."""
    if "client" not in ctx.obj:
        # Get credentials
        username = ctx.obj.get("username") or os.environ.get("ANY_LLM_USERNAME")
        password = ctx.obj.get("password") or os.environ.get("ANY_LLM_PASSWORD")

        if not username or not password:
            click.echo("Error: Username and password required for management commands", err=True)
            click.echo("Set ANY_LLM_USERNAME and ANY_LLM_PASSWORD environment variables", err=True)
            click.echo("Or use --username and --password options", err=True)
            sys.exit(1)

        # Create and authenticate client
        any_llm_platform_url = ctx.obj.get("any_llm_platform_url") or os.environ.get("ANY_LLM_PLATFORM_URL")
        client = AnyLLMPlatformClient(any_llm_platform_url)

        try:
            client.login(username, password)
            ctx.obj["client"] = client
        except AuthenticationError as e:
            click.echo(f"Error: Authentication failed - {e}", err=True)
            sys.exit(1)

    return ctx.obj["client"]


def _format_date(date_str: str | None, field_name: str = "") -> str:
    """Format a date string to human-readable format.

    Args:
        date_str: ISO date string (e.g., "2026-02-23T14:37:32")
        field_name: Name of the field being formatted (used for context-specific defaults)

    Returns:
        Human-readable date (e.g., "Feb 23, 2026")
    """
    if not date_str:
        # For "last_used" fields, show "Never used"
        if "last_used" in field_name.lower():
            return "Never used"
        # For other date fields, show "N/A"
        return "N/A"

    try:
        from datetime import datetime

        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return dt.strftime("%b %d, %Y")
    except Exception:
        return date_str


def _transform_dates_in_data(items: list[dict]) -> list[dict]:
    """Transform all date fields in data to human-readable format.

    Automatically formats any field ending in '_at' (e.g., created_at, updated_at)
    to human-readable format like "Feb 23, 2026".

    Args:
        items: List of dicts from API

    Returns:
        Transformed list with formatted dates
    """
    transformed = []
    for item in items:
        display_item = {}

        # Always put 'id' first if it exists
        if "id" in item:
            display_item["id"] = item["id"]

        # Then add all other fields
        for key, value in item.items():
            if key == "id":
                continue  # Already added
            # Format date fields (any field ending with _at)
            if key.endswith("_at"):
                # Remove _at suffix for cleaner display
                display_key = key.replace("_at", "")
                display_item[display_key] = _format_date(value, key)
            else:
                display_item[key] = value
        transformed.append(display_item)

    return transformed


def _transform_provider_key_data(items: list[dict]) -> list[dict]:
    """Transform provider key data for display.

    Converts API response fields to user-friendly display format:
    - id: Provider key ID (for management operations)
    - provider: Keep as-is
    - archived: "Yes" or "No" (from is_archived field)
    - created_at: Format as "Feb 23, 2026"
    - last_used_at: Format as "Feb 23, 2026" or "Never used"
    - budget: Format as "$0.00 / $1.00" (if available)

    Args:
        items: List of provider key dicts from API

    Returns:
        Transformed list with display-friendly fields
    """
    transformed = []
    for item in items:
        # Check if archived - API may return either:
        # - is_archived: boolean (True/False)
        # - archived_at: timestamp (non-null means archived, null means not archived)
        is_archived = item.get("is_archived") or item.get("archived_at") is not None

        display_item = {
            "id": item.get("id", ""),
            "provider": item.get("provider", ""),
            "archived": "Yes" if is_archived else "No",
            "created": _format_date(item.get("created_at"), "created_at"),
            "last_used": _format_date(item.get("last_used_at"), "last_used_at"),
        }

        # Add budget if available
        if "budget" in item:
            budget = item["budget"]
            if isinstance(budget, dict):
                spent = budget.get("spent", 0)
                limit = budget.get("limit", 0)
                display_item["budget"] = f"${spent:.2f} / ${limit:.2f}"
            else:
                display_item["budget"] = str(budget)
        else:
            display_item["budget"] = "N/A"

        transformed.append(display_item)

    return transformed


def _config_for_name_column() -> dict[str, Any]:
    """Get column configuration for name field."""
    return {
        "show": True,
        "no_wrap": True,
        "overflow": "ellipsis",
        "max_width": NAME_WIDTH,
    }


def _config_for_id_column(terminal_width: int) -> dict[str, Any]:
    """Get column configuration for ID field with smart truncation."""
    if terminal_width < TERMINAL_WIDTH_NARROW:
        id_width = ID_WIDTH_NARROW
    elif terminal_width < TERMINAL_WIDTH_MEDIUM:
        id_width = ID_WIDTH_MEDIUM
    else:
        id_width = ID_WIDTH_FULL
    return {
        "show": True,
        "no_wrap": True,
        "overflow": "ellipsis",
        "max_width": id_width,
    }


def _config_for_description_column(terminal_width: int) -> dict[str, Any]:
    """Get column configuration for description field with responsive width."""
    if terminal_width < TERMINAL_WIDTH_NARROW:
        desc_width = DESCRIPTION_WIDTH_NARROW
    elif terminal_width < TERMINAL_WIDTH_MEDIUM:
        desc_width = DESCRIPTION_WIDTH_MEDIUM
    else:
        desc_width = DESCRIPTION_WIDTH_WIDE
    return {
        "show": True,
        "no_wrap": False,
        "overflow": "fold",
        "max_width": desc_width,
    }


def _config_for_date_column(header: str, terminal_width: int) -> dict[str, Any]:
    """Get column configuration for date fields."""
    # Updated timestamps hide in narrow terminals to save space
    if header in ["updated_at", "updated"]:
        return {
            "show": terminal_width >= TERMINAL_WIDTH_MEDIUM,
            "no_wrap": True,
            "overflow": "ellipsis",
            "max_width": DATE_WIDTH,
        }
    # Created timestamps always show
    return {
        "show": True,
        "no_wrap": True,
        "overflow": "ellipsis",
        "max_width": DATE_WIDTH,
    }


def _config_for_hidden_field() -> dict[str, Any]:
    """Get column configuration for fields that should be hidden."""
    return {"show": False}


def _config_for_standard_field(max_width: int | None = None) -> dict[str, Any]:
    """Get column configuration for standard fields."""
    return {
        "show": True,
        "no_wrap": True,
        "overflow": "ellipsis",
        "max_width": max_width,
    }


def _config_for_budget_period(terminal_width: int) -> dict[str, Any]:
    """Get column configuration for budget period timestamps."""
    return {
        "show": terminal_width >= TERMINAL_WIDTH_WIDE,
        "no_wrap": True,
        "overflow": "ellipsis",
        "max_width": 20,
    }


def _get_column_config(header: str, terminal_width: int) -> dict[str, Any]:
    """Get column configuration for a given header.

    Returns dict with 'show', 'no_wrap', 'overflow', and 'max_width' keys.
    """
    # Name: always show first, never wrap, reasonable width
    if header == "name":
        return _config_for_name_column()

    # ID: show with smart truncation (beginning + end of UUID)
    if header == "id":
        return _config_for_id_column(terminal_width)

    # Description: allow wrapping on multiple lines with generous width
    if header == "description":
        return _config_for_description_column(terminal_width)

    # Date fields: show created always, hide updated in narrow terminals
    if header in ["created_at", "created", "updated_at", "updated"]:
        return _config_for_date_column(header, terminal_width)

    # Hidden fields: technical or internal fields
    if header in ["encryption_key", "project_id", "encrypted_key", "is_archived"]:
        return _config_for_hidden_field()

    # Budget period timestamps: hide in narrow terminals
    if header in ["period_start", "period_end"]:
        return _config_for_budget_period(terminal_width)

    # Standard fields with specific widths
    if header == "provider":
        return _config_for_standard_field(20)
    if header == "archived":
        return _config_for_standard_field(10)
    if header in ["budget_limit", "current_spend", "spend_period"]:
        return _config_for_standard_field(15)
    if header in ["budget", "last_used_at", "last_used"]:
        return _config_for_standard_field(20)

    # Default: show with reasonable defaults
    return _config_for_standard_field(None)


def _is_provider_key_data(items: list[dict]) -> bool:
    """Check if data represents provider key response."""
    return bool(items) and "provider" in items[0] and "encrypted_key" in items[0]


def _is_list_response(data: dict) -> bool:
    """Check if data is a list response with 'data' field."""
    return "data" in data and isinstance(data["data"], list)


def _format_table(data: Any) -> None:
    """Format data as a pretty table using rich.

    For lists of objects, creates a formatted table with headers.
    For single objects, creates key-value pairs.
    For simple values, prints them directly.
    """
    if isinstance(data, dict):
        # Check if it's a response with 'data' and 'count' (list endpoints)
        if _is_list_response(data):
            items = data["data"]
            if items:
                # Transform data based on type
                if _is_provider_key_data(items):
                    items = _transform_provider_key_data(items)
                else:
                    items = _transform_dates_in_data(items)

                # Create rich table with optimized column display
                headers = list(items[0].keys())
                table = Table(show_header=True, header_style="bold cyan", box=box.SIMPLE)

                # Get terminal width for responsive layout
                terminal_width = console.width

                # Add columns based on configuration (skip hidden ones like 'id')
                visible_headers = []
                for header in headers:
                    config = _get_column_config(header, terminal_width)
                    if not config.get("show", True):
                        continue  # Skip hidden columns

                    visible_headers.append(header)
                    kwargs = {
                        "no_wrap": config.get("no_wrap", True),
                        "overflow": config.get("overflow", "ellipsis"),
                    }
                    if config.get("max_width"):
                        kwargs["max_width"] = config["max_width"]

                    table.add_column(header, **kwargs)

                # Add rows (only visible columns)
                for item in items:
                    row = [str(item.get(h, "")) for h in visible_headers]
                    table.add_row(*row)

                console.print(table)
            else:
                # Empty list - show friendly message
                console.print("\n[dim]No items found.[/dim]")
            if "count" in data:
                console.print(f"\n[dim]Total: {data['count']}[/dim]")
        else:
            # Single object - transform dates and print key-value pairs as a table
            display_data = _transform_dates_in_data([data])[0] if data else data
            table = Table(show_header=True, header_style="bold cyan", box=box.SIMPLE)
            table.add_column("Key", no_wrap=True)
            table.add_column("Value", no_wrap=False, overflow="fold")

            for key, value in display_data.items():
                table.add_row(str(key), str(value))

            console.print(table)
    elif isinstance(data, list):
        if data:
            # List of objects
            if isinstance(data[0], dict):
                # Transform dates to human-readable format
                data = _transform_dates_in_data(data)

                headers = list(data[0].keys())
                table = Table(show_header=True, header_style="bold cyan", box=box.SIMPLE)

                # Get terminal width for responsive layout
                terminal_width = console.width

                # Add columns based on configuration (skip hidden ones like 'id')
                visible_headers = []
                for header in headers:
                    config = _get_column_config(header, terminal_width)
                    if not config.get("show", True):
                        continue  # Skip hidden columns

                    visible_headers.append(header)
                    kwargs = {
                        "no_wrap": config.get("no_wrap", True),
                        "overflow": config.get("overflow", "ellipsis"),
                    }
                    if config.get("max_width"):
                        kwargs["max_width"] = config["max_width"]

                    table.add_column(header, **kwargs)

                # Add rows (only visible columns)
                for item in data:
                    row = [str(item.get(h, "")) for h in visible_headers]
                    table.add_row(*row)

                console.print(table)
            else:
                # Simple list
                table = Table(show_header=True, header_style="bold cyan", box=box.SIMPLE)
                table.add_column("Value", no_wrap=False)

                for item in data:
                    table.add_row(str(item))

                console.print(table)
    else:
        # Simple value
        console.print(str(data))


def format_output(data: Any, format_type: str = "table") -> None:
    """Format and display output data.

    Args:
        data: The data to format (dict or list)
        format_type: Output format - "table", "json", or "yaml"
    """
    if format_type == "json":
        click.echo(json.dumps(data, indent=2, default=str))
    elif format_type == "yaml":
        click.echo(yaml.dump(data, default_flow_style=False, sort_keys=False))
    else:
        # Table format - parseable output
        _format_table(data)


def handle_error(error: Exception, operation: str) -> None:
    """Unified error handler for CLI commands.

    Args:
        error: The exception that occurred
        operation: Description of the operation (e.g., "list projects")
    """
    if isinstance(error, AuthenticationError):
        click.echo(f"Error: Authentication failed - {error}", err=True)
    elif isinstance(error, ChallengeCreationError | ProviderKeyFetchError):
        click.echo(f"Error: {error}", err=True)
    else:
        click.echo(f"Error: Failed to {operation} - {error}", err=True)
    sys.exit(1)


# ========== Main CLI Group ==========


@click.group()
@click.option("--any-llm-platform-url", help="any-llm platform API URL")
@click.option("--any-llm-key", help="ANY_LLM_KEY string to use (skips prompt)")
@click.option("--client-name", help="Client name for budget enforcement")
@click.option("--username", help="Username for authentication (management commands)")
@click.option("--password", help="Password for authentication (management commands)")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose logging")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json", "yaml"]),
    default="table",
    help="Output format (management commands)",
)
@click.pass_context
def cli(
    ctx: click.Context,
    any_llm_platform_url: str | None,
    any_llm_key: str | None,
    client_name: str | None,
    username: str | None,
    password: str | None,
    verbose: bool,
    output_format: str,
) -> None:
    """any-llm platform Management CLI.

    Manage your any-llm platform projects, provider keys, budgets, and clients.

    Use 'any-llm <command> --help' for more information on a command.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(message)s")

    # Suppress noisy HTTP logs from httpx/httpcore
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("httpcore.connection").setLevel(logging.WARNING)
    logging.getLogger("httpcore.http11").setLevel(logging.WARNING)

    # Initialize context object for subcommands
    ctx.ensure_object(dict)
    ctx.obj["username"] = username
    ctx.obj["password"] = password
    ctx.obj["any_llm_platform_url"] = any_llm_platform_url
    ctx.obj["output_format"] = output_format
    ctx.obj["any_llm_key"] = any_llm_key
    ctx.obj["client_name"] = client_name


# ========== Project Commands ==========


@cli.group()
def project() -> None:
    """Manage projects."""
    pass


@project.command("list")
@click.option("--skip", default=0, help="Number of projects to skip")
@click.option("--limit", default=100, help="Maximum number of projects to return")
@click.pass_context
def project_list(ctx: click.Context, skip: int, limit: int) -> None:
    """List all projects."""
    client = get_authenticated_client(ctx)
    try:
        result = client.list_projects(skip=skip, limit=limit)
        format_output(result, ctx.obj["output_format"])
    except Exception as e:
        handle_error(e, "list projects")


@project.command("create")
@click.argument("name")
@click.option("--description", help="Project description")
@click.pass_context
def project_create(ctx: click.Context, name: str, description: str) -> None:
    """Create a new project."""
    client = get_authenticated_client(ctx)
    try:
        result = client.create_project(name=name, description=description)
        click.echo(f"Created project: {result['id']}")
        format_output(result, ctx.obj["output_format"])
    except Exception as e:
        handle_error(e, "create project")


@project.command("show")
@click.argument("project_id")
@click.pass_context
def project_show(ctx: click.Context, project_id: str) -> None:
    """Show project details."""
    client = get_authenticated_client(ctx)
    try:
        result = client.get_project(project_id)
        format_output(result, ctx.obj["output_format"])
    except Exception as e:
        handle_error(e, "show project")


@project.command("update")
@click.argument("project_id")
@click.option("--name", help="New project name")
@click.option("--description", help="New project description")
@click.pass_context
def project_update(ctx: click.Context, project_id: str, name: str, description: str) -> None:
    """Update a project."""
    client = get_authenticated_client(ctx)
    try:
        result = client.update_project(project_id, name=name, description=description)
        click.echo(f"Updated project: {project_id}")
        format_output(result, ctx.obj["output_format"])
    except Exception as e:
        handle_error(e, "update project")


@project.command("delete")
@click.argument("project_id")
@click.confirmation_option(prompt="Are you sure you want to delete this project?")
@click.pass_context
def project_delete(ctx: click.Context, project_id: str) -> None:
    """Delete a project."""
    client = get_authenticated_client(ctx)
    try:
        result = client.delete_project(project_id)
        click.echo(f"Deleted project: {project_id}")
        format_output(result, ctx.obj["output_format"])
    except Exception as e:
        handle_error(e, "delete project")


# ========== Key Commands (Provider Keys & Decryption) ==========


@cli.group("key")
def key() -> None:
    """Manage provider keys and decrypt API keys."""
    pass


@key.command("decrypt")
@click.argument("provider", required=False)
@click.pass_context
def key_decrypt(ctx: click.Context, provider: str | None) -> None:
    """Decrypt a provider API key.

    Requires ANY_LLM_KEY environment variable or --any-llm-key option.

    Examples:
      any-llm key decrypt openai
      any-llm key decrypt anthropic
    """
    try:
        any_llm_platform_url = ctx.obj.get("any_llm_platform_url") or os.environ.get("ANY_LLM_PLATFORM_URL")
        client_name = ctx.obj.get("client_name")
        any_llm_key = ctx.obj.get("any_llm_key")

        client = AnyLLMPlatformClient(any_llm_platform_url, client_name=client_name)

        if provider is None:
            provider = click.prompt("Enter Provider name (e.g., openai, anthropic)")

        any_llm_key_resolved = _get_any_llm_key(any_llm_key)
        # provider is guaranteed to be a str at this point
        _run_decryption(str(provider), any_llm_key_resolved, client)

    except (ChallengeCreationError, ProviderKeyFetchError) as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
    except Exception as exc:  # pragma: no cover - top-level CLI error handling
        click.echo(f"Error: {exc}", err=True)
        raise


@key.command("list")
@click.argument("project_id")
@click.option("--include-archived", is_flag=True, help="Include archived keys")
@click.pass_context
def key_list(ctx: click.Context, project_id: str, include_archived: bool) -> None:
    """List provider keys for a project."""
    client = get_authenticated_client(ctx)
    try:
        result = client.list_provider_keys(project_id, include_archived=include_archived)
        format_output(result, ctx.obj["output_format"])
    except Exception as e:
        handle_error(e, "list provider keys")


@key.command("create")
@click.argument("project_id")
@click.argument("provider_name")
@click.argument("encrypted_key")
@click.pass_context
def key_create(ctx: click.Context, project_id: str, provider_name: str, encrypted_key: str) -> None:
    """Create a provider key.

    Use empty string "" for local providers like Ollama.
    """
    client = get_authenticated_client(ctx)
    try:
        result = client.create_provider_key_mgmt(project_id, provider_name, encrypted_key)
        click.echo(f"Created provider key: {result['id']}")
        format_output(result, ctx.obj["output_format"])
    except Exception as e:
        handle_error(e, "create provider key")


@key.command("update")
@click.argument("provider_key_id")
@click.argument("encrypted_key")
@click.pass_context
def key_update(ctx: click.Context, provider_key_id: str, encrypted_key: str) -> None:
    """Update a provider key."""
    client = get_authenticated_client(ctx)
    try:
        result = client.update_provider_key_mgmt(provider_key_id, encrypted_key)
        click.echo(f"Updated provider key: {provider_key_id}")
        format_output(result, ctx.obj["output_format"])
    except Exception as e:
        handle_error(e, "update provider key")


@key.command("delete")
@click.argument("provider_key_id")
@click.option("--permanent", is_flag=True, help="Permanently delete (default: archive)")
@click.confirmation_option(prompt="Are you sure you want to delete this provider key?")
@click.pass_context
def key_delete(ctx: click.Context, provider_key_id: str, permanent: bool) -> None:
    """Delete or archive a provider key."""
    client = get_authenticated_client(ctx)
    try:
        result = client.delete_provider_key_mgmt(provider_key_id, permanent=permanent)
        action = "Deleted" if permanent else "Archived"
        click.echo(f"{action} provider key: {provider_key_id}")
        format_output(result, ctx.obj["output_format"])
    except Exception as e:
        handle_error(e, "delete provider key")


@key.command("unarchive")
@click.argument("provider_key_id")
@click.pass_context
def key_unarchive(ctx: click.Context, provider_key_id: str) -> None:
    """Unarchive a provider key."""
    client = get_authenticated_client(ctx)
    try:
        result = client.unarchive_provider_key(provider_key_id)
        click.echo(f"Unarchived provider key: {provider_key_id}")
        format_output(result, ctx.obj["output_format"])
    except Exception as e:
        handle_error(e, "unarchive provider key")


@key.command("generate")
@click.argument("project_id")
@click.option("--old-key", help="Old ANY_LLM_KEY for migrating existing provider keys")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompts")
@click.pass_context
def key_generate(ctx: click.Context, project_id: str, old_key: str | None, yes: bool) -> None:
    """Generate a new encryption key for a project and migrate provider keys.

    This command:
    1. Generates a new X25519 keypair
    2. Updates the project's encryption_key with the new public key
    3. Migrates all provider keys from old key to new key
    4. Displays the new ANY_LLM_KEY (save this securely!)

    If old key is provided, provider keys are migrated. If not, they are archived.

    Examples:
      # Generate and migrate from old key
      any-llm key generate <project-id> --old-key "ANY.v1..."

      # Generate without migration (archive all keys)
      any-llm key generate <project-id>
    """
    client = get_authenticated_client(ctx)
    try:
        # Fetch project info
        project = client.get_project(project_id)

        # Prompt for old key if not provided
        if not old_key:
            old_key_input = click.prompt(
                "Enter old ANY_LLM_KEY to migrate provider keys (or press Enter to archive all)",
                default="",
                hide_input=True,
                show_default=False,
            )
            old_key = old_key_input if old_key_input else None

        # Parse old key if provided
        old_private_key = None
        if old_key:
            try:
                old_key_components = parse_any_llm_key(old_key)
                old_private_key = load_private_key(old_key_components.base64_encoded_private_key)
            except Exception as e:
                click.echo(f"Error: Invalid old ANY_LLM_KEY format: {e}")
                sys.exit(1)

        # Generate new keypair
        click.echo("")
        click.echo("Generating new encryption key...")
        new_private_key, new_public_key = generate_keypair()

        # Format as ANY_LLM_KEY
        new_any_llm_key = format_any_llm_key(new_private_key)

        # Get public key as base64
        new_public_key_base64 = extract_public_key(new_private_key)

        # Update project with new encryption key
        client.update_project(project_id, encryption_key=new_public_key_base64)
        click.echo("Updated project encryption key")

        # Fetch all provider keys
        result = client.list_provider_keys(project_id, include_archived=True)

        # Extract provider keys - API returns {"data": [...], "count": N}
        if isinstance(result, dict):
            provider_keys = result.get("data", result.get("items", []))
        elif isinstance(result, list):
            provider_keys = result
        else:
            provider_keys = []

        if provider_keys:
            click.echo("")
            click.echo(
                f"Migrating provider keys for project: {project['name']} ({project_id[:PROJECT_ID_DISPLAY_LENGTH]}...)"
            )
            click.echo("")
            click.echo(f"Found {len(provider_keys)} provider key(s) to process:")
            for pk in provider_keys:
                status = " (archived)" if pk.get("is_archived") else ""
                is_local = " (local)" if not pk.get("encrypted_key") else ""
                click.echo(f"  - {pk['provider']}{status}{is_local}")
            click.echo("")

            # Show warning based on whether old key is provided
            if not old_private_key:
                click.echo("WARNING: No old key provided. All encrypted provider keys will be ARCHIVED.")
                click.echo("This means you will need to re-enter all API keys in the web interface.")
                click.echo("")
                if not yes:
                    confirmation = click.prompt(
                        "Type 'archive all' to confirm",
                        default="",
                    )
                    if confirmation != "archive all":
                        click.echo("Operation cancelled.")
                        sys.exit(0)
            else:
                click.echo("WARNING: This will re-encrypt all provider keys with the new encryption key.")
                if not yes and not click.confirm("Continue?"):
                    click.echo("Operation cancelled.")
                    sys.exit(0)

            click.echo("")
            click.echo("Processing provider keys...")

            # Process each provider key
            migrated = 0
            skipped = 0
            archived = 0
            failed = 0

            for pk in provider_keys:
                pk_id = pk["id"]
                provider = pk["provider"]
                encrypted_key = pk.get("encrypted_key", "")

                # Skip empty keys (local providers like ollama)
                if not encrypted_key:
                    click.echo(f"  [SKIP] {provider} - Local provider, no encryption")
                    skipped += 1
                    continue

                # If no old key, archive all
                if not old_private_key:
                    try:
                        client.delete_provider_key_mgmt(pk_id, permanent=False)
                        click.echo(f"  [OK]   {provider} - Archived")
                        archived += 1
                    except Exception as e:
                        click.echo(f"  [FAIL] {provider} - Failed to archive: {e}")
                        failed += 1
                    continue

                # Try to decrypt with old key and re-encrypt with new key
                try:
                    from .crypto import decrypt_data

                    decrypted_api_key = decrypt_data(encrypted_key, old_private_key)

                    # Re-encrypt with new key
                    new_encrypted_key = encrypt_data(decrypted_api_key, new_public_key)

                    # Update via API
                    client.update_provider_key_mgmt(pk_id, new_encrypted_key)

                    click.echo(f"  [OK]   {provider} - Migrated successfully")
                    migrated += 1

                except Exception:
                    # Failed to decrypt - archive the key
                    try:
                        client.delete_provider_key_mgmt(pk_id, permanent=False)
                        click.echo(f"  [FAIL] {provider} - Archived (failed to decrypt with old key)")
                        archived += 1
                    except Exception as archive_error:
                        click.echo(f"  [FAIL] {provider} - Failed to archive: {archive_error}")
                        failed += 1

            # Display migration summary
            click.echo("")
            click.echo("Migration Summary:")
            click.echo(f"  Migrated: {migrated} key(s)")
            click.echo(f"  Skipped: {skipped} key(s) (local providers)")
            click.echo(f"  Archived: {archived} key(s) (decryption failed or no old key)")
            click.echo(f"  Failed: {failed} key(s) (API errors)")
        else:
            click.echo("")
            click.echo("No provider keys found for this project.")

        # Display the new key
        click.echo("")
        click.echo("=" * 70)
        click.echo("")
        click.echo("Generated new encryption key for project!")
        click.echo("")
        click.echo("IMPORTANT: Save this key in a secure location. It cannot be recovered!")
        click.echo("")
        click.echo(new_any_llm_key)
        click.echo("")
        click.echo("=" * 70)
        click.echo("")

    except Exception as e:
        click.echo(f"Error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


# ========== Budget Commands ==========


@cli.group()
def budget() -> None:
    """Manage project budgets.

    Set spending limits for projects with daily, weekly, or monthly periods.
    """
    pass


@budget.command("list")
@click.argument("project_id")
@click.pass_context
def budget_list(ctx: click.Context, project_id: str) -> None:
    """List budgets for a project."""
    client = get_authenticated_client(ctx)
    try:
        result = client.list_project_budgets(project_id)
        format_output(result, ctx.obj["output_format"])
    except Exception as e:
        handle_error(e, "list budgets")


@budget.command("create")
@click.argument("project_id")
@click.argument("budget_limit", type=float)
@click.option("--period", type=click.Choice(["daily", "weekly", "monthly"]), default="monthly")
@click.pass_context
def budget_create(ctx: click.Context, project_id: str, budget_limit: float, period: str) -> None:
    """Create a project budget."""
    client = get_authenticated_client(ctx)
    try:
        result = client.create_project_budget(project_id, budget_limit, spend_period=period)
        click.echo(f"Created {period} budget for project: {project_id}")
        format_output(result, ctx.obj["output_format"])
    except Exception as e:
        handle_error(e, "create budget")


@budget.command("show")
@click.argument("project_id")
@click.argument("period", type=click.Choice(["daily", "weekly", "monthly"]))
@click.pass_context
def budget_show(ctx: click.Context, project_id: str, period: str) -> None:
    """Show a project budget."""
    client = get_authenticated_client(ctx)
    try:
        result = client.get_project_budget(project_id, period)
        format_output(result, ctx.obj["output_format"])
    except Exception as e:
        handle_error(e, "show budget")


@budget.command("update")
@click.argument("project_id")
@click.argument("period", type=click.Choice(["daily", "weekly", "monthly"]))
@click.argument("budget_limit", type=float)
@click.pass_context
def budget_update(ctx: click.Context, project_id: str, period: str, budget_limit: float) -> None:
    """Update a project budget."""
    client = get_authenticated_client(ctx)
    try:
        result = client.update_project_budget(project_id, period, budget_limit)
        click.echo(f"Updated {period} budget for project: {project_id}")
        format_output(result, ctx.obj["output_format"])
    except Exception as e:
        handle_error(e, "update budget")


@budget.command("delete")
@click.argument("project_id")
@click.argument("period", type=click.Choice(["daily", "weekly", "monthly"]))
@click.confirmation_option(prompt="Are you sure you want to delete this budget?")
@click.pass_context
def budget_delete(ctx: click.Context, project_id: str, period: str) -> None:
    """Delete a project budget."""
    client = get_authenticated_client(ctx)
    try:
        result = client.delete_project_budget(project_id, period)
        click.echo(f"Deleted {period} budget for project: {project_id}")
        format_output(result, ctx.obj["output_format"])
    except Exception as e:
        handle_error(e, "delete budget")


# ========== Client Commands ==========


@cli.group()
def client() -> None:
    """Manage project clients."""
    pass


@client.command("list")
@click.argument("project_id")
@click.option("--skip", default=0, help="Number of clients to skip")
@click.option("--limit", default=100, help="Maximum number of clients to return")
@click.pass_context
def client_list(ctx: click.Context, project_id: str, skip: int, limit: int) -> None:
    """List clients for a project."""
    client_obj = get_authenticated_client(ctx)
    try:
        result = client_obj.list_clients(project_id, skip=skip, limit=limit)
        format_output(result, ctx.obj["output_format"])
    except Exception as e:
        handle_error(e, "list clients")


@client.command("create")
@click.argument("project_id")
@click.argument("name")
@click.option("--default", "is_default", is_flag=True, help="Set as default client")
@click.pass_context
def client_create(ctx: click.Context, project_id: str, name: str, is_default: bool) -> None:
    """Create a new client."""
    client_obj = get_authenticated_client(ctx)
    try:
        result = client_obj.create_client(project_id, name, is_default=is_default)
        click.echo(f"Created client: {result['id']}")
        format_output(result, ctx.obj["output_format"])
    except Exception as e:
        handle_error(e, "create client")


@client.command("show")
@click.argument("project_id")
@click.argument("client_id")
@click.pass_context
def client_show(ctx: click.Context, project_id: str, client_id: str) -> None:
    """Show client details."""
    client_obj = get_authenticated_client(ctx)
    try:
        result = client_obj.get_client(project_id, client_id)
        format_output(result, ctx.obj["output_format"])
    except Exception as e:
        handle_error(e, "show client")


@client.command("update")
@click.argument("project_id")
@click.argument("client_id")
@click.option("--name", help="New client name")
@click.option("--default/--no-default", "is_default", default=None, help="Set or unset as default")
@click.pass_context
def client_update(ctx: click.Context, project_id: str, client_id: str, name: str, is_default: bool) -> None:
    """Update a client."""
    client_obj = get_authenticated_client(ctx)
    try:
        result = client_obj.update_client(project_id, client_id, name=name, is_default=is_default)
        click.echo(f"Updated client: {client_id}")
        format_output(result, ctx.obj["output_format"])
    except Exception as e:
        handle_error(e, "update client")


@client.command("delete")
@click.argument("project_id")
@click.argument("client_id")
@click.confirmation_option(prompt="Are you sure you want to delete this client?")
@click.pass_context
def client_delete(ctx: click.Context, project_id: str, client_id: str) -> None:
    """Delete a client."""
    client_obj = get_authenticated_client(ctx)
    try:
        result = client_obj.delete_client(project_id, client_id)
        click.echo(f"Deleted client: {client_id}")
        format_output(result, ctx.obj["output_format"])
    except Exception as e:
        handle_error(e, "delete client")


@client.command("set-default")
@click.argument("project_id")
@click.argument("client_id")
@click.pass_context
def client_set_default(ctx: click.Context, project_id: str, client_id: str) -> None:
    """Set a client as the default for a project."""
    client_obj = get_authenticated_client(ctx)
    try:
        result = client_obj.set_default_client(project_id, client_id)
        click.echo(f"Set client {client_id} as default")
        format_output(result, ctx.obj["output_format"])
    except Exception as e:
        handle_error(e, "set default client")


# ========== Main Entry Point ==========


def main() -> None:
    """Entry point for the CLI."""
    cli(obj={})


if __name__ == "__main__":
    main()
