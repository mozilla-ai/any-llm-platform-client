"""Click-based command-line interface for the provider key decrypter (renamed)."""

import logging
import os
import sys

import click

from .client import AnyLLMPlatformClient
from .exceptions import ChallengeCreationError, ProviderKeyFetchError


def _get_any_llm_key(cli_key: str | None) -> str:
    if cli_key:
        return cli_key

    env_key = __import__("os").environ.get("ANY_LLM_KEY")
    if env_key:
        click.echo("✅ Using ANY_LLM_KEY from environment variable")
        return env_key

    return click.prompt("Paste ANY_LLM_KEY (ANY.v1.<kid>.<fingerprint>-<base64_key>)", hide_input=True)


def _run_decryption(provider: str, any_llm_key: str, client: AnyLLMPlatformClient) -> str:
    # Use the convenience method which handles all the steps internally
    result = client.get_decrypted_provider_key(any_llm_key, provider)

    click.echo("")
    click.echo("🎉 SUCCESS!")
    click.echo("🔑 Decrypted API Key:")
    click.echo(f"   {result.api_key}")

    return result.api_key


@click.command()
@click.argument("provider", required=False)
@click.option(
    "--any-llm-platform-url",
    "any_llm_platform_url",
    help="any llm platform base URL to use (overrides default)",
)
@click.option("--any-llm-key", "any_llm_key", help="ANY_LLM_KEY string to use (skips prompt)")
@click.option("--client-name", "client_name", help="Client name for budget enforcement")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose (DEBUG) logging")
def main(
    provider: str | None,
    any_llm_platform_url: str | None,
    any_llm_key: str | None,
    client_name: str | None,
    verbose: bool = False,
) -> None:
    """CLI entry point for decrypting provider API keys from ANY LLM platform."""
    try:
        level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(level=level, format="%(message)s")

        any_llm_platform_url_env = os.environ.get("ANY_LLM_PLATFORM_URL")
        if any_llm_platform_url is None and any_llm_platform_url_env:
            any_llm_platform_url = any_llm_platform_url_env

        client = AnyLLMPlatformClient(any_llm_platform_url, client_name=client_name)

        if provider is None:
            provider = click.prompt("Enter Provider name (e.g., openai, anthropic)")

        any_llm_key_resolved = _get_any_llm_key(any_llm_key)
        _run_decryption(provider, any_llm_key_resolved, client)

    except (ChallengeCreationError, ProviderKeyFetchError) as exc:
        click.echo(f"❌ Error: {exc}")
        sys.exit(1)
    except Exception as exc:  # pragma: no cover - top-level CLI error handling
        click.echo(f"❌ Error: {exc}")
        raise


if __name__ == "__main__":
    main()
