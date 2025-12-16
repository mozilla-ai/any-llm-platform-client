"""Click-based command-line interface for the provider key decrypter (renamed)."""

import logging
import os
import sys

import click

from .client import AnyLLMClient
from .crypto import extract_public_key, load_private_key, parse_any_llm_key
from .exceptions import ChallengeCreationError, ProviderKeyFetchError


def _get_any_llm_key(cli_key: str | None) -> str:
    if cli_key:
        return cli_key

    env_key = __import__("os").environ.get("ANY_LLM_KEY")
    if env_key:
        click.echo("✅ Using ANY_LLM_KEY from environment variable")
        return env_key

    return click.prompt("Paste ANY_LLM_KEY (ANY.v1.<kid>.<fingerprint>-<base64_key>)", hide_input=True)


def _run_decryption(provider: str, any_llm_key: str, client: AnyLLMClient) -> str:
    click.echo("🔍 Parsing ANY_LLM_KEY...")
    kid, fingerprint, private_key_base64 = parse_any_llm_key(any_llm_key)
    click.echo(f"✅ Key ID: {kid}")
    click.echo(f"✅ Fingerprint: {fingerprint}")

    click.echo("🔑 Loading X25519 private key...")
    private_key = load_private_key(private_key_base64)
    click.echo("✅ Private key loaded")

    click.echo("🔑 Extracting public key...")
    public_key = extract_public_key(private_key)
    click.echo("✅ Public key extracted")

    challenge_data = client.create_challenge(public_key)
    solved_challenge = client.solve_challenge(challenge_data["encrypted_challenge"], private_key)
    provider_key_data = client.fetch_provider_key(provider, public_key, solved_challenge)
    print(provider_key_data["encrypted_key"])
    print(private_key)
    decrypted_api_key = client.decrypt_provider_key_value(provider_key_data["encrypted_key"], private_key)

    click.echo("🎉 SUCCESS!")
    click.echo(f"Provider: {provider_key_data['provider']}")
    click.echo(f"Project ID: {provider_key_data['project_id']}")
    click.echo(f"Created: {provider_key_data['created_at']}")
    click.echo("")
    click.echo("🔑 Decrypted API Key:")
    click.echo(f"   {decrypted_api_key}")

    return decrypted_api_key


@click.command()
@click.argument("provider", required=False)
@click.option(
    "--any-llm-platform-url",
    "any_llm_platform_url",
    help="any llm platform base URL to use (overrides default)",
)
@click.option("--any-llm-key", "any_llm_key", help="ANY_LLM_KEY string to use (skips prompt)")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose (DEBUG) logging")
def main(
    provider: str | None, any_llm_platform_url: str | None, any_llm_key: str | None, verbose: bool = False
) -> None:
    """CLI entry point for decrypting provider API keys from ANY LLM platform."""
    try:
        level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(level=level, format="%(message)s")

        any_llm_platform_url_env = os.environ.get("ANY_LLM_PLATFORM_URL")
        if any_llm_platform_url is None and any_llm_platform_url_env:
            any_llm_platform_url = any_llm_platform_url_env

        client = AnyLLMClient(any_llm_platform_url) if any_llm_platform_url else AnyLLMClient()

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
