"""Click-based command-line interface for the provider key decrypter."""

import os

import click

from .client import (
    create_challenge,
    decrypt_provider_key_value,
    fetch_provider_key,
    set_api_base_url,
    solve_challenge,
)
from .crypto import extract_public_key, load_private_key, parse_any_llm_key


def _get_any_llm_key(cli_key: str | None) -> str:
    """Resolve ANY_LLM_KEY from CLI option, env, or prompt.

    Priority: CLI option > environment variable > interactive prompt
    """
    if cli_key:
        return cli_key

    env_key = __import__("os").environ.get("ANY_LLM_KEY")
    if env_key:
        click.echo("✅ Using ANY_LLM_KEY from environment variable")
        return env_key

    return click.prompt("Paste ANY_LLM_KEY (ANY.v1.<kid>.<fingerprint>-<base64_key>)", hide_input=True)


def _run_decryption(provider: str, any_llm_key: str) -> str:
    """Perform the decryption workflow and return decrypted API key."""
    # Parse ANY_LLM_KEY
    click.echo("🔍 Parsing ANY_LLM_KEY...")
    kid, fingerprint, private_key_base64 = parse_any_llm_key(any_llm_key)
    click.echo(f"✅ Key ID: {kid}")
    click.echo(f"✅ Fingerprint: {fingerprint}")

    # Load private key
    click.echo("🔑 Loading X25519 private key...")
    private_key = load_private_key(private_key_base64)
    click.echo("✅ Private key loaded")

    # Extract public key
    click.echo("🔑 Extracting public key...")
    public_key = extract_public_key(private_key)
    click.echo("✅ Public key extracted")

    # Create challenge
    challenge_data = create_challenge(public_key)

    # Solve challenge
    solved_challenge = solve_challenge(challenge_data["encrypted_challenge"], private_key)

    # Fetch provider key
    provider_key_data = fetch_provider_key(provider, public_key, solved_challenge)

    # Decrypt provider key
    decrypted_api_key = decrypt_provider_key_value(provider_key_data["encrypted_key"], private_key)

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
@click.option("--api-base-url", "api_base_url", help="API base URL to use (overrides default)")
@click.option("--any-llm-key", "any_llm_key", help="ANY_LLM_KEY string to use (skips prompt)")
def main(provider: str | None, api_base_url: str | None, any_llm_key: str | None) -> None:
    """Run the provider key decryption CLI.

    If `provider` is omitted, the command will prompt for it interactively.
    """
    try:
        # Resolve API base URL from CLI option or environment variable.
        # Priority: CLI option > ANY_API_BASE_URL env var
        api_base_url_env = os.environ.get("ANY_API_BASE_URL")
        if api_base_url is None and api_base_url_env:
            api_base_url = api_base_url_env

        if api_base_url:
            set_api_base_url(api_base_url)

        if provider is None:
            provider = click.prompt("Enter Provider name (e.g., openai, anthropic)")

        any_llm_key_resolved = _get_any_llm_key(any_llm_key)

        _run_decryption(provider, any_llm_key_resolved)

    except Exception as exc:  # pragma: no cover - top-level CLI error handling
        click.echo(f"❌ Error: {exc}")
        raise


if __name__ == "__main__":
    main()
