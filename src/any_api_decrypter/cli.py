"""Command-line interface for the provider key decrypter."""

import os
import sys
import traceback

import requests

from .client import (
    create_challenge,
    decrypt_provider_key_value,
    fetch_provider_key,
    solve_challenge,
)
from .crypto import extract_public_key, load_private_key, parse_any_llm_key


def get_any_llm_key() -> str:
    """Get ANY_LLM_KEY from environment variable or prompt user.

    Returns:
        str: The ANY_LLM_KEY string.

    Raises:
        SystemExit: If the key is not provided or user cancels.
    """
    any_llm_key = os.getenv("ANY_LLM_KEY")

    if any_llm_key:
        print("✅ Using ANY_LLM_KEY from environment variable")
        return any_llm_key

    print("\n🔑 ANY_LLM_KEY Required")
    print("=" * 60)
    print("Please paste your ANY_LLM_KEY (generated from the project page)")
    print("Format: ANY.v1.<kid>.<fingerprint>-<base64_key>")
    print()
    print("💡 TIP: Set as environment variable:")
    print("   export ANY_LLM_KEY='your-key-here'")
    print()

    try:
        any_llm_key = input("Paste key and press Enter: ").strip()
        if not any_llm_key:
            print("❌ ANY_LLM_KEY is required")
            sys.exit(1)
        return any_llm_key
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
        sys.exit(0)


def interactive_mode() -> str:
    """Interactive mode - asks for provider only.

    Returns:
        str: The provider name entered by the user.

    Raises:
        SystemExit: If user cancels or no provider is entered.
    """
    print("\n🔐 Interactive Mode")
    print("=" * 60)
    print("💡 Find provider names in the web UI")
    print()

    try:
        provider = input("Enter Provider name (e.g., openai, anthropic): ").strip()
        if not provider:
            print("❌ Provider name is required")
            sys.exit(1)

        return provider

    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
        sys.exit(0)


def decrypt_provider_key(provider: str) -> str:
    """Decrypt a provider key for the given provider.

    This is the main logic that can be used programmatically or from the CLI.

    Args:
        provider: Provider name (e.g., "openai", "anthropic").

    Returns:
        str: The decrypted provider API key.

    Raises:
        SystemExit: If any step fails.
        Exception: If decryption or API communication fails.
    """
    try:
        # Get ANY_LLM_KEY
        any_llm_key = get_any_llm_key()
        print()

        # Parse ANY_LLM_KEY
        print("🔍 Parsing ANY_LLM_KEY...")
        kid, fingerprint, private_key_base64 = parse_any_llm_key(any_llm_key)
        print(f"✅ Key ID: {kid}")
        print(f"✅ Fingerprint: {fingerprint}")
        print()

        # Load private key
        print("🔑 Loading X25519 private key...")
        private_key = load_private_key(private_key_base64)
        print("✅ Private key loaded")
        print()

        # Extract public key
        print("🔑 Extracting public key...")
        public_key = extract_public_key(private_key)
        print("✅ Public key extracted")
        print()

        # Step 1: Create challenge
        challenge_data = create_challenge(public_key)
        print()

        # Step 2: Solve challenge
        solved_challenge = solve_challenge(challenge_data["encrypted_challenge"], private_key)
        print()

        # Step 3: Fetch provider key (encrypted)
        provider_key_data = fetch_provider_key(provider, public_key, solved_challenge)
        print()

        # Step 4: Decrypt the provider key
        decrypted_api_key = decrypt_provider_key_value(
            provider_key_data["encrypted_key"], private_key
        )
        print()

        # Display results
        print("=" * 60)
        print("🎉 SUCCESS!")
        print("=" * 60)
        print(f"Provider: {provider_key_data['provider']}")
        print(f"Project ID: {provider_key_data['project_id']}")
        print(f"Created: {provider_key_data['created_at']}")
        print()
        print("🔑 Decrypted API Key:")
        print(f"   {decrypted_api_key}")
        print("=" * 60)

        return decrypted_api_key

    except requests.RequestException as e:
        print(f"❌ Network error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        traceback.print_exc()
        sys.exit(1)


def main() -> None:
    """Main entry point for the provider key decryption script.

    Supports both interactive and direct modes:
    - Interactive: Prompts for provider name
    - Direct: Accepts provider as command-line argument
    """
    # Parse command line arguments
    if len(sys.argv) == 2:
        provider = sys.argv[1]
        interactive = False
    elif len(sys.argv) == 1:
        provider = None
        interactive = True
    else:
        print("Usage:")
        print("  any-api-decrypter             # Interactive mode")
        print("  any-api-decrypter <provider>  # Direct mode")
        print("\nExample:")
        print("  any-api-decrypter openai")
        sys.exit(1)

    print("=" * 60)
    print("🔐 Provider Key Decryption")
    print("=" * 60)

    if not interactive:
        print(f"Provider: {provider}")

    print("=" * 60)
    print()

    # Get provider if interactive mode
    if interactive:
        provider = interactive_mode()
        print()

    # Run decryption
    decrypt_provider_key(provider)


if __name__ == "__main__":
    main()
