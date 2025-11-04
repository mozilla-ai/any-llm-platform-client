#!/usr/bin/env python3
"""Script to post token usage events.

Usage:
    python post_token_usage.py                    # Interactive mode (recommended)
    python post_token_usage.py <project_id> <provider>  # Direct mode

Example:
    python post_token_usage.py                    # Will prompt for ANY_API_KEY
    python post_token_usage.py 155c8a03-6906-4390-884c-785a2de8560d openai

The script expects ANY_API_KEY in the format:
    ANY.v1.<kid>.<fingerprint>-<base64_32byte_private_key>
"""

import sys
import uuid

import requests

# Import functions from the reference script
from decrypt_provider_key import (
    API_BASE_URL,
    create_challenge,
    extract_public_key,
    fetch_provider_key,
    get_any_llm_key,
    interactive_mode,
    load_private_key,
    parse_any_llm_key,
    solve_challenge,
)


def post_usage_event(
    provider_key_id: str,
    provider: str,
    public_key: str,
    solved_challenge: uuid.UUID,
    model: str = "gpt-4.1",
    input_tokens: int = 100,
    output_tokens: int = 1000,
    event_metadata: dict = None,
) -> None:
    """Post a usage event to the API."""
    print(f"📊 Posting usage event for {provider}...")

    if event_metadata is None:
        event_metadata = {"foo": "bar"}

    # Generate a random UUID for the event
    event_id = str(uuid.uuid4())

    payload = {
        "provider_key_id": provider_key_id,
        "provider": provider,
        "model": model,
        "data": {"input_tokens": input_tokens, "output_tokens": output_tokens, "metadata": event_metadata},
        "id": event_id,
    }

    print(f"📦 Payload: {payload}")

    response = requests.post(
        f"{API_BASE_URL}/usage-events/",
        json=payload,
        headers={"encryption-key": public_key, "X-Solved-Challenge": str(solved_challenge)},
    )

    if response.status_code != 204:
        print(f"❌ Error posting usage event: {response.status_code}")
        print(response.json())
        sys.exit(1)

    print("✅ Usage event posted successfully!")


def main() -> None:
    """Main entry point for posting token usage events to the API.

    Supports both interactive and direct modes:
    - Interactive: Prompts for provider name
    - Direct: Accepts project_id and provider as command-line arguments

    The script authenticates using challenge-response, fetches provider key details,
    then posts a usage event with token counts and metadata.
    """
    # Parse command line arguments
    if len(sys.argv) == 3:
        project_id = sys.argv[1]
        provider = sys.argv[2]
        interactive = False
    elif len(sys.argv) == 1:
        project_id = None
        provider = None
        interactive = True
    else:
        print("Usage:")
        print("  python post_token_usage.py                    # Interactive mode")
        print("  python post_token_usage.py <project_id> <provider>  # Direct mode")
        print("\nExample:")
        print("  python post_token_usage.py 123e4567-e89b-12d3-a456-426614174000 openai")
        sys.exit(1)

    print("=" * 60)
    print("📊 Token Usage Posting Script")
    print("=" * 60)

    if not interactive:
        print(f"Project ID: {project_id}")
        print(f"Provider: {provider}")

    print("=" * 60)
    print()

    try:
        # Get ANY_API_KEY
        any_api_key = get_any_llm_key()
        print()

        # Parse ANY_API_KEY
        print("🔍 Parsing ANY_API_KEY...")
        kid, fingerprint, private_key_base64 = parse_any_llm_key(any_api_key)
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

        # Get project and provider if interactive mode
        if interactive:
            provider = interactive_mode()
            print()

        # Step 1: Create challenge to GET provider key details (ID, name)
        challenge_data = create_challenge(public_key)
        print()

        # Step 2: Solve challenge
        solved_challenge = solve_challenge(challenge_data["encrypted_challenge"], private_key)
        print()

        # Step 3: Fetch provider key to get ID and provider
        provider_key_data = fetch_provider_key(provider, public_key, solved_challenge)
        print()

        # Extract provider key ID
        provider_key_id = provider_key_data.get("id")
        provider_name = provider_key_data.get("provider")

        print(f"📋 Provider Key ID: {provider_key_id}")
        print(f"📋 Provider: {provider_name}")
        print()

        # Step 4: Create second challenge for POST request
        challenge_data = create_challenge(public_key)
        print()

        # Step 5: Solve second challenge
        solved_challenge = solve_challenge(challenge_data["encrypted_challenge"], private_key)
        print()

        # Step 6: POST usage event
        post_usage_event(
            provider_key_id=provider_key_id,
            provider=provider_name,
            public_key=public_key,
            solved_challenge=solved_challenge,
            model="gpt-4.1",
            input_tokens=100,
            output_tokens=1000,
            event_metadata={"foo": "bar"},
        )
        print()

        # Display results
        print("=" * 60)
        print("🎉 SUCCESS!")
        print("=" * 60)

    except requests.RequestException as e:
        print(f"❌ Network error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
