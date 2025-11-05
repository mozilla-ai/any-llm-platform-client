#!/usr/bin/env python3
"""
Script to populate usage data with multiple events for testing the dashboard.
"""

import sys
import uuid
import requests
import random
from datetime import datetime, timedelta

from decrypt_provider_key import (
    parse_any_llm_key,
    load_private_key,
    extract_public_key,
    create_challenge,
    solve_challenge,
    API_BASE_URL
)


def get_provider_keys(public_key: str, solved_challenge: uuid.UUID) -> list:
    """Get all provider keys for the project."""
    print("📋 Fetching provider keys...")

    response = requests.get(
        f"{API_BASE_URL}/provider-keys/project/34418010-5860-4562-98b8-df34dfc0b4d3",
        headers={
            "Authorization": f"Bearer {public_key}",  # This won't work, we need JWT
        }
    )

    if response.status_code == 401:
        print("⚠️  Need JWT authentication to list provider keys")
        print("Let me try fetching individual providers...")
        return []

    return response.json().get('data', [])


def post_usage_event(
    provider_key_id: str,
    provider: str,
    public_key: str,
    solved_challenge: uuid.UUID,
    model: str,
    input_tokens: int,
    output_tokens: int,
) -> bool:
    """Post a single usage event."""

    event_id = str(uuid.uuid4())

    payload = {
        "provider_key_id": provider_key_id,
        "provider": provider,
        "model": model,
        "data": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "extra_metadata": {"test": "data"}
        },
        "id": event_id
    }

    response = requests.post(
        f"{API_BASE_URL}/usage-events/",
        json=payload,
        headers={
            "encryption-key": public_key,
            "X-Solved-Challenge": str(solved_challenge)
        }
    )

    if response.status_code == 204:
        print(f"✅ Posted: {provider}/{model} - {input_tokens + output_tokens} tokens")
        return True
    else:
        print(f"❌ Failed: {response.status_code} - {response.text}")
        return False


def main():
    any_llm_key = "ANY.v1.a457b979.4fa5956c-GPYu/6TZvBG9xj++fglLvtmVvBPSGBXaTA1U0UVrRV4="

    print("=" * 60)
    print("📊 Populating Usage Data")
    print("=" * 60)
    print()

    # Parse key
    print("🔍 Parsing ANY_LLM_KEY...")
    kid, fingerprint, private_key_base64 = parse_any_llm_key(any_llm_key)
    private_key = load_private_key(private_key_base64)
    public_key = extract_public_key(private_key)
    print("✅ Key loaded")
    print()

    # Test data: different providers and models
    test_configs = [
        {"provider": "openai", "model": "gpt-4", "input": 1500, "output": 800},
        {"provider": "openai", "model": "gpt-4", "input": 2000, "output": 1200},
        {"provider": "openai", "model": "gpt-3.5-turbo", "input": 500, "output": 300},
        {"provider": "openai", "model": "gpt-3.5-turbo", "input": 800, "output": 400},
        {"provider": "anthropic", "model": "claude-3-opus", "input": 1800, "output": 900},
        {"provider": "anthropic", "model": "claude-3-sonnet", "input": 1200, "output": 600},
        {"provider": "anthropic", "model": "claude-3-haiku", "input": 600, "output": 300},
        {"provider": "google", "model": "gemini-pro", "input": 1000, "output": 500},
        {"provider": "google", "model": "gemini-pro", "input": 1500, "output": 750},
    ]

    success_count = 0

    for i, config in enumerate(test_configs, 1):
        print(f"\n[{i}/{len(test_configs)}] Processing {config['provider']}/{config['model']}...")

        try:
            # Create challenge
            challenge_data = create_challenge(public_key)
            solved_challenge = solve_challenge(challenge_data['encrypted_challenge'], private_key)

            # Fetch provider key to get its ID
            response = requests.get(
                f"{API_BASE_URL}/provider-keys/{config['provider']}",
                headers={
                    "encryption-key": public_key,
                    "X-Solved-Challenge": str(solved_challenge)
                }
            )

            if response.status_code != 200:
                print(f"⚠️  Skipping {config['provider']} - provider key not found")
                continue

            provider_key_data = response.json()
            provider_key_id = provider_key_data['id']

            # Create new challenge for posting
            challenge_data = create_challenge(public_key)
            solved_challenge = solve_challenge(challenge_data['encrypted_challenge'], private_key)

            # Post usage event
            if post_usage_event(
                provider_key_id=provider_key_id,
                provider=config['provider'],
                public_key=public_key,
                solved_challenge=solved_challenge,
                model=config['model'],
                input_tokens=config['input'],
                output_tokens=config['output'],
            ):
                success_count += 1

        except Exception as e:
            print(f"❌ Error: {e}")
            continue

    print()
    print("=" * 60)
    print(f"🎉 Done! Successfully created {success_count}/{len(test_configs)} events")
    print("=" * 60)


if __name__ == "__main__":
    main()
