#!/usr/bin/env python3
"""
Script to decrypt provider keys using the ANY_API_KEY format.

Installation:
    pip install -r requirements-decrypt.txt

Usage:
    python decrypt_provider_key.py                    # Interactive mode (recommended)
    python decrypt_provider_key.py <project_id> <provider>  # Direct mode

Example:
    python decrypt_provider_key.py                    # Will prompt for ANY_API_KEY
    python decrypt_provider_key.py 155c8a03-6906-4390-884c-785a2de8560d openai

The script expects ANY_API_KEY in the format:
    ANY.v2.<kid>.<fingerprint>-<base64_32byte_private_key>
"""

import sys
import base64
import uuid
import requests
import os

try:
    import nacl.public
except ImportError:
    print("❌ Error: Missing required Python packages")
    print("\nPlease install dependencies:")
    print("  pip install PyNaCl requests")
    sys.exit(1)


# Configuration
API_BASE_URL = "http://localhost:8000/api/v1"


def parse_any_api_key(any_api_key: str) -> tuple:
    """Parse ANY_API_KEY format and extract components.

    Format: ANY.v2.<kid>.<fingerprint>-<base64_32byte_private_key>

    Returns:
        tuple: (kid, fingerprint, base64_private_key)
    """
    import re

    match = re.match(r'^ANY\.v2\.([^.]+)\.([^-]+)-(.+)$', any_api_key)

    if not match:
        raise ValueError("Invalid ANY_API_KEY format. Expected: ANY.v2.<kid>.<fingerprint>-<base64_key>")

    kid, fingerprint, base64_private_key = match.groups()
    return kid, fingerprint, base64_private_key


def load_private_key(private_key_base64: str):
    """Load X25519 private key from base64 string."""
    private_key_bytes = base64.b64decode(private_key_base64)
    if len(private_key_bytes) != 32:
        raise ValueError(f"X25519 private key must be 32 bytes, got {len(private_key_bytes)}")
    return nacl.public.PrivateKey(private_key_bytes)


def extract_public_key(private_key) -> str:
    """Extract public key as base64 from X25519 private key."""
    public_key_bytes = bytes(private_key.public_key)
    return base64.b64encode(public_key_bytes).decode('utf-8')


def decrypt_data(encrypted_data_base64: str, private_key) -> str:
    """Decrypt data using X25519 sealed box.

    Format: ephemeral_public_key (32 bytes) + ciphertext (nonce derived internally)
    """
    encrypted_data = base64.b64decode(encrypted_data_base64)

    # Create sealed box with private key
    sealed_box = nacl.public.SealedBox(private_key)

    # Decrypt using sealed box
    decrypted_data = sealed_box.decrypt(encrypted_data)
    return decrypted_data.decode('utf-8')


def create_challenge(public_key: str) -> dict:
    """Step 1: Create an authentication challenge."""
    print("📝 Creating authentication challenge...")

    response = requests.post(
        f"{API_BASE_URL}/auth/",
        json={
            "encryption_key": public_key,
            "key_type": "RSA"  # Backend auto-detects X25519, this is just for tracking
        }
    )

    if response.status_code != 200:
        print(f"❌ Error creating challenge: {response.status_code}")
        print(response.json())

        if "No user found" in str(response.json()):
            print("\n⚠️  The public key from your ANY_API_KEY doesn't match any user.")
            print("Solution: Go to Settings → ANY_API_KEY tab and generate a new key.")
        sys.exit(1)

    data = response.json()
    print(f"✅ Challenge created")
    return data


def solve_challenge(encrypted_challenge: str, private_key) -> uuid.UUID:
    """Step 2: Decrypt the challenge to get the UUID."""
    print("🔐 Decrypting challenge...")

    decrypted_uuid_str = decrypt_data(encrypted_challenge, private_key)
    solved_challenge = uuid.UUID(decrypted_uuid_str)

    print(f"✅ Challenge solved: {solved_challenge}")
    return solved_challenge


def fetch_provider_key(
    project_id: str,
    provider: str,
    public_key: str,
    solved_challenge: uuid.UUID
) -> dict:
    """Step 3: Fetch the provider key using the solved challenge."""
    print(f"🔑 Fetching provider key for {provider}...")

    # Base64-encode the key for HTTP header
    encryption_key_base64 = base64.b64encode(public_key.encode()).decode()

    response = requests.get(
        f"{API_BASE_URL}/provider-keys/{project_id}/{provider}",
        headers={
            "encryption-key": encryption_key_base64,
            "X-Solved-Challenge": str(solved_challenge)
        }
    )

    if response.status_code != 200:
        print(f"❌ Error fetching provider key: {response.status_code}")
        print(response.json())
        sys.exit(1)

    data = response.json()
    print(f"✅ Provider key fetched")
    return data


def decrypt_provider_key_value(encrypted_key: str, private_key) -> str:
    """Step 4: Decrypt the actual provider API key."""
    print("🔓 Decrypting provider API key...")

    decrypted_key = decrypt_data(encrypted_key, private_key)
    print(f"✅ Decrypted successfully!")
    return decrypted_key


def get_any_api_key() -> str:
    """Get ANY_API_KEY from environment variable or prompt user."""
    any_api_key = os.getenv('ANY_API_KEY')

    if any_api_key:
        print("✅ Using ANY_API_KEY from environment variable")
        return any_api_key

    print("\n🔑 ANY_API_KEY Required")
    print("=" * 60)
    print("Please paste your ANY_API_KEY (generated from the web UI)")
    print("Format: ANY.v2.<kid>.<fingerprint>-<base64_key>")
    print()
    print("💡 TIP: Set as environment variable:")
    print("   export ANY_API_KEY='your-key-here'")
    print()

    try:
        any_api_key = input("Paste key and press Enter: ").strip()
        if not any_api_key:
            print("❌ ANY_API_KEY is required")
            sys.exit(1)
        return any_api_key
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
        sys.exit(0)


def interactive_mode():
    """Interactive mode - asks for project ID and provider."""
    print("\n🔐 Interactive Mode")
    print("=" * 60)
    print("💡 Find project IDs and providers in the web UI")
    print()

    try:
        project_id = input("Enter Project ID (UUID): ").strip()
        if not project_id:
            print("❌ Project ID is required")
            sys.exit(1)

        try:
            uuid.UUID(project_id)
        except ValueError:
            print("❌ Invalid UUID format")
            sys.exit(1)

        provider = input("Enter Provider name (e.g., openai, anthropic): ").strip()
        if not provider:
            print("❌ Provider name is required")
            sys.exit(1)

        return project_id, provider

    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
        sys.exit(0)


def main():
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
        print("  python decrypt_provider_key.py                    # Interactive mode")
        print("  python decrypt_provider_key.py <project_id> <provider>  # Direct mode")
        print("\nExample:")
        print("  python decrypt_provider_key.py 123e4567-e89b-12d3-a456-426614174000 openai")
        sys.exit(1)

    print("=" * 60)
    print("🔐 Provider Key Decryption Script")
    print("=" * 60)

    if not interactive:
        print(f"Project ID: {project_id}")
        print(f"Provider: {provider}")

    print("=" * 60)
    print()

    try:
        # Get ANY_API_KEY
        any_api_key = get_any_api_key()
        print()

        # Parse ANY_API_KEY
        print("🔍 Parsing ANY_API_KEY...")
        kid, fingerprint, private_key_base64 = parse_any_api_key(any_api_key)
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
            project_id, provider = interactive_mode()
            print()

        # Step 1: Create challenge
        challenge_data = create_challenge(public_key)
        print()

        # Step 2: Solve challenge
        solved_challenge = solve_challenge(
            challenge_data['encrypted_challenge'],
            private_key
        )
        print()

        # Step 3: Fetch provider key (encrypted)
        provider_key_data = fetch_provider_key(
            project_id,
            provider,
            public_key,
            solved_challenge
        )
        print()

        # Step 4: Decrypt the provider key
        decrypted_api_key = decrypt_provider_key_value(
            provider_key_data['encrypted_key'],
            private_key
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
        print(f"🔑 Decrypted API Key:")
        print(f"   {decrypted_api_key}")
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
