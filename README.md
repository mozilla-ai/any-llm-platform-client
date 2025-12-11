# Provider Key Decrypter

Python package to decrypt provider API keys using X25519 sealed box encryption and challenge-response authentication with the ANY LLM backend.

## Installation

Install from PyPI:
```bash
pip install any-llm-crypto
```

Or install from source:
```bash
git clone https://github.com/mozilla-ai/any-api-decrypter-cli
cd any-api-decrypter-cli
pip install -e .
```

### Development

For development mode using `uv`:
```bash
git clone https://github.com/mozilla-ai/any-api-decrypter-cli
cd any-api-decrypter-cli
uv sync --dev
uv run pre-commit install
uv run any-llm-crypto <provider>
```

Or enter a shell environment:
```bash
uv sync
uv venv
source .venv/bin/activate  # or: .\.venv\Scripts\activate on Windows
any-llm-crypto <provider>
```

## Usage

### Command Line Interface

Interactive mode (prompts for provider):
```bash
export ANY_LLM_KEY='ANY.v1.<kid>.<fingerprint>-<base64_key>'
any-llm-crypto
```

Direct mode (specify provider as argument):
```bash
any-llm-crypto openai
```

### Configuring the API Base URL

By default, the client connects to `http://localhost:8000/api/v1`. To change this, instantiate `AnyLLMCryptoClient` with a custom `any_llm_platform_url` or call `set_any_llm_platform_url` on the client instance:

```python
from any_llm_crypto.client import AnyLLMCryptoClient

# Create a client that talks to a different backend
client = AnyLLMCryptoClient(any_llm_platform_url="https://api.example.com/v1")

# Now calls on `client` will use the configured base URL
challenge_data = client.create_challenge(public_key)
```

Or set the environment variable before running the CLI. The CLI will use the
first defined of `--api-base-url` or `ANY_LLM_PLATFORM_URL`.

```bash
# Example: temporarily point CLI to a staging backend
export ANY_LLM_PLATFORM_URL="https://staging-api.example.com/v1"
any-llm-crypto openai
```

### As a Python Library

```python
from any_llm_crypto import (
    parse_any_llm_key,
    load_private_key,
    extract_public_key,
    decrypt_data,
)
from any_llm_crypto.client import AnyLLMCryptoClient

# Parse the key
any_llm_key = "ANY.v1...."
key_id, fingerprint, private_key_base64 = parse_any_llm_key(any_llm_key)

# Load private key
private_key = load_private_key(private_key_base64)

# Extract public key
public_key = extract_public_key(private_key)

# Authenticate with challenge-response using the client
client = AnyLLMCryptoClient()
# challenge/solve (logging controls visibility)
challenge_data = client.create_challenge(public_key)
solved_challenge = client.solve_challenge(challenge_data["encrypted_challenge"], private_key)

# Fetch and decrypt provider key
provider_key_data = client.fetch_provider_key("openai", public_key, solved_challenge)
api_key = client.decrypt_provider_key_value(provider_key_data["encrypted_key"], private_key)

print(f"API Key: {api_key}")
```

## How It Works

1. The script/library extracts the X25519 private key from your ANY_LLM_KEY
2. Derives the public key and sends it to create an authentication challenge
3. The backend returns an encrypted challenge
4. Decrypts the challenge UUID using your private key
5. Uses the solved challenge to authenticate and fetch the encrypted provider key
6. Decrypts the provider API key using your private key

## Requirements

- Python 3.11+
- PyNaCl (for X25519 sealed box encryption/decryption)
- requests (for API calls)

## ANY_LLM_KEY Format

```
ANY.v1.<kid>.<fingerprint>-<base64_32byte_private_key>
```

Generate your ANY_LLM_KEY from the project page in the web UI.

## Security Notes

- The private key from your ANY_LLM_KEY is highly sensitive and should never be logged or transmitted over insecure channels
- This package uses X25519 sealed box encryption with XChaCha20-Poly1305 for strong cryptographic guarantees

## Development

Run tests:
```bash
uv run pytest
```

Run tests with coverage:
```bash
uv run pytest --cov=src/any_llm_crypto
```

Run linting:
```bash
uv run pre-commit run --all-files
```
