# Provider Key Decrypter

Python script to decrypt provider API keys using X25519 sealed box encryption and challenge-response authentication.

## Installation

Create a virtual environment and install dependencies
```bash
uv sync
```

## Usage

```bash
export ANY_LLM_KEY='ANY.v1.<kid>.<fingerprint>-<base64_key>'
uv run python decrypt_provider_key.py <provider>
```

Example:
```bash
uv run python decrypt_provider_key.py openai
```

## How It Works

1. The script extracts the X25519 private key from your ANY_LLM_KEY
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
