# Provider Key Decrypter

Python script to decrypt provider API keys using X25519 sealed box encryption and challenge-response authentication.

## Usage

```bash
uv sync
export ANY_API_KEY='ANY.v2.<kid>.<fingerprint>-<base64_key>'
uv run decrypt_provider_key.py <project_id> <provider>
```

The script authenticates using your ANY_API_KEY (generated from the web UI), solves the encrypted challenge, and retrieves the decrypted provider API key. Requires PyNaCl for X25519 sealed box decryption.

To post dummy token usage events (after solving the challenge), use the following command:
```bash
uv run post_token_usage.py <project_id> <provider>
```
