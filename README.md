# Provider Key Decrypter

Python package to decrypt provider API keys using X25519 sealed box encryption and challenge-response authentication with the ANY LLM backend.

## Installation

Install from PyPI:
```bash
pip install any-llm-platform-client
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
uv run any-llm <provider>
```

Or enter a shell environment:
```bash
uv sync
uv venv
source .venv/bin/activate  # or: .\.venv\Scripts\activate on Windows
any-llm <provider>
```

## Usage

### Command Line Interface

The CLI provides a unified interface for managing your any-llm platform:

```bash
# Get help
any-llm --help

# View available commands
any-llm project --help
any-llm key --help
any-llm budget --help
any-llm client --help
```

#### Authentication

Set credentials for management commands:

```bash
export ANY_LLM_USERNAME="your-email@example.com"
export ANY_LLM_PASSWORD="your-password"  # pragma: allowlist secret
export ANY_LLM_PLATFORM_URL="http://localhost:8000/api/v1"  # optional
```

#### Managing Projects

```bash
# List all projects
any-llm project list

# Create a new project
any-llm project create "My Project" --description "My project description"

# Show project details
any-llm project show <project-id>

# Update a project
any-llm project update <project-id> --name "Updated Name"

# Delete a project
any-llm project delete <project-id>
```

#### Managing Provider Keys

```bash
# List provider keys for a project
any-llm key list <project-id>

# Create a provider key
any-llm key create <project-id> openai <encrypted-key>

# Update a provider key
any-llm key update <provider-key-id> <encrypted-key>

# Archive a provider key (soft delete)
any-llm key delete <provider-key-id>

# Permanently delete a provider key
any-llm key delete <provider-key-id> --permanent

# Restore an archived key
any-llm key unarchive <provider-key-id>
```

#### Generating New Encryption Keys

Generate a new encryption key and automatically migrate provider keys:

```bash
# Generate new key and migrate from old key
any-llm key generate <project-id> --old-key "ANY.v1.<old-key>"

# Generate new key without migration (archives all provider keys)
any-llm key generate <project-id>

# Skip confirmation prompts (for automation)
any-llm key generate <project-id> --old-key "ANY.v1.<old-key>" --yes
```

This command will:
1. Generate a new X25519 keypair
2. Update the project's encryption key
3. Migrate all provider keys from the old key to the new key (if old key provided)
4. Display the new ANY_LLM_KEY (save it securely!)

**Important:** Save the generated `ANY_LLM_KEY` in a secure location. It cannot be recovered if lost!

**Migration Behavior:**
- **With old key:** Successfully decrypted provider keys are re-encrypted with the new key. Keys that fail to decrypt are archived.
- **Without old key:** All encrypted provider keys are archived. You'll need to re-enter them in the web interface.
- **Local providers** (e.g., Ollama with empty keys) are skipped during migration.

#### Decrypting Provider Keys

Decrypt a provider API key using your ANY_LLM_KEY:

```bash
# Set your ANY_LLM_KEY
export ANY_LLM_KEY='ANY.v1.<kid>.<fingerprint>-<base64_key>'

# Decrypt a provider key
any-llm key decrypt openai
any-llm key decrypt anthropic

# Or provide the key inline
any-llm --any-llm-key 'ANY.v1...' key decrypt openai
```

#### Managing Budgets

```bash
# List budgets for a project
any-llm budget list <project-id>

# Create a project budget
any-llm budget create <project-id> 100.00 --period monthly

# Show a specific budget
any-llm budget show <project-id> monthly

# Update a budget
any-llm budget update <project-id> monthly 200.00

# Delete a budget
any-llm budget delete <project-id> monthly
```

Budget periods: `daily`, `weekly`, `monthly`

#### Managing Clients

```bash
# List clients for a project
any-llm client list <project-id>

# Create a new client
any-llm client create <project-id> "My Client" --default

# Show client details
any-llm client show <project-id> <client-id>

# Update a client
any-llm client update <project-id> <client-id> --name "Updated Client"

# Set as default client
any-llm client set-default <project-id> <client-id>

# Delete a client
any-llm client delete <project-id> <client-id>
```

#### Output Formats

All commands support two output formats:
- `table` (default): Human-readable formatted output
- `json`: Machine-readable JSON output for scripting

```bash
# Get JSON output for scripting
any-llm --format json project list

# Example: Extract project ID
PROJECT_ID=$(any-llm --format json project create "New Project" | jq -r '.id')
```

### Configuring the API Base URL

By default, the client connects to `http://localhost:8000/api/v1`. To change this, instantiate `AnyLLMPlatformClient` with a custom `any_llm_platform_url` or set the attribute directly:

```python
from any_llm_platform_client.client import AnyLLMPlatformClient

# Create a client that talks to a different backend
client = AnyLLMPlatformClient(any_llm_platform_url="https://api.example.com/v1")

# Now calls on `client` will use the configured base URL
challenge_data = client.create_challenge(public_key)
```

Or set the `ANY_LLM_PLATFORM_URL` environment variable before running the CLI:

```bash
# Example: temporarily point CLI to a staging backend
export ANY_LLM_PLATFORM_URL="https://staging-api.example.com/v1"
any-llm key decrypt openai
```

### As a Python Library

#### Simple Usage (Recommended)

```python
from any_llm_platform_client import AnyLLMPlatformClient

# Create client
client = AnyLLMPlatformClient()

# Get decrypted provider key with metadata in one call
any_llm_key = "ANY.v1.12345678.abcdef01-YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3OA=="
result = client.get_decrypted_provider_key(any_llm_key, provider="openai")

# Access the decrypted API key and metadata
print(f"API Key: {result.api_key}")
print(f"Provider Key ID: {result.provider_key_id}")
print(f"Project ID: {result.project_id}")
print(f"Provider: {result.provider}")
print(f"Created At: {result.created_at}")
```

#### Advanced Usage (Manual Steps)

For more control over the authentication flow:

```python
from any_llm_platform_client import (
    parse_any_llm_key,
    load_private_key,
    extract_public_key,
)
from any_llm_platform_client.client import AnyLLMPlatformClient

# Parse the key
any_llm_key = "ANY.v1...."
key_components = parse_any_llm_key(any_llm_key)

# Load private key
private_key = load_private_key(key_components.base64_encoded_private_key)

# Extract public key
public_key = extract_public_key(private_key)

# Authenticate with challenge-response using the client
client = AnyLLMPlatformClient()
challenge_data = client.create_challenge(public_key)
solved_challenge = client.solve_challenge(challenge_data["encrypted_challenge"], private_key)

# Fetch and decrypt provider key
provider_key_data = client.fetch_provider_key("openai", public_key, solved_challenge)
api_key = client.decrypt_provider_key_value(provider_key_data["encrypted_key"], private_key)

print(f"API Key: {api_key}")
```

#### Async Usage

```python
import asyncio
from any_llm_platform_client import AnyLLMPlatformClient

async def main():
    client = AnyLLMPlatformClient()
    any_llm_key = "ANY.v1...."
    result = await client.aget_decrypted_provider_key(any_llm_key, provider="openai")
    print(f"API Key: {result.api_key}")
    print(f"Provider Key ID: {result.provider_key_id}")

asyncio.run(main())
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

You can generate a new ANY_LLM_KEY using:
- The CLI: `any-llm key generate <project-id>`
- The project page in the web UI

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
uv run pytest --cov=src/any_llm_platform_client
```

Run linting:
```bash
uv run pre-commit run --all-files
```
