# CLI Usage Guide

Comprehensive guide to using the `any-llm` command-line interface.

## Installation

```bash
# From PyPI
pip install any-llm-platform-client

# From source (development)
git clone https://github.com/mozilla-ai/any-api-decrypter-cli
cd any-api-decrypter-cli
uv sync --dev
uv run any-llm --help
```

## Authentication

### Environment Variables

Set credentials for management commands:

```bash
export ANY_LLM_USERNAME="your-email@example.com"
export ANY_LLM_PASSWORD="your-password"  # pragma: allowlist secret
export ANY_LLM_PLATFORM_URL="http://localhost:8000/api/v1"  # optional

# For decryption operations
export ANY_LLM_KEY='ANY.v1.<kid>.<fingerprint>-<base64_key>'
```

### Command-Line Options

```bash
# Pass credentials as options
any-llm --username user@example.com --password mypass project list

# Pass API URL
any-llm --any-llm-platform-url http://localhost:8100/api/v1 project list
```

## Command Structure

```bash
any-llm [OPTIONS] COMMAND [ARGS]...

Commands:
  project  Manage projects
  key      Manage provider keys and decrypt API keys
  budget   Manage project budgets
  client   Manage project clients
```

## Project Management

### List Projects

```bash
any-llm project list [--skip N] [--limit N]

# Examples
any-llm project list
any-llm project list --skip 10 --limit 20
any-llm --format json project list | jq '.data[].name'
```

### Create Project

```bash
any-llm project create <name> [--description TEXT]

# Examples
any-llm project create "ML Research"
any-llm project create "ML Research" --description "Machine learning experiments"

# Capture project ID for automation
PROJECT_ID=$(any-llm --format json project create "New Project" | jq -r '.id')
```

### Show Project

```bash
any-llm project show <project-id>

# Example
any-llm project show abc123-def456-789
```

### Update Project

```bash
any-llm project update <project-id> [--name TEXT] [--description TEXT]

# Examples
any-llm project update abc123 --name "Updated Name"
any-llm project update abc123 --description "New description"
any-llm project update abc123 --name "New Name" --description "New desc"
```

### Delete Project

```bash
any-llm project delete <project-id> [--yes]

# Examples
any-llm project delete abc123  # Prompts for confirmation
any-llm project delete abc123 --yes  # Skips confirmation
```

## Provider Key Management

### List Provider Keys

```bash
any-llm key list <project-id> [--include-archived]

# Examples
any-llm key list abc123
any-llm key list abc123 --include-archived
```

### Create Provider Key

```bash
any-llm key create <project-id> <provider-name> <encrypted-key>

# Examples
any-llm key create abc123 "openai" "base64_encrypted_key_here"
any-llm key create abc123 "anthropic" "base64_encrypted_key_here"

# For local providers (no API key needed)
any-llm key create abc123 "ollama" ""
```

**Supported providers**: openai, anthropic, ollama, and others

### Update Provider Key

```bash
any-llm key update <provider-key-id> <encrypted-key>

# Example
any-llm key update key123 "new_encrypted_key_base64"
```

### Delete Provider Key

```bash
any-llm key delete <provider-key-id> [--permanent]

# Archive (soft delete) - preserves events and budgets
any-llm key delete key123

# Permanent delete - removes all associated data
any-llm key delete key123 --permanent
```

### Unarchive Provider Key

```bash
any-llm key unarchive <provider-key-id>

# Example
any-llm key unarchive key123
```

### Generate New Encryption Key

Generate a new X25519 keypair and rotate provider keys:

```bash
any-llm key generate <project-id> [--old-key TEXT] [--yes]

# With migration (decrypt old, re-encrypt with new)
any-llm key generate abc123 --old-key "ANY.v1.kid.fp-base64key"

# Without migration (archives all existing keys)
any-llm key generate abc123

# Skip confirmation prompts
any-llm key generate abc123 --old-key "ANY.v1..." --yes
```

**Migration behavior:**
- **With old key**: Decrypts and re-encrypts provider keys
  - Successfully migrated keys remain active
  - Failed decryptions result in archived keys
  - Local providers (empty keys) are skipped
- **Without old key**: Archives all encrypted provider keys
  - You'll need to re-enter them in the web interface

**Important**: Save the generated `ANY_LLM_KEY` securely! It cannot be recovered if lost.

### Decrypt Provider Key

Decrypt a provider API key using your ANY_LLM_KEY:

```bash
# Set your ANY_LLM_KEY environment variable
export ANY_LLM_KEY='ANY.v1.<kid>.<fingerprint>-<base64_key>'

# Decrypt provider keys
any-llm key decrypt openai
any-llm key decrypt anthropic

# Or pass key inline
any-llm --any-llm-key 'ANY.v1...' key decrypt openai
```

## Budget Management

### Budget Periods

All budgets support three time periods:
- `daily`: Resets daily at midnight UTC
- `weekly`: Resets weekly on Sunday midnight UTC
- `monthly`: Resets monthly on the 1st at midnight UTC

### List Budgets

```bash
any-llm budget list <project-id>

# Example
any-llm budget list abc123
```

### Create Budget

```bash
any-llm budget create <project-id> <budget-limit> [--period PERIOD]

# Examples
any-llm budget create abc123 100.00 --period monthly
any-llm budget create abc123 20.00 --period daily
any-llm budget create abc123 50.00 --period weekly
```

### Show Budget

```bash
any-llm budget show <project-id> <period>

# Examples
any-llm budget show abc123 monthly
any-llm budget show abc123 daily
```

### Update Budget

```bash
any-llm budget update <project-id> <period> <budget-limit>

# Example
any-llm budget update abc123 monthly 200.00
```

### Delete Budget

```bash
any-llm budget delete <project-id> <period>

# Example
any-llm budget delete abc123 monthly
```

## Client Management

Clients represent different consumers or applications using your project's provider keys.

### List Clients

```bash
any-llm client list <project-id> [--skip N] [--limit N]

# Examples
any-llm client list abc123
any-llm client list abc123 --limit 50
```

### Create Client

```bash
any-llm client create <project-id> <name> [--default]

# Examples
any-llm client create abc123 "Web App"
any-llm client create abc123 "Mobile App" --default

# Capture client ID
CLIENT_ID=$(any-llm --format json client create abc123 "CLI Tool" | jq -r '.id')
```

### Show Client

```bash
any-llm client show <project-id> <client-id>

# Example
any-llm client show abc123 client456
```

### Update Client

```bash
any-llm client update <project-id> <client-id> [--name TEXT] [--default/--no-default]

# Examples
any-llm client update abc123 client456 --name "Updated Name"
any-llm client update abc123 client456 --default
any-llm client update abc123 client456 --no-default
```

### Set Default Client

```bash
any-llm client set-default <project-id> <client-id>

# Example
any-llm client set-default abc123 client456
```

### Delete Client

```bash
any-llm client delete <project-id> <client-id>

# Example
any-llm client delete abc123 client456
```

## Output Formats

All commands support multiple output formats:

### Table Format (Default)

Human-readable formatted output (JSON pretty-printed):

```bash
any-llm project list
```

### JSON Format

Machine-readable JSON output for scripting:

```bash
any-llm --format json project list

# Examples with jq
any-llm --format json project list | jq '.data[].name'
any-llm --format json project show abc123 | jq '.id, .name'
PROJECT_ID=$(any-llm --format json project create "Test" | jq -r '.id')
```

### YAML Format

YAML output for configuration files:

```bash
any-llm --format yaml project list
any-llm --format yaml project show abc123
```

## Complete Workflow Examples

### End-to-End Project Setup

```bash
# 1. Create a project
PROJECT_ID=$(any-llm --format json project create "AI Research" \
  --description "Research project" | jq -r '.id')

# 2. Generate encryption key
any-llm key generate "$PROJECT_ID"
# Save the ANY_LLM_KEY output securely!
export ANY_LLM_KEY='ANY.v1....'

# 3. Add provider keys (encrypted in web UI first)
OPENAI_KEY_ID=$(any-llm --format json key create "$PROJECT_ID" \
  "openai" "encrypted_key_here" | jq -r '.id')

# 4. Set budgets
any-llm budget create "$PROJECT_ID" 20.00 --period daily
any-llm budget create "$PROJECT_ID" 100.00 --period weekly
any-llm budget create "$PROJECT_ID" 500.00 --period monthly

# 5. Create clients
WEB_CLIENT=$(any-llm --format json client create "$PROJECT_ID" \
  "Web App" --default | jq -r '.id')
CLI_CLIENT=$(any-llm --format json client create "$PROJECT_ID" \
  "CLI Tool" | jq -r '.id')

# 6. View setup
any-llm project show "$PROJECT_ID"
any-llm key list "$PROJECT_ID"
any-llm budget list "$PROJECT_ID"
any-llm client list "$PROJECT_ID"
```

### Key Rotation with Migration

```bash
# Rotate encryption key and migrate provider keys
any-llm key generate "$PROJECT_ID" \
  --old-key "$OLD_ANY_LLM_KEY" \
  --yes

# Update environment variable with new key
export ANY_LLM_KEY='ANY.v1....'  # New key from output

# Verify provider keys still work
any-llm key decrypt openai
```

### Budget Monitoring

```bash
# Check current spend across all periods
any-llm budget show "$PROJECT_ID" daily
any-llm budget show "$PROJECT_ID" weekly
any-llm budget show "$PROJECT_ID" monthly

# Update if nearing limit
any-llm budget update "$PROJECT_ID" monthly 1000.00
```

### Cleanup

```bash
# Archive a provider key (preserves data)
any-llm key delete "$PROVIDER_KEY_ID"

# Restore if needed
any-llm key unarchive "$PROVIDER_KEY_ID"

# Delete project (removes everything)
any-llm project delete "$PROJECT_ID" --yes
```

## Error Handling

### Authentication Errors

```bash
# Missing credentials
any-llm project list
# Error: Username and password required

# Solution: Set environment variables or use options
export ANY_LLM_USERNAME="user@example.com"
export ANY_LLM_PASSWORD="password"  # pragma: allowlist secret
```

### Connection Errors

```bash
# Check if backend is running
curl http://localhost:8100/api/v1/

# Verify API URL
echo $ANY_LLM_PLATFORM_URL

# Set correct URL
export ANY_LLM_PLATFORM_URL="http://localhost:8100/api/v1"
```

### Decryption Errors

```bash
# Invalid ANY_LLM_KEY format
any-llm key decrypt openai
# Error: Invalid ANY_LLM_KEY format

# Solution: Check key format
export ANY_LLM_KEY='ANY.v1.<kid>.<fingerprint>-<base64_key>'
```

## Tips and Tricks

### Bash Aliases

```bash
# Add to ~/.bashrc or ~/.zshrc
alias llm='any-llm'
alias llm-json='any-llm --format json'

# Usage
llm project list
llm-json project list | jq '.data[].name'
```

### JSON Processing with jq

```bash
# Extract specific fields
any-llm --format json project list | jq '.data[] | {id, name}'

# Filter by name
any-llm --format json project list | jq '.data[] | select(.name | contains("Research"))'

# Count projects
any-llm --format json project list | jq '.data | length'
```

### Automation Scripts

```bash
#!/bin/bash
set -e

# Setup script
PROJECT_NAME="${1:-My Project}"

echo "Creating project: $PROJECT_NAME"
PROJECT_ID=$(any-llm --format json project create "$PROJECT_NAME" | jq -r '.id')

echo "Setting up budgets..."
any-llm budget create "$PROJECT_ID" 100.00 --period monthly

echo "Creating default client..."
any-llm client create "$PROJECT_ID" "Default" --default

echo "Project ID: $PROJECT_ID"
```

## Environment Variables Reference

| Variable | Purpose | Default |
|----------|---------|---------|
| `ANY_LLM_USERNAME` | Username for auth | (required) |
| `ANY_LLM_PASSWORD` | Password for auth | (required) |
| `ANY_LLM_PLATFORM_URL` | API base URL | `http://localhost:8000/api/v1` |
| `ANY_LLM_KEY` | Encryption key | (required for decrypt) |

## Getting Help

```bash
# General help
any-llm --help

# Command-specific help
any-llm project --help
any-llm key --help
any-llm budget --help
any-llm client --help

# Subcommand help
any-llm key generate --help
any-llm budget create --help
```

## Troubleshooting

For issues or questions, visit: https://github.com/mozilla-ai/any-api-decrypter-cli/issues
