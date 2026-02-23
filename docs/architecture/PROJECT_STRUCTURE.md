# Project Structure

This document describes the code organization and module responsibilities.

## Directory Layout

```
any-api-decrypter-cli/
├── src/any_llm_platform_client/     # Main package source
│   ├── __init__.py                   # Public API exports
│   ├── cli.py                        # Click-based CLI
│   ├── client.py                     # Core decryption client
│   ├── client_management.py          # Management API (CRUD operations)
│   ├── crypto.py                     # X25519 cryptography
│   └── exceptions.py                 # Custom exceptions
├── tests/                            # Test suite
│   ├── conftest.py                   # Pytest fixtures
│   ├── test_basic.py                 # Basic import tests
│   ├── test_cli.py                   # CLI command tests
│   ├── test_cli_integration.py       # Integration tests
│   └── test_client.py                # Client library tests
├── docs/                             # Documentation
│   ├── DEVELOPMENT.md                # Build, test, lint guide
│   ├── CODE_STYLE.md                 # Style conventions
│   ├── CLI_USAGE.md                  # CLI reference
│   └── architecture/                 # Architecture docs
│       ├── CRYPTOGRAPHY.md           # Crypto design
│       └── PROJECT_STRUCTURE.md      # This file
├── .github/workflows/                # CI/CD configuration
├── pyproject.toml                    # Package configuration
├── ruff.toml                         # Linter configuration
├── .pre-commit-config.yaml           # Pre-commit hooks
├── AGENTS.md                         # Agent development guide (map)
└── README.md                         # User-facing documentation
```

## Module Responsibilities

### `cli.py` - Command-Line Interface

**Purpose**: Click-based CLI for all user-facing commands

**Key Components**:
- `main()`: Entry point for `any-llm` command
- Command groups: `project`, `key`, `budget`, `client`
- Output formatters: table (JSON pretty-print), JSON, YAML
- Authentication helpers

**Dependencies**:
- `click`: CLI framework
- `rich`: Terminal formatting (tables, colors)
- `client.py`: API client
- `client_management.py`: Management operations
- `crypto.py`: Key generation, encryption

**Key Functions**:
- `get_authenticated_client()`: Creates authenticated API client
- Output formatting: `_format_output()`, `_format_table()`
- Date formatting: `_format_date()`

### `client.py` - Core Decryption Client

**Purpose**: Main API client for challenge-response authentication and provider key decryption

**Key Classes**:
- `AnyLLMPlatformClient`: Main client class (inherits `ManagementMixin`)
- `DecryptedProviderKey`: Dataclass for decrypted key + metadata
- `KeyRotationResult`: Result of rotating a single provider key
- `KeyRotationSummary`: Summary of key rotation operation

**Key Methods**:
- `get_decrypted_provider_key()`: High-level convenience method (recommended)
- `create_challenge()`: Request authentication challenge
- `solve_challenge()`: Decrypt challenge with private key
- `fetch_provider_key()`: Retrieve encrypted provider key
- `decrypt_provider_key_value()`: Decrypt provider key
- Async variants: `aget_decrypted_provider_key()`, etc.

**Dependencies**:
- `httpx`: HTTP client (sync + async)
- `crypto.py`: Cryptographic operations
- `client_management.py`: Management mixin

### `client_management.py` - Management API

**Purpose**: Mixin class providing CRUD operations for projects, keys, budgets, clients

**Pattern**: Mixin design - mixed into `AnyLLMPlatformClient`

**Key Features**:
- **Authentication**: `login()`, token refresh
- **Projects**: create, read, update, delete
- **Provider Keys**: create, read, update, delete, archive, unarchive
- **Budgets**: create, read, update, delete (daily/weekly/monthly)
- **Clients**: create, read, update, delete, set default
- **Key Generation**: generate new encryption keys, rotate provider keys

**Authentication**:
- JWT-based with automatic token refresh
- Access token + refresh token
- Tokens stored in memory (not persisted)

**Dependencies**:
- `httpx`: HTTP client
- `crypto.py`: Key generation

### `crypto.py` - Cryptography Utilities

**Purpose**: X25519 key handling and sealed box operations

**Key Components**:
- `KeyComponents`: NamedTuple for parsed ANY_LLM_KEY
- `parse_any_llm_key()`: Parse key format
- `load_private_key()`: Load X25519 private key from base64
- `extract_public_key()`: Derive public key from private key
- `encrypt_data()`: Encrypt with sealed box (X25519 + XChaCha20-Poly1305)
- `decrypt_data()`: Decrypt sealed box
- `generate_keypair()`: Generate new X25519 keypair
- `format_any_llm_key()`: Format keypair as ANY_LLM_KEY string

**Cryptographic Stack**:
- **Key Exchange**: X25519 (Curve25519 ECDH)
- **Encryption**: XChaCha20-Poly1305 (AEAD)
- **Library**: PyNaCl (libsodium bindings)

**Key Format**:
```
ANY.v1.<key_id>.<fingerprint>-<base64_private_key>
```

**Dependencies**:
- `nacl.public`: X25519 operations
- `nacl.bindings`: Low-level crypto functions

### `exceptions.py` - Custom Exceptions

**Purpose**: Domain-specific exception types

**Classes**:
- `ChallengeCreationError`: Authentication challenge creation failed
- `ProviderKeyFetchError`: Provider key retrieval failed
- `AuthenticationError`: Login/authentication failed (in `client_management.py`)

**Usage Pattern**:
```python
try:
    challenge = client.create_challenge(public_key)
except ChallengeCreationError as e:
    logger.error("Challenge failed: %s", e)
    # Handle error
```

## Design Patterns

### Mixin Pattern

`AnyLLMPlatformClient` inherits from `ManagementMixin`:

```python
class ManagementMixin:
    """Provides CRUD operations"""
    def login(self, username: str, password: str) -> None: ...
    def create_project(self, name: str, description: str | None) -> dict: ...

class AnyLLMPlatformClient(ManagementMixin):
    """Core client + management operations"""
    def get_decrypted_provider_key(self, any_llm_key: str, provider: str): ...
```

**Benefits**:
- Separation of concerns
- Core decryption logic separate from management API
- Easy to extend with additional mixins

### Dataclass Pattern

Used for structured data:

```python
@dataclass
class DecryptedProviderKey:
    api_key: str
    provider_key_id: uuid.UUID
    project_id: uuid.UUID
    provider: str
    created_at: datetime
    updated_at: datetime | None = None
```

**Benefits**:
- Type safety
- Automatic `__init__`, `__repr__`, `__eq__`
- Clear data structure

### NamedTuple Pattern

Used for immutable data:

```python
class KeyComponents(NamedTuple):
    key_id: str
    public_key_fingerprint: str
    base64_encoded_private_key: str
```

**Benefits**:
- Immutable
- Lightweight
- Type-safe tuple unpacking

## API Layers

### Layer 1: Cryptography (`crypto.py`)
- Pure cryptographic operations
- No network calls
- No state

### Layer 2: Core Client (`client.py`)
- Challenge-response authentication
- Provider key decryption
- Stateless (except HTTP client connection pooling)

### Layer 3: Management API (`client_management.py`)
- CRUD operations
- Stateful (authentication tokens)
- Depends on Layer 2 for client infrastructure

### Layer 4: CLI (`cli.py`)
- User interface
- Output formatting
- Depends on Layers 2 & 3

## Data Flow

### Decryption Flow

```
User Input (ANY_LLM_KEY)
    ↓
parse_any_llm_key() → KeyComponents
    ↓
load_private_key() → PrivateKey
    ↓
extract_public_key() → PublicKey
    ↓
create_challenge(PublicKey) → encrypted_challenge
    ↓
decrypt_data(encrypted_challenge, PrivateKey) → challenge_uuid
    ↓
fetch_provider_key(PublicKey, challenge_uuid) → encrypted_provider_key
    ↓
decrypt_data(encrypted_provider_key, PrivateKey) → api_key
```

### Management Flow

```
User Credentials
    ↓
login(username, password) → access_token, refresh_token
    ↓
Store tokens in client instance
    ↓
API requests include Authorization: Bearer <access_token>
    ↓
If 401 → refresh_token → new access_token
```

## Testing Strategy

### Test Organization

- `test_basic.py`: Import tests, basic functionality
- `test_cli.py`: CLI command structure, help text
- `test_cli_integration.py`: Integration tests with mocked API
- `test_client.py`: Client library tests with mocked HTTP

### Mocking Strategy

- Use `httpx` mocks for API calls
- Use fixtures for common test data
- Mock at HTTP layer, not crypto layer (test crypto for real)

### Coverage Goals

- Core client: >75%
- CLI: >50% (UI code harder to test)
- Crypto: >50% (delegate to libsodium testing)
- Management: >30% (mostly HTTP wrappers)

## Configuration Files

### `pyproject.toml`
- Package metadata
- Dependencies
- Build configuration
- Tool configuration (pytest, setuptools_scm)

### `ruff.toml`
- Linter rules
- Code style enforcement
- Import sorting (isort)
- File-specific rule overrides

### `.pre-commit-config.yaml`
- Pre-commit hooks
- Ruff (lint + format)
- Secret detection
- Trailing whitespace removal

## Extension Points

### Adding New Providers

1. No code changes needed - provider names are dynamic
2. Encryption/decryption works for any provider
3. Only backend needs to know about new providers

### Adding New CLI Commands

1. Add command function to `cli.py`
2. Decorate with `@cli.command()` or `@<group>.command()`
3. Add to management mixin if needed
4. Add tests to `test_cli.py`

### Adding New Output Formats

1. Add format to `output_format` option
2. Implement formatter function
3. Update `_format_output()` switch

## Security Boundaries

### Trust Boundaries

1. **User Input**: CLI arguments, environment variables
2. **Network**: HTTP API calls to backend
3. **Cryptographic**: Private keys, challenges, encrypted data

### Validation Points

- Input validation: CLI layer (Click)
- Authentication: Management layer (JWT tokens)
- Cryptographic: Crypto layer (libsodium)

### Sensitive Data

- Private keys (never transmitted)
- API keys (encrypted at rest, in transit)
- Passwords (only during login)
- Tokens (in-memory only)

## Dependencies

### Production Dependencies

- `pynacl>=1.6.0`: Cryptography (libsodium bindings)
- `httpx>=0.28.0`: HTTP client (sync + async)
- `click>=8.1.0`: CLI framework
- `pyyaml>=6.0.0`: YAML output format
- `rich>=13.0.0`: Terminal formatting

### Development Dependencies

- `pytest>=8,<9`: Testing framework
- `pytest-cov>=4.0.0`: Coverage reporting
- `pytest-asyncio>=0.24.0`: Async test support
- `ruff>=0.14.3`: Linter + formatter
- `pre-commit>=4.3.0`: Pre-commit hooks

## Performance Considerations

### HTTP Connection Pooling

- `httpx.Client` reuses connections
- Connection pooling reduces latency
- Async client for concurrent operations

### Cryptographic Operations

- X25519 operations are fast (~0.1ms)
- XChaCha20 encryption is fast (~1GB/s)
- Bottleneck is network I/O, not crypto

### Memory Usage

- Minimal state (except tokens)
- No caching of decrypted keys
- Keys cleared from memory when out of scope

## Future Considerations

### Planned Enhancements

- [ ] Persistent credential storage (keyring integration)
- [ ] Configuration file support (~/.any-llm/config.yaml)
- [ ] Shell completion (bash, zsh, fish)
- [ ] Progress bars for long operations
- [ ] Concurrent key decryption (async batch operations)

### Deprecated Patterns

None currently - project is young

### Migration Path

- Version format: `ANY.v1.*` allows future format changes
- Backward compatibility maintained within v1
- v2 format would require migration tool
