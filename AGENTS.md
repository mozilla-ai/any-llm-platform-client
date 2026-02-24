# AGENTS.md - Agent Development Guide

This document is the **table of contents** for AI coding agents working in this repository. It provides a map to deeper documentation rather than exhaustive instructions.

## Quick Start

```bash
# Setup
uv sync --dev && uv run pre-commit install

# Run tests
uv run pytest -v

# Run single test
uv run pytest tests/test_cli.py::test_cli_help -v

# Lint and format
uv run ruff check . --fix && uv run ruff format .
```

## Project Identity

- **Package**: `any-llm-platform-client`
- **CLI**: `any-llm`
- **Python**: 3.11+ (compatible with 3.11–3.14)
- **Package Manager**: `uv` (or `pip`)
- **Source**: `src/any_llm_platform_client/`
- **Tests**: `tests/`

## Repository Knowledge Map

The repository follows a **structured documentation approach** inspired by agent-first development principles. Knowledge lives in versioned, discoverable artifacts—not external documents or chat threads.

### Core Documentation

| Document | Purpose |
|----------|---------|
| `docs/DEVELOPMENT.md` | Development workflow, commands, testing |
| `docs/CODE_STYLE.md` | Style guide, formatting, naming, type hints |
| `docs/CLI_USAGE.md` | CLI commands, OAuth authentication, examples |
| `docs/architecture/CRYPTOGRAPHY.md` | Encryption design, security properties |
| `docs/architecture/PROJECT_STRUCTURE.md` | Code organization, module responsibilities |
| `docs/architecture/OAUTH_BACKEND.md` | Backend OAuth requirements for CLI support |

### Quick Reference

- **Build/Test/Lint**: See `docs/DEVELOPMENT.md`
- **Code Style**: See `docs/CODE_STYLE.md`
- **CLI Usage**: See `docs/CLI_USAGE.md`
- **Architecture**: See `docs/architecture/`

## Core Principles

Following the OpenAI agent-first development model, this repository enforces:

1. **Agent Legibility**: Code structure optimized for agent reasoning
2. **Repository as Truth**: All knowledge versioned in-repo (not in Slack/Docs)
3. **Progressive Disclosure**: Start with this map, navigate to details as needed
4. **Mechanical Enforcement**: Linters enforce architecture, not docs alone

## Code Style Highlights

```python
# Type hints (required)
def decrypt_data(encrypted_data: bytes, private_key: nacl.public.PrivateKey) -> bytes:
    """Decrypt data using X25519 sealed box.

    Args:
        encrypted_data: The encrypted data bytes
        private_key: The X25519 private key for decryption

    Returns:
        Decrypted data as bytes

    Raises:
        ValueError: If decryption fails
    """
    ...

# Modern syntax
items: list[str] = []  # Not List[str]
result: str | None = None  # Not Optional[str]

# Imports (grouped: stdlib → third-party → local)
import logging
from typing import Any

import httpx
from rich.console import Console

from .client import AnyLLMPlatformClient
```

**Key Rules**:
- 120 char line length
- Double quotes for strings
- Google docstring format
- Type hints required (except tests, `__init__.py`)
- No bare `except:`, use specific exception types

## Project Structure

```
src/any_llm_platform_client/
├── __init__.py           # Public API exports
├── cli.py                # Click CLI commands (includes OAuth)
├── client.py             # Core decryption client
├── client_management.py  # Management API (CRUD)
├── config.py             # OAuth token storage
├── crypto.py             # X25519 cryptography
├── exceptions.py         # Custom exceptions
└── oauth.py              # OAuth flow implementation

tests/
├── test_basic.py         # Basic imports
├── test_cli.py           # CLI commands
├── test_cli_integration.py  # Integration tests
└── test_client.py        # Client library tests

docs/
├── DEVELOPMENT.md        # Build, test, lint
├── CODE_STYLE.md         # Style guide
├── CLI_USAGE.md          # CLI reference (includes OAuth auth)
└── architecture/         # Design docs
    ├── CRYPTOGRAPHY.md
    ├── OAUTH_BACKEND.md
    └── PROJECT_STRUCTURE.md
```

## Environment Variables

- `ANY_LLM_USERNAME`: Username for management commands (alternative to OAuth)
- `ANY_LLM_PASSWORD`: Password for management commands (alternative to OAuth)
- `ANY_LLM_PLATFORM_URL`: API base URL (default: `https://platform-api.any-llm.ai/api/v1`)
- `ANY_LLM_KEY`: Encryption key format: `ANY.v1.<kid>.<fingerprint>-<base64_key>`

**Note**: OAuth authentication is recommended. Credentials are stored in `~/.any-llm/config.json`.

## Common Pitfalls

1. **Don't** skip type annotations in production code
2. **Don't** use mutable default arguments
3. **Don't** commit secrets (pre-commit hooks check)
4. **Don't** ignore ruff's bugbear rules (B)—they catch real bugs
5. **Don't** create files without reading existing ones first

## CI/CD

- **Platforms**: Linux, macOS, Windows
- **Python versions**: 3.11, 3.12, 3.13, 3.14
- **Pre-commit**: Linting, formatting, secrets detection
- **Coverage**: Codecov (Ubuntu + Python 3.11 only)

## Where to Look Next

- **First time here?** Start with `docs/DEVELOPMENT.md`
- **Writing code?** Check `docs/CODE_STYLE.md`
- **Using the CLI?** See `docs/CLI_USAGE.md`
- **Understanding crypto?** Read `docs/architecture/CRYPTOGRAPHY.md`
- **Need examples?** See `docs/CLI_USAGE.md` examples section

---

**Philosophy**: This file is a **map**, not a manual. For detailed instructions, follow the links above to specialized documentation.
