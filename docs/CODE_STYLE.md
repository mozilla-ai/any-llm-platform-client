# Code Style Guide

This document defines the coding conventions for this project. These rules are enforced by ruff and pre-commit hooks.

## Python Version

- **Target**: Python 3.11+
- **Compatibility**: 3.11, 3.12, 3.13, 3.14
- **Policy**: Follow [NEP 29](https://numpy.org/neps/nep-0029-deprecation_policy.html) deprecation policy

## Formatting

### Line Length
- **Maximum**: 120 characters
- Enforced by ruff

### Quotes
- **String quotes**: Double quotes (`"`)
- **Docstring quotes**: Triple double quotes (`"""`)

```python
# Good
message = "Hello, world"
name = "Alice"

# Bad
message = 'Hello, world'  # Single quotes
```

### Indentation
- **Style**: 4 spaces (no tabs)
- **Continuation**: Align with opening delimiter or use hanging indent

```python
# Good - aligned with opening delimiter
result = some_function(arg1, arg2,
                      arg3, arg4)

# Good - hanging indent
result = some_function(
    arg1, arg2,
    arg3, arg4
)

# Bad - mixed indentation
result = some_function(arg1, arg2,
    arg3, arg4)
```

### Line Endings
- **Auto-detected**: LF on Unix, CRLF on Windows
- Enforced by pre-commit hooks

## Imports

### Import Order
Group imports in this order, separated by blank lines:

1. **Standard library imports**
2. **Third-party imports**
3. **Local application imports**

Sort alphabetically within each group.

```python
# Good
import logging
import os
from typing import Any

import click
import httpx
from rich.console import Console

from .client import AnyLLMPlatformClient
from .exceptions import ChallengeCreationError

# Bad - mixed groups
import logging
from .client import AnyLLMPlatformClient
import click
```

### Import Style
- Use absolute imports: `from any_llm_platform_client.client import ...`
- Avoid wildcard imports: `from module import *`
- Group related imports on one line if short:
  ```python
  from .crypto import decrypt_data, encrypt_data, load_private_key
  ```

## Type Annotations

### Required
Type hints are **required** for all:
- Function parameters
- Function return values
- Class attributes (when not obvious)

### Modern Syntax (Python 3.10+)
Use modern type hint syntax:

```python
# Good - modern syntax
def process_items(items: list[str]) -> dict[str, int]:
    result: dict[str, int] = {}
    return result

def get_value() -> str | None:
    return None

# Bad - old syntax
from typing import List, Dict, Optional

def process_items(items: List[str]) -> Dict[str, int]:
    result: Dict[str, int] = {}
    return result

def get_value() -> Optional[str]:
    return None
```

### Type Hint Rules
```python
# Always annotate return type (even None)
def process() -> None:
    print("Done")

# Use union with pipe operator
def get_config() -> dict[str, Any] | None:
    ...

# Avoid Any unless truly necessary
def format_output(data: dict[str, Any]) -> str:  # OK in CLI output formatters
    ...

# Use Protocol for structural typing
from typing import Protocol

class Comparable(Protocol):
    def __lt__(self, other: Any) -> bool: ...
```

### Exceptions
Type hints not required in:
- Test files (`tests/`)
- `__init__.py` files
- Private functions (starting with `_`) - optional but encouraged

## Docstrings

### Required
Docstrings are **required** for all:
- Public modules
- Public classes
- Public functions
- Public methods

### Style: Google Format

```python
def decrypt_data(encrypted_data: bytes, private_key: nacl.public.PrivateKey) -> bytes:
    """Decrypt data using X25519 sealed box.

    This function uses libsodium's sealed box construction (ECIES) to decrypt
    data with a recipient's private key.

    Args:
        encrypted_data: The encrypted data bytes (ephemeral_key || ciphertext)
        private_key: The X25519 private key for decryption

    Returns:
        Decrypted data as bytes

    Raises:
        ValueError: If decryption fails (wrong key or corrupted data)
        CryptoError: If underlying cryptographic operations fail

    Example:
        >>> private_key = load_private_key(key_string)
        >>> plaintext = decrypt_data(encrypted, private_key)
    """
    ...
```

### Docstring Sections
- **Short summary**: One-line description (imperative mood)
- **Long description**: Additional context (optional)
- **Args**: Parameter descriptions
- **Returns**: Return value description
- **Raises**: Exceptions that may be raised
- **Example**: Usage examples (optional but helpful)

### Not Required
Docstrings not required for:
- Test functions
- Private functions (but encouraged for complex logic)
- `__init__.py` modules (but include package-level docstring if exporting API)

## Naming Conventions

### Modules
- **Style**: `lowercase_with_underscores`
- Examples: `client.py`, `client_management.py`, `crypto.py`

### Classes
- **Style**: `PascalCase`
- Examples: `AnyLLMPlatformClient`, `DecryptedProviderKey`, `KeyComponents`

### Functions and Variables
- **Style**: `snake_case`
- Examples: `get_decrypted_provider_key`, `create_challenge`, `api_key`

### Constants
- **Style**: `UPPER_SNAKE_CASE`
- Examples: `DEFAULT_TIMEOUT`, `MAX_RETRIES`, `API_VERSION`

### Private Members
- **Prefix**: Single underscore `_`
- Examples: `_handle_error`, `_format_response`, `_cached_value`

### Protected Members (Avoid)
- **Prefix**: Double underscore `__` triggers name mangling
- **Recommendation**: Use single underscore instead

```python
class Client:
    def __init__(self):
        self.public_attr = "visible"
        self._internal_cache = {}  # Good - internal use
        # Avoid: self.__private_attr = {}  # Name mangling rarely needed
```

## Error Handling

### Use Custom Exceptions
```python
from .exceptions import ChallengeCreationError, ProviderKeyFetchError

try:
    response = client.create_challenge(public_key)
except httpx.HTTPError as e:
    logger.error("HTTP error during challenge: %s", e)
    raise ChallengeCreationError(f"Failed to create challenge: {e}") from e
```

### Never Use Bare Except
```python
# Bad
try:
    risky_operation()
except:  # Catches KeyboardInterrupt, SystemExit, etc!
    pass

# Good
try:
    risky_operation()
except (ValueError, KeyError) as e:
    logger.error("Operation failed: %s", e)
    raise
```

### Use contextlib.suppress for Expected Exceptions
```python
from contextlib import suppress

# Good - when you truly want to ignore specific exceptions
with suppress(KeyError):
    del cache[key]

# Equivalent to:
try:
    del cache[key]
except KeyError:
    pass
```

### Always Chain Exceptions
```python
# Good - preserves original exception
try:
    process_data(data)
except ValueError as e:
    raise DataProcessingError("Failed to process") from e

# Bad - loses original context
try:
    process_data(data)
except ValueError:
    raise DataProcessingError("Failed to process")
```

## Logging

### Module-Level Logger
```python
import logging

logger = logging.getLogger(__name__)
```

### Lazy Formatting
```python
# Good - lazy evaluation
logger.info("Processing item: %s", item)
logger.debug("Config: %r", config)

# Bad - eager formatting (always evaluates f-string)
logger.info(f"Processing item: {item}")
```

### Log Levels
- **DEBUG**: Detailed diagnostic information
- **INFO**: General informational messages
- **WARNING**: Warning messages for potentially harmful situations
- **ERROR**: Error messages for failures
- **CRITICAL**: Critical errors that may cause shutdown

```python
logger.debug("Attempting to connect to %s", url)
logger.info("Successfully authenticated user %s", username)
logger.warning("Retrying connection (attempt %d/%d)", attempt, max_attempts)
logger.error("Failed to decrypt data: %s", error)
logger.critical("Database connection lost, shutting down")
```

## Function Design

### Avoid Mutable Default Arguments
```python
# Bad - mutable default is shared across calls!
def add_item(item: str, items: list[str] = []) -> list[str]:
    items.append(item)
    return items

# Good - use None and create new list
def add_item(item: str, items: list[str] | None = None) -> list[str]:
    if items is None:
        items = []
    items.append(item)
    return items
```

### Prefer Keyword Arguments for Clarity
```python
# Good - clear what each argument means
client = AnyLLMPlatformClient(
    any_llm_platform_url="http://localhost:8000/api/v1",
    timeout=30
)

# Bad - unclear what arguments are
client = AnyLLMPlatformClient("http://localhost:8000/api/v1", 30)
```

### Keep Functions Focused
- One function, one responsibility
- If a function is >50 lines, consider splitting it
- Extract complex logic into helper functions

## Code Organization

### Module Structure
```python
"""Module docstring describing purpose."""

# 1. Imports
import logging
from typing import Any

import httpx

from .exceptions import CustomError

# 2. Module-level constants
DEFAULT_TIMEOUT = 30
MAX_RETRIES = 3

# 3. Module-level logger
logger = logging.getLogger(__name__)

# 4. Classes and functions
class MyClass:
    ...

def my_function() -> None:
    ...
```

### Class Structure
```python
class MyClass:
    """Class docstring."""

    # 1. Class constants
    MAX_SIZE = 100

    # 2. __init__
    def __init__(self, value: int) -> None:
        self.value = value

    # 3. Public methods
    def public_method(self) -> str:
        return self._format()

    # 4. Private methods
    def _format(self) -> str:
        return f"Value: {self.value}"

    # 5. Special methods at end
    def __str__(self) -> str:
        return self._format()
```

## Common Patterns

### Context Managers
```python
# Prefer context managers for resource management
with open("file.txt") as f:
    data = f.read()

# For custom cleanup
from contextlib import contextmanager

@contextmanager
def temporary_config(config: dict[str, Any]):
    old_config = get_config()
    set_config(config)
    try:
        yield
    finally:
        set_config(old_config)
```

### Dataclasses
```python
from dataclasses import dataclass
from datetime import datetime

@dataclass
class User:
    """User information."""
    id: int
    name: str
    email: str
    created_at: datetime
```

### Type Guards
```python
from typing import TypeGuard

def is_list_of_strings(value: list[Any]) -> TypeGuard[list[str]]:
    return all(isinstance(item, str) for item in value)

# Usage
items = ["a", "b", "c"]
if is_list_of_strings(items):
    # Type checker knows items is list[str] here
    print(items[0].upper())
```

## Enforcement

These rules are enforced by:
- **ruff**: Linting and formatting
- **pre-commit hooks**: Automatic checks before commit
- **GitHub Actions**: CI/CD pipeline validation

Run checks locally:
```bash
uv run ruff check . --fix
uv run ruff format .
uv run pre-commit run --all-files
```
