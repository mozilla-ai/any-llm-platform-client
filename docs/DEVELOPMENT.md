# Development Guide

Comprehensive guide for building, testing, and maintaining this project.

## Quick Start

```bash
# Clone and setup
git clone https://github.com/mozilla-ai/any-api-decrypter-cli
cd any-api-decrypter-cli
uv sync --dev
uv run pre-commit install
```

## Installation

### Using uv (Recommended)

```bash
# Install dependencies
uv sync --dev

# Install pre-commit hooks
uv run pre-commit install

# Enter shell with virtual environment
uv venv
source .venv/bin/activate  # or: .\.venv\Scripts\activate on Windows
```

### Using pip

```bash
# Install in development mode
pip install -e .

# Install development dependencies
pip install -e ".[dev]"
```

## Running Tests

### Basic Testing

```bash
# Run all tests
uv run pytest

# Run tests with verbose output
uv run pytest -v

# Run tests with coverage
uv run pytest --cov=src/any_llm_platform_client --cov-report=term-missing

# Generate coverage report (XML for CI)
uv run pytest --cov=src/any_llm_platform_client --cov-report=xml
```

### Targeted Testing

```bash
# Run specific test file
uv run pytest tests/test_cli.py -v
uv run pytest tests/test_cli_integration.py -v

# Run specific test function
uv run pytest tests/test_cli.py::test_cli_help -v

# Run async tests
uv run pytest tests/test_client.py -v --asyncio-mode=auto
```

### Test Structure

- `tests/test_basic.py` - Basic import and parsing tests
- `tests/test_cli.py` - CLI command structure and help text tests
- `tests/test_cli_integration.py` - Integration tests with mocked API responses
- `tests/test_client.py` - Client library tests with mocked HTTP calls

## Linting and Formatting

### Pre-commit Hooks

```bash
# Run all pre-commit checks
uv run pre-commit run --all-files

# Install hooks (runs on every commit)
uv run pre-commit install
```

### Manual Linting

```bash
# Run ruff linter
uv run ruff check .

# Run ruff linter with auto-fix
uv run ruff check . --fix

# Run ruff formatter
uv run ruff format .

# Check for secrets
detect-secrets scan
```

### What Gets Checked

Pre-commit hooks run:
- **ruff**: Linting and formatting (pycodestyle, pyflakes, pyupgrade, flake8-bugbear, etc.)
- **detect-secrets**: Prevents committing credentials
- **trailing-whitespace**: Removes trailing spaces
- **end-of-file-fixer**: Ensures files end with newline
- **check-merge-conflict**: Detects merge conflict markers
- **uv-lock**: Ensures `uv.lock` is up to date

## Manual Testing

### Local Testing Script

A helper script is provided for testing against a local ANY LLM platform instance:

```bash
# Basic commands
./test_local.sh project list
./test_local.sh --format json project list
./test_local.sh project create "My Project" --description "Test project"

# Default credentials (can be overridden via environment variables):
# ANY_LLM_USERNAME=admin@example.com
# ANY_LLM_PASSWORD=changethis
# ANY_LLM_PLATFORM_URL=http://localhost:8100/api/v1

# Override credentials
ANY_LLM_USERNAME=myuser@example.com ./test_local.sh project list
```

### Running CLI Directly

```bash
# Run CLI with uv
uv run any-llm --help
uv run any-llm project list

# Or activate venv and run directly
source .venv/bin/activate
any-llm --help
```

## Continuous Integration

### GitHub Actions

Tests run automatically on:
- Pull requests to `main`
- Pushes to `main`

### Test Matrix

- **Operating Systems**: Ubuntu, macOS, Windows
- **Python Versions**: 3.11, 3.12, 3.13, 3.14

### Coverage Reporting

- Coverage reports uploaded to Codecov
- Only from Ubuntu + Python 3.11 runs
- Non-blocking (won't fail CI)

### Lint Workflow

Separate workflow runs pre-commit checks on Ubuntu + Python 3.11.

## Build and Distribution

### Building Package

```bash
# Build distribution packages
python -m build

# Outputs:
# - dist/any_llm_platform_client-*.tar.gz (source)
# - dist/any_llm_platform_client-*.whl (wheel)
```

### Version Management

Version is managed via `setuptools_scm`:
- Automatically determined from git tags
- Stored in `src/any_llm_platform_client/_version.py` (generated)

## Common Development Tasks

### Adding a New Dependency

```bash
# Add to pyproject.toml [project.dependencies]
# Then sync
uv sync

# For dev dependencies, add to [dependency-groups.dev]
uv sync --dev
```

### Running in Development Mode

```bash
# Option 1: Use uv run
uv run any-llm --help

# Option 2: Activate venv
source .venv/bin/activate
any-llm --help
```

### Testing Against Local Backend

1. Start the ANY LLM backend locally (port 8100)
2. Use the test script:
   ```bash
   ./test_local.sh project list
   ```

## Troubleshooting

### Import Errors

```bash
# Ensure package is installed in development mode
pip install -e .
# or
uv sync --dev
```

### Pre-commit Hook Failures

```bash
# Run hooks manually to see details
uv run pre-commit run --all-files

# Update hooks to latest versions
uv run pre-commit autoupdate
```

### Test Failures

```bash
# Run with more verbose output
uv run pytest -vv

# Run with full stack traces
uv run pytest --tb=long

# Run specific failing test
uv run pytest tests/test_cli.py::test_cli_help -vv
```

### Lock File Issues

```bash
# Regenerate lock file
uv lock --upgrade

# Sync dependencies
uv sync --dev
```

## Best Practices

1. **Always run tests before committing**: `uv run pytest`
2. **Use pre-commit hooks**: They catch issues early
3. **Test across Python versions**: Use GitHub Actions or `tox`
4. **Keep dependencies minimal**: Only add what's truly needed
5. **Document breaking changes**: Update relevant docs
6. **Follow semantic versioning**: Major.Minor.Patch

## Performance Tips

### Faster Test Runs

```bash
# Run tests in parallel (requires pytest-xdist)
uv run pytest -n auto

# Skip slow tests (if marked with @pytest.mark.slow)
uv run pytest -m "not slow"
```

### Incremental Type Checking

```bash
# If using mypy
uv run mypy src/ --incremental
```

## Resources

- **Ruff documentation**: https://docs.astral.sh/ruff/
- **pytest documentation**: https://docs.pytest.org/
- **uv documentation**: https://docs.astral.sh/uv/
- **Pre-commit hooks**: https://pre-commit.com/
