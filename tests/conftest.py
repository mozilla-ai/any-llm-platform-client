"""Pytest configuration and fixtures."""

import sys
from pathlib import Path

import pytest

# Add src directory to path for testing
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))


@pytest.fixture
def valid_any_llm_key() -> str:
    return "ANY.v1.12345678.abcdef01-YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3OA=="  # pragma: allowlist secret
