#!/bin/bash
# Helper script for testing CLI commands against local any-llm platform
#
# This script simplifies testing by automatically setting up credentials
# for the local development environment.
#
# Default credentials (can be overridden via environment variables):
#   ANY_LLM_USERNAME=admin@example.com
#   ANY_LLM_PASSWORD=changethis
#   ANY_LLM_PLATFORM_URL=http://localhost:8100/api/v1
#
# Usage:
#   ./test_local.sh project list
#   ./test_local.sh key list <project-id>
#   ./test_local.sh --format json project list
#   ./test_local.sh project create "My Project" --description "Test project"
#   ./test_local.sh budget create <project-id> 100.0 --period monthly
#   ./test_local.sh client create <project-id> "My Client" --default
#
# Override credentials:
#   ANY_LLM_USERNAME=myuser@example.com ./test_local.sh project list
#   ANY_LLM_PASSWORD=mypassword ./test_local.sh project list
#   ANY_LLM_PLATFORM_URL=http://localhost:9000/api/v1 ./test_local.sh project list

set -e

# Default credentials for local testing
export ANY_LLM_USERNAME="${ANY_LLM_USERNAME:-admin@example.com}"
export ANY_LLM_PASSWORD="${ANY_LLM_PASSWORD:-changethis}"
export ANY_LLM_PLATFORM_URL="${ANY_LLM_PLATFORM_URL:-http://localhost:8100/api/v1}"

# Run the CLI with the provided arguments
uv run any-llm "$@"
