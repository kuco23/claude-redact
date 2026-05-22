#!/usr/bin/env bash
set -euo pipefail

mkdir -p "$HOME/.claude"
touch "$HOME/.claude.json"

echo "WORKSPACE_NAME=$(basename "$PWD")" > .devcontainer/.env
