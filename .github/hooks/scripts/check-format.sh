#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

# Skip if no .NET projects exist yet
if ! find . \( -name "*.csproj" -o -name "*.sln" \) -not -path "./.git/*" | grep -q .; then
  exit 0
fi

if OUTPUT=$(dotnet format --verify-no-changes 2>&1); then
  exit 0
fi

REASON=$(printf 'Formatting check failed. Run `dotnet format` to fix the issues before finishing.\n\nOutput:\n%s' "$OUTPUT" | head -c 4000)
jq -cn --arg reason "$REASON" '{"decision":"block","reason":$reason}'
