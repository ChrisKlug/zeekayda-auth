#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

# Skip if no .NET projects exist yet
if ! find . \( -name "*.csproj" -o -name "*.sln" -o -name "*.slnx" \) -not -path "./.git/*" | grep -q .; then
  exit 0
fi

# Scope the check to C# files this session/branch actually touched: working-tree
# edits, commits not yet on main, and untracked files. Turns that change no C#
# code skip the (slow, solution-wide) format run entirely.
BASE="$(git merge-base HEAD origin/main 2>/dev/null || git merge-base HEAD main 2>/dev/null || echo HEAD)"

CHANGED="$(
  {
    git diff --name-only HEAD -- '*.cs'
    git diff --name-only "$BASE" HEAD -- '*.cs'
    git ls-files --others --exclude-standard -- '*.cs'
  } 2>/dev/null | sort -u
)" || CHANGED=""

FILES=()
while IFS= read -r f; do
  [ -n "$f" ] && [ -f "$f" ] && FILES+=("$f")
done <<< "$CHANGED"

if [ "${#FILES[@]}" -eq 0 ]; then
  exit 0
fi

# Explicit solution path required: alongside ZeeKayDa.Auth.slnx, the repo now also carries
# per-OS solution filters (ZeeKayDa.Auth.{Windows,MacOS,Linux}.slnf, see ci.yml) that
# `dotnet format`'s auto-discovery treats as additional candidate solution files, causing a
# "Multiple MSBuild solution files found" error when no path is given.
if OUTPUT=$(dotnet format ZeeKayDa.Auth.slnx --verify-no-changes --include "${FILES[@]}" 2>&1); then
  exit 0
fi

REASON=$(printf 'Formatting check failed. Run `dotnet format` to fix the issues before finishing.\n\nOutput:\n%s' "$OUTPUT" | head -c 4000)
jq -cn --arg reason "$REASON" '{"decision":"block","reason":$reason}'
