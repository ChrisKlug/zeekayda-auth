#!/usr/bin/env bash
# Defence-in-depth grep check: fails the build if any C# file in ZeeKayDa.Auth
# uses sensitive parameter names as structured-log placeholders
# ({client_secret}, {code_verifier}, {Authorization}).
#
# NOTE: The primary preventive control is now the Roslyn analyzer ZEEKAYDA0001, which enforces
# ISanitizingLogger<T> injection at compile time. This script is a secondary runtime-script
# layer that catches anything the analyzer cannot see (e.g. generated code, IL-patched assemblies).
#
# Append "# log-hygiene-ok" to a line to allowlist it explicitly.
#
# ADR 0007 §7 / Issue #118.

set -euo pipefail

SEARCH_PATHS=(
    "src/"
)

# Matches {client_secret}, {code_verifier}, {Authorization}, with optional :format specifier.
PATTERN='\{(client_secret|code_verifier|Authorization)(:[^}]*)?\}'

found=0

for path in "${SEARCH_PATHS[@]}"; do
    [ -d "$path" ] || continue
    while IFS= read -r line; do
        [[ "$line" == *'# log-hygiene-ok'* ]] && continue
        echo "$line"
        found=1
    done < <(grep -rn --include="*.cs" -E "$PATTERN" "$path" 2>/dev/null || true)
done

if [ "$found" -ne 0 ]; then
    printf '\nLOG HYGIENE FAILURE (ADR 0007 §7): sensitive parameter names must not appear as\n'
    printf 'structured-log placeholders in any ZeeKayDa.Auth code code.\n'
    printf 'Append "# log-hygiene-ok" to a line to allowlist it explicitly.\n'
    exit 1
fi

echo "Log hygiene check passed."
