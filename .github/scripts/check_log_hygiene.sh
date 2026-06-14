#!/usr/bin/env bash
# Defence-in-depth grep check: fails the build if any C# file in ZeeKayDa.Auth
# uses a sensitive OAuth/OIDC parameter name as a structured-log placeholder.
# The full list of matched keys is defined in PATTERN below.
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
PATTERN='\{(client_secret|code_verifier|Authorization|access_token|refresh_token|id_token|client_assertion|assertion|device_code|subject_token|actor_token|password|code|DPoP)(:[^}]*)?\}'

found=0

for path in "${SEARCH_PATHS[@]}"; do
    [ -d "$path" ] || continue
    while IFS= read -r line; do
        [[ "$line" == *'# log-hygiene-ok'* ]] && continue
        echo "$line"
        found=1
    done < <(grep -rn --include="*.cs" -E "$PATTERN" -i "$path" 2>/dev/null || true)
done

if [ "$found" -ne 0 ]; then
    printf '\nLOG HYGIENE FAILURE (ADR 0007 §7): sensitive parameter names must not appear as\n'
    printf 'structured-log placeholders in any ZeeKayDa.Auth code code.\n'
    printf 'Append "# log-hygiene-ok" to a line to allowlist it explicitly.\n'
    exit 1
fi

echo "Log hygiene check passed."
