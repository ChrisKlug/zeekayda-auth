#!/usr/bin/env bash
# Fails the build if any C# file in token-endpoint or client-authentication code uses
# sensitive parameter names as structured-log placeholders ({client_secret}, {code_verifier},
# {Authorization}).
#
# Append "# log-hygiene-ok" to a line to allowlist it explicitly.
#
# ADR 0007 §7 / Issue #118.

set -euo pipefail

SEARCH_PATHS=(
    "src/ZeeKayDa.Auth.AspNetCore/ClientAuthentication"
    "src/ZeeKayDa.Auth.AspNetCore/Endpoints"
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
    printf 'structured-log placeholders in token-endpoint or client-authentication code.\n'
    printf 'Append "# log-hygiene-ok" to a line to allowlist it explicitly.\n'
    exit 1
fi

echo "Log hygiene check passed."
