#!/usr/bin/env bash
# Defence-in-depth grep check: fails the build if any C# file in ZeeKayDa.Auth
# uses a sensitive OAuth/OIDC parameter name as a structured-log placeholder.
# The full list of matched keys is defined in PATTERN below.
#
# NOTE: The primary preventive control is now the Roslyn analyzer ZEEKAYDA0001, which enforces
# ISanitizingLogger<T> injection at compile time. This script is a secondary runtime-script
# layer that catches anything the analyzer cannot see (e.g. generated code, IL-patched assemblies).
#
# To suppress a specific line, append a structured suppression comment:
#
#   // log-hygiene-ok: <non-empty reason> (#<issue-or-pr-number>)
#
# Example:
#   _logger.LogDebug("Verifier: {code_verifier}", v); // log-hygiene-ok: test fixture, never reaches production (#179)
#
# The bare form "// log-hygiene-ok" is rejected. Both a non-empty reason and a
# parenthesised issue/PR number are required. Changes to this script and any
# suppression inventory file require security-owner approval (see CODEOWNERS).
#
# ADR 0007 §7 / Issue #118. Structured suppression format: Issue #179.

set -euo pipefail

# Allow tests to redirect the search path via an environment variable.
# In normal CI usage the variable is unset and the default "src/" path is used.
if [[ -n "${LOG_HYGIENE_SEARCH_PATHS:-}" ]]; then
    IFS=':' read -ra SEARCH_PATHS <<< "${LOG_HYGIENE_SEARCH_PATHS}"
else
    SEARCH_PATHS=(
        "src/"
    )
fi

# Matches {client_secret}, {code_verifier}, {Authorization}, with optional :format specifier.
PATTERN='\{(client_secret|code_verifier|Authorization|access_token|refresh_token|id_token|client_assertion|assertion|device_code|subject_token|actor_token|password|code|DPoP)(:[^}]*)?\}'

found=0

for path in "${SEARCH_PATHS[@]}"; do
    [ -d "$path" ] || continue
    while IFS= read -r line; do
        # Accept only the structured suppression form:
        #   // log-hygiene-ok: <non-empty reason> (#<digits>)
        # The reason must contain at least one non-space character before the
        # parenthesised reference. The bare form "// log-hygiene-ok" is rejected.
        [[ "$line" =~ //[[:space:]]*log-hygiene-ok:[[:space:]]+[^[:space:]].*\(#[0-9]+\)[[:space:]]*$ ]] && continue
        echo "$line"
        found=1
    done < <(grep -rn --include="*.cs" -E "$PATTERN" -i "$path" 2>/dev/null || true)
done

if [ "$found" -ne 0 ]; then
    printf '\nLOG HYGIENE FAILURE (ADR 0007 §7): sensitive parameter names must not appear as\n'
    printf 'structured-log placeholders in any ZeeKayDa.Auth code.\n'
    printf 'To suppress a specific line, append a structured suppression comment:\n'
    printf '  // log-hygiene-ok: <non-empty reason> (#<issue-or-pr-number>)\n'
    printf 'Example:\n'
    printf '  // log-hygiene-ok: test fixture, never reaches production (#179)\n'
    printf 'Both a non-empty reason and a parenthesised issue/PR number are required.\n'
    printf 'The bare form "// log-hygiene-ok" is not accepted.\n'
    exit 1
fi

echo "Log hygiene check passed."
