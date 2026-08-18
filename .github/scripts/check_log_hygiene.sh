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
# The same structured justification is required for the other ways this script can detect
# silencing ZEEKAYDA0001/ZEEKAYDA0002: #pragma warning disable, [SuppressMessage(...)],
# a single-line project-wide <NoWarn> entry, and a single-line .editorconfig severity
# override below "error". This is a grep-based check, not semantic analysis — see
# docs/reference/analyzer-rules.md for what it does and does not cover.
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

# Second check: any #pragma warning disable naming ZEEKAYDA0001/ZEEKAYDA0002 must carry the
# same structured "// log-hygiene-ok: <reason> (#N)" comment on the same line, so a future
# self-served suppression is visible in the diff rather than a quiet commit. Today every source
# file falls under CODEOWNERS' repo-wide "* @ChrisKlug" entry, so any such suppression already
# requires maintainer review; that default-owner coverage, not this script's own CODEOWNERS entry,
# is what makes the review requirement hold at a suppression's actual call site. If narrower,
# per-directory CODEOWNERS entries are ever introduced, revisit whether src/ still needs one too.
PRAGMA_PATTERN='#pragma[[:space:]]+warning[[:space:]]+disable.*\b(ZEEKAYDA0001|ZEEKAYDA0002)\b'
pragma_found=0

for path in "${SEARCH_PATHS[@]}"; do
    [ -d "$path" ] || continue
    while IFS= read -r line; do
        [[ "$line" =~ //[[:space:]]*log-hygiene-ok:[[:space:]]+[^[:space:]].*\(#[0-9]+\)[[:space:]]*$ ]] && continue
        echo "$line"
        pragma_found=1
    done < <(grep -rn --include="*.cs" -E "$PRAGMA_PATTERN" "$path" 2>/dev/null || true)
done

if [ "$pragma_found" -ne 0 ]; then
    printf '\nLOG HYGIENE FAILURE: a #pragma warning disable for ZEEKAYDA0001/ZEEKAYDA0002 must\n'
    printf 'carry a structured suppression comment on the same line:\n'
    printf '  // log-hygiene-ok: <non-empty reason> (#<issue-or-pr-number>)\n'
    exit 1
fi

# Third check: a [SuppressMessage("...", "ZEEKAYDA0001"/"ZEEKAYDA0002")] attribute is a second
# code-level way to silence the analyzer and must carry the same structured comment as a
# #pragma suppression.
SUPPRESS_PATTERN='\bSuppressMessage[[:space:]]*\(.*\b(ZEEKAYDA0001|ZEEKAYDA0002)\b'
suppress_found=0

for path in "${SEARCH_PATHS[@]}"; do
    [ -d "$path" ] || continue
    while IFS= read -r line; do
        [[ "$line" =~ //[[:space:]]*log-hygiene-ok:[[:space:]]+[^[:space:]].*\(#[0-9]+\)[[:space:]]*$ ]] && continue
        echo "$line"
        suppress_found=1
    done < <(grep -rn --include="*.cs" -E "$SUPPRESS_PATTERN" "$path" 2>/dev/null || true)
done

if [ "$suppress_found" -ne 0 ]; then
    printf '\nLOG HYGIENE FAILURE: a [SuppressMessage] attribute for ZEEKAYDA0001/ZEEKAYDA0002 must\n'
    printf 'carry a structured suppression comment on the same line:\n'
    printf '  // log-hygiene-ok: <non-empty reason> (#<issue-or-pr-number>)\n'
    exit 1
fi

# Allow tests to redirect the config-file search path (csproj/props/.editorconfig live outside
# src/, unlike the C#-source checks above, so they get their own overridable path list).
if [[ -n "${LOG_HYGIENE_CONFIG_SEARCH_PATHS:-}" ]]; then
    IFS=':' read -ra CONFIG_SEARCH_PATHS <<< "${LOG_HYGIENE_CONFIG_SEARCH_PATHS}"
else
    CONFIG_SEARCH_PATHS=(".")
fi

# Fourth check: a project-wide <NoWarn>ZEEKAYDA0001/ZEEKAYDA0002</NoWarn> in any .csproj or
# Directory.Build.props silences the analyzer for every file the project compiles, so it needs
# the same visible, structured justification as a single-line suppression.
NOWARN_PATTERN='<NoWarn[^>]*>[^<]*\b(ZEEKAYDA0001|ZEEKAYDA0002)\b'
nowarn_found=0
# Reason text is restricted to non-< and non-> characters so the match can't cross a
# "-->...<!--" boundary; this also means a reason mentioning a generic type like
# ISanitizingLogger<T> is rejected — write around it rather than widen the exclusion.
# Held in a variable (rather than written inline in [[ =~ ]]) because bash's parser treats an
# unescaped "<>" as a redirection token even inside a regex bracket expression.
NOWARN_JUSTIFICATION_REGEX='<!--[[:space:]]*log-hygiene-ok:[[:space:]]+[^[:space:]][^<>]*\(#[0-9]+\)[[:space:]]*-->'

for path in "${CONFIG_SEARCH_PATHS[@]}"; do
    [ -d "$path" ] || continue
    while IFS= read -r line; do
        [[ "$line" =~ $NOWARN_JUSTIFICATION_REGEX ]] && continue
        echo "$line"
        nowarn_found=1
    done < <(grep -rn --include="*.csproj" --include="Directory.Build.props" -E "$NOWARN_PATTERN" "$path" 2>/dev/null || true)
done

if [ "$nowarn_found" -ne 0 ]; then
    printf '\nLOG HYGIENE FAILURE: a <NoWarn> entry for ZEEKAYDA0001/ZEEKAYDA0002 must carry a\n'
    printf 'structured suppression comment on the same line:\n'
    printf '  <!-- log-hygiene-ok: <non-empty reason> (#<issue-or-pr-number>) -->\n'
    exit 1
fi

# Fifth check: a .editorconfig severity override that sets ZEEKAYDA0001/ZEEKAYDA0002 below
# "error" is a third project-wide suppression route. An inline trailing comment on a
# key=value line is not valid .editorconfig syntax, so the justification must be a standalone
# comment line immediately above the override instead.
SEVERITY_PATTERN='dotnet_diagnostic\.(ZEEKAYDA0001|ZEEKAYDA0002)\.severity[[:space:]]*=[[:space:]]*(none|silent|suggestion|warning|refactoring)\b'
severity_found=0

for path in "${CONFIG_SEARCH_PATHS[@]}"; do
    [ -d "$path" ] || continue
    while IFS= read -r match; do
        file="${match%%:*}"
        rest="${match#*:}"
        lineno="${rest%%:*}"
        prev_lineno=$((lineno - 1))
        prev_line=""
        if [ "$prev_lineno" -ge 1 ]; then
            prev_line=$(sed -n "${prev_lineno}p" "$file")
        fi
        if [[ "$prev_line" =~ ^[[:space:]]*[#\;][[:space:]]*log-hygiene-ok:[[:space:]]+[^[:space:]].*\(#[0-9]+\)[[:space:]]*$ ]]; then
            continue
        fi
        echo "$match"
        severity_found=1
    done < <(grep -rn --include=".editorconfig" -E "$SEVERITY_PATTERN" "$path" 2>/dev/null || true)
done

if [ "$severity_found" -ne 0 ]; then
    printf '\nLOG HYGIENE FAILURE: a .editorconfig severity override for ZEEKAYDA0001/ZEEKAYDA0002\n'
    printf 'below "error" must carry a structured suppression comment on the line immediately\n'
    printf 'above it (inline trailing comments are not valid .editorconfig syntax):\n'
    printf '  ; log-hygiene-ok: <non-empty reason> (#<issue-or-pr-number>)\n'
    printf '  dotnet_diagnostic.ZEEKAYDA0002.severity = warning\n'
    exit 1
fi

echo "Log hygiene check passed."
