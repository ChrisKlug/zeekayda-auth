#!/usr/bin/env bash
# Smoke tests for .github/scripts/check_log_hygiene.sh
#
# Builds synthetic .cs fixture files and asserts that the log hygiene checker
# exits 0 when no violations are present (or all are validly suppressed) and
# exits 1 when violations are found or suppressions are malformed.
#
# The script under test must honour the LOG_HYGIENE_SEARCH_PATHS environment
# variable as a colon-separated list of paths that overrides the hardcoded
# SEARCH_PATHS array.
#
# Invoked from CI and can be run locally:
#   bash .github/scripts/tests/check_log_hygiene.tests.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
TARGET="${REPO_ROOT}/.github/scripts/check_log_hygiene.sh"

if [[ ! -f "${TARGET}" ]]; then
    echo "FAIL: cannot find ${TARGET}" >&2
    exit 1
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

write_cs_file() {
    local dir="$1"
    local filename="$2"
    local content="$3"
    mkdir -p "${dir}"
    printf '%s\n' "${content}" > "${dir}/${filename}"
}

run_hygiene_check() {
    local search_path="$1"
    (
        cd "${REPO_ROOT}"
        LOG_HYGIENE_SEARCH_PATHS="${search_path}" bash "${TARGET}" >/dev/null 2>&1
    )
}

# Like run_hygiene_check, but also scopes the config-file checks (NoWarn/.editorconfig) to a
# directory instead of the real repo root, via LOG_HYGIENE_CONFIG_SEARCH_PATHS.
run_hygiene_check_config() {
    local config_path="$1"
    (
        cd "${REPO_ROOT}"
        LOG_HYGIENE_SEARCH_PATHS="${config_path}" LOG_HYGIENE_CONFIG_SEARCH_PATHS="${config_path}" bash "${TARGET}" >/dev/null 2>&1
    )
}

PASS=0
FAIL=0
record_pass() { PASS=$((PASS + 1)); echo "PASS: $1"; }
record_fail() { FAIL=$((FAIL + 1)); echo "FAIL: $1" >&2; }

assert_exit() {
    local name="$1"
    local expected="$2"
    shift 2
    set +e
    "$@"
    local actual=$?
    set -e
    if [[ "${actual}" -eq "${expected}" ]]; then
        record_pass "${name} (exit ${actual})"
    else
        record_fail "${name} (expected ${expected}, got ${actual})"
    fi
}

# ---------------------------------------------------------------------------
# Case 1: Clean file — no sensitive patterns at all → exit 0
# ---------------------------------------------------------------------------
DIR="${WORK_DIR}/case1"
write_cs_file "${DIR}" "Service.cs" \
    '_logger.LogInformation("User authenticated successfully for {UserId}", userId);'
assert_exit "clean file with no sensitive patterns passes" 0 \
    run_hygiene_check "${DIR}"

# ---------------------------------------------------------------------------
# Case 2: Bare suppression — "# log-hygiene-ok" with no colon, reason, or
# issue reference → exit 1
# ---------------------------------------------------------------------------
DIR="${WORK_DIR}/case2"
write_cs_file "${DIR}" "Service.cs" \
    '_logger.LogInformation("Token: {access_token}", token); // log-hygiene-ok'
assert_exit "bare suppression without structured format fails" 1 \
    run_hygiene_check "${DIR}"

# ---------------------------------------------------------------------------
# Case 3: Valid structured suppression — "# log-hygiene-ok: <reason> (#NNN)"
# → exit 0
# ---------------------------------------------------------------------------
DIR="${WORK_DIR}/case3"
write_cs_file "${DIR}" "Service.cs" \
    '_logger.LogInformation("Token: {access_token}", token); // log-hygiene-ok: test fixture only (#179)'
assert_exit "valid structured suppression with reason and issue ref passes" 0 \
    run_hygiene_check "${DIR}"

# ---------------------------------------------------------------------------
# Case 4: Missing issue reference — "# log-hygiene-ok: reason without ref"
# → exit 1
# ---------------------------------------------------------------------------
DIR="${WORK_DIR}/case4"
write_cs_file "${DIR}" "Service.cs" \
    '_logger.LogInformation("Token: {access_token}", token); // log-hygiene-ok: reason without issue ref'
assert_exit "suppression missing issue reference fails" 1 \
    run_hygiene_check "${DIR}"

# ---------------------------------------------------------------------------
# Case 5: Empty reason — "# log-hygiene-ok: (#179)" → exit 1
# ---------------------------------------------------------------------------
DIR="${WORK_DIR}/case5"
write_cs_file "${DIR}" "Service.cs" \
    '_logger.LogInformation("Token: {access_token}", token); // log-hygiene-ok: (#179)'
assert_exit "suppression with empty reason fails" 1 \
    run_hygiene_check "${DIR}"

# ---------------------------------------------------------------------------
# Case 6: No suppression comment at all — sensitive pattern with no comment
# → exit 1
# ---------------------------------------------------------------------------
DIR="${WORK_DIR}/case6"
write_cs_file "${DIR}" "Service.cs" \
    '_logger.LogInformation("Token: {access_token}", token);'
assert_exit "sensitive pattern with no suppression comment fails" 1 \
    run_hygiene_check "${DIR}"

# ---------------------------------------------------------------------------
# Case 7: Valid structured suppression with a different issue number → exit 0
# ---------------------------------------------------------------------------
DIR="${WORK_DIR}/case7"
write_cs_file "${DIR}" "Service.cs" \
    '_logger.LogInformation("Token: {access_token}", token); // log-hygiene-ok: test fixture only (#999)'
assert_exit "valid structured suppression with alternate issue ref passes" 0 \
    run_hygiene_check "${DIR}"

# ---------------------------------------------------------------------------
# Case 8: Multiple sensitive token types — all covered by valid suppressions
# → exit 0
# ---------------------------------------------------------------------------
DIR="${WORK_DIR}/case8"
write_cs_file "${DIR}" "Service.cs" \
    '_logger.LogInformation("Secret: {client_secret}", s); // log-hygiene-ok: integration test only (#179)
_logger.LogInformation("Verifier: {code_verifier}", v); // log-hygiene-ok: integration test only (#179)'
assert_exit "multiple lines each with valid structured suppressions pass" 0 \
    run_hygiene_check "${DIR}"

# ---------------------------------------------------------------------------
# Case 9: Mixed file — one valid suppression and one bare suppression → exit 1
# ---------------------------------------------------------------------------
DIR="${WORK_DIR}/case9"
write_cs_file "${DIR}" "Service.cs" \
    '_logger.LogInformation("Token: {access_token}", t); // log-hygiene-ok: valid (#179)
_logger.LogInformation("Secret: {client_secret}", s); // log-hygiene-ok'
assert_exit "mixed file with one bare suppression fails" 1 \
    run_hygiene_check "${DIR}"

# ---------------------------------------------------------------------------
# Case 10: Empty directory (no .cs files) → exit 0
# ---------------------------------------------------------------------------
DIR="${WORK_DIR}/case10"
mkdir -p "${DIR}"
assert_exit "empty directory with no cs files passes" 0 \
    run_hygiene_check "${DIR}"

# ---------------------------------------------------------------------------
# Case 11: Bypass marker embedded inside a string literal — not a // comment
# The sensitive pattern would be flagged by grep; the marker is inside the string
# so it must NOT be treated as a suppression → exit 1
# ---------------------------------------------------------------------------
DIR="${WORK_DIR}/case11"
write_cs_file "${DIR}" "Service.cs" \
    '_logger.LogInformation("token={access_token} log-hygiene-ok: reason (#42)", value);'
assert_exit "bypass marker inside string literal is not a valid suppression" 1 \
    run_hygiene_check "${DIR}"

# ---------------------------------------------------------------------------
# Case 12: Marker inside a /* */ block comment rather than a // line comment
# → exit 1
# ---------------------------------------------------------------------------
DIR="${WORK_DIR}/case12"
write_cs_file "${DIR}" "Service.cs" \
    'var x = token; /* log-hygiene-ok: reason (#42) */ _logger.LogInformation("{access_token}", x);'
assert_exit "bypass marker not in a // comment is not a valid suppression" 1 \
    run_hygiene_check "${DIR}"

# ---------------------------------------------------------------------------
# Case 13: Valid-looking suppression with trailing code after the (#N) token —
# isolates the $ end-anchor: the marker is a real // comment and the reason +
# issue ref are present, but extra code follows the closing parenthesis so the
# line does not end with (#N). Without the $ anchor this would be a bypass.
# → exit 1
# ---------------------------------------------------------------------------
DIR="${WORK_DIR}/case13"
write_cs_file "${DIR}" "Service.cs" \
    '_logger.LogInformation("{access_token}", t); // log-hygiene-ok: reason (#42) extra trailing code'
assert_exit "suppression with trailing code after issue ref fails ($ end-anchor isolation)" 1 \
    run_hygiene_check "${DIR}"

# ---------------------------------------------------------------------------
# Case 14: #pragma warning disable ZEEKAYDA0002 with a valid structured
# suppression comment on the same line → exit 0
# ---------------------------------------------------------------------------
DIR="${WORK_DIR}/case14"
write_cs_file "${DIR}" "Service.cs" \
    '#pragma warning disable ZEEKAYDA0002 // log-hygiene-ok: composes a constant prefix with another unformatted template (#444)'
assert_exit "pragma disable with valid structured suppression passes" 0 \
    run_hygiene_check "${DIR}"

# ---------------------------------------------------------------------------
# Case 15: #pragma warning disable ZEEKAYDA0002 with no suppression comment
# → exit 1
# ---------------------------------------------------------------------------
DIR="${WORK_DIR}/case15"
write_cs_file "${DIR}" "Service.cs" \
    '#pragma warning disable ZEEKAYDA0002'
assert_exit "pragma disable without a suppression comment fails" 1 \
    run_hygiene_check "${DIR}"

# ---------------------------------------------------------------------------
# Case 16: [SuppressMessage] attribute for ZEEKAYDA0002 with a valid structured
# suppression comment on the same line → exit 0
# ---------------------------------------------------------------------------
DIR="${WORK_DIR}/case16"
write_cs_file "${DIR}" "Service.cs" \
    '[SuppressMessage("Design", "ZEEKAYDA0002")] // log-hygiene-ok: composes a constant prefix with another unformatted template (#444)'
assert_exit "SuppressMessage with valid structured suppression passes" 0 \
    run_hygiene_check "${DIR}"

# ---------------------------------------------------------------------------
# Case 17: [SuppressMessage] attribute for ZEEKAYDA0002 with no suppression
# comment → exit 1
# ---------------------------------------------------------------------------
DIR="${WORK_DIR}/case17"
write_cs_file "${DIR}" "Service.cs" \
    '[SuppressMessage("Design", "ZEEKAYDA0002")]'
assert_exit "SuppressMessage without a suppression comment fails" 1 \
    run_hygiene_check "${DIR}"

# ---------------------------------------------------------------------------
# Case 17b: fully-qualified [System.Diagnostics.CodeAnalysis.SuppressMessage]
# attribute with no suppression comment → exit 1 (a bare "[SuppressMessage("
# anchor would miss this)
# ---------------------------------------------------------------------------
DIR="${WORK_DIR}/case17b"
write_cs_file "${DIR}" "Service.cs" \
    '[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "ZEEKAYDA0002")]'
assert_exit "fully-qualified SuppressMessage without a suppression comment fails" 1 \
    run_hygiene_check "${DIR}"

# ---------------------------------------------------------------------------
# Case 18: <NoWarn> entry for ZEEKAYDA0001 in a .csproj with a valid structured
# XML comment on the same line → exit 0
# ---------------------------------------------------------------------------
DIR="${WORK_DIR}/case18"
mkdir -p "${DIR}"
printf '%s\n' '<Project><PropertyGroup><NoWarn>ZEEKAYDA0001</NoWarn> <!-- log-hygiene-ok: generated proxy code, reviewed manually (#454) --></PropertyGroup></Project>' \
    > "${DIR}/Sample.csproj"
assert_exit "NoWarn with valid structured XML comment passes" 0 \
    run_hygiene_check_config "${DIR}"

# ---------------------------------------------------------------------------
# Case 19: <NoWarn> entry for ZEEKAYDA0001 in a .csproj with no justification
# comment → exit 1
# ---------------------------------------------------------------------------
DIR="${WORK_DIR}/case19"
mkdir -p "${DIR}"
printf '%s\n' '<Project><PropertyGroup><NoWarn>ZEEKAYDA0001</NoWarn></PropertyGroup></Project>' \
    > "${DIR}/Sample.csproj"
assert_exit "NoWarn without a justification comment fails" 1 \
    run_hygiene_check_config "${DIR}"

# ---------------------------------------------------------------------------
# Case 19b: <NoWarn Condition="..."> with an attribute on the element (a bare
# "<NoWarn>" anchor would miss this) and no justification comment → exit 1
# ---------------------------------------------------------------------------
DIR="${WORK_DIR}/case19b"
mkdir -p "${DIR}"
printf '%s\n' "<Project><PropertyGroup><NoWarn Condition=\"'\$(Configuration)'=='Debug'\">ZEEKAYDA0001</NoWarn></PropertyGroup></Project>" \
    > "${DIR}/Sample.csproj"
assert_exit "NoWarn with an XML attribute and no justification fails" 1 \
    run_hygiene_check_config "${DIR}"

# ---------------------------------------------------------------------------
# Case 20: .editorconfig severity override below "error" for ZEEKAYDA0002 with
# a valid structured comment on the line above → exit 0
# ---------------------------------------------------------------------------
DIR="${WORK_DIR}/case20"
mkdir -p "${DIR}"
printf '%s\n' \
    '; log-hygiene-ok: temporarily relaxed while migrating legacy module (#454)' \
    'dotnet_diagnostic.ZEEKAYDA0002.severity = warning' \
    > "${DIR}/.editorconfig"
assert_exit "editorconfig severity override with valid comment above passes" 0 \
    run_hygiene_check_config "${DIR}"

# ---------------------------------------------------------------------------
# Case 21: .editorconfig severity override below "error" for ZEEKAYDA0002 with
# no justification comment on the line above → exit 1
# ---------------------------------------------------------------------------
DIR="${WORK_DIR}/case21"
mkdir -p "${DIR}"
printf '%s\n' \
    'dotnet_diagnostic.ZEEKAYDA0002.severity = warning' \
    > "${DIR}/.editorconfig"
assert_exit "editorconfig severity override without justification fails" 1 \
    run_hygiene_check_config "${DIR}"

# ---------------------------------------------------------------------------
# Case 22: .editorconfig severity explicitly set to "error" is not a
# suppression at all → exit 0, no justification required
# ---------------------------------------------------------------------------
DIR="${WORK_DIR}/case22"
mkdir -p "${DIR}"
printf '%s\n' \
    'dotnet_diagnostic.ZEEKAYDA0002.severity = error' \
    > "${DIR}/.editorconfig"
assert_exit "editorconfig severity set to error requires no justification" 0 \
    run_hygiene_check_config "${DIR}"

# ---------------------------------------------------------------------------
# Case 23: <NoWarn> justification containing a hyphen in the reason text →
# exit 0 (regression test: the reason-text regex must not stop at the first
# hyphen; see docs/reference/analyzer-rules.md's own hyphenated example)
# ---------------------------------------------------------------------------
DIR="${WORK_DIR}/case23"
mkdir -p "${DIR}"
printf '%s\n' '<Project><PropertyGroup><NoWarn>ZEEKAYDA0001</NoWarn> <!-- log-hygiene-ok: diagnostic-only dev build (#454) --></PropertyGroup></Project>' \
    > "${DIR}/Sample.csproj"
assert_exit "NoWarn justification with a hyphenated reason passes" 0 \
    run_hygiene_check_config "${DIR}"

# ---------------------------------------------------------------------------
# Case 24: a <NoWarn> "justified" by a reason and issue reference split across
# two separate XML comments → exit 1 (regression test: the reason-text regex
# must not cross a "-->...<!--" comment boundary and treat the two comments
# as one combined justification)
# ---------------------------------------------------------------------------
DIR="${WORK_DIR}/case24"
mkdir -p "${DIR}"
printf '%s\n' '<Project><PropertyGroup><NoWarn>ZEEKAYDA0001</NoWarn></PropertyGroup></Project> <!-- log-hygiene-ok: TODO --> <!-- (#1) -->' \
    > "${DIR}/Sample.csproj"
assert_exit "NoWarn justification split across two XML comments still fails" 1 \
    run_hygiene_check_config "${DIR}"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
echo "Smoke test summary: ${PASS} passed, ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]]
