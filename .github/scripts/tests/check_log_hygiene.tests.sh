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
# Summary
# ---------------------------------------------------------------------------
echo
echo "Smoke test summary: ${PASS} passed, ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]]
