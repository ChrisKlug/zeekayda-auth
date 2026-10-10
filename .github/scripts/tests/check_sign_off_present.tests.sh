#!/usr/bin/env bash
# Smoke tests for .github/scripts/check_sign_off_present.sh
#
# Invoked from CI (`.github/workflows/sign-off.yml`) and can be run locally:
#   bash .github/scripts/tests/check_sign_off_present.tests.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
TARGET="${REPO_ROOT}/.github/scripts/check_sign_off_present.sh"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

PASS=0
FAIL=0

# assert_exit <name> <expected-exit> <added-lines> <pr-body> [issue...]
assert_exit() {
    local name="$1" expected="$2" added="$3" body="$4"
    shift 4
    printf '%s\n' "${added}" > "${WORK_DIR}/added"
    printf '%s\n' "${body}" > "${WORK_DIR}/body"
    set +e
    bash "${TARGET}" "${WORK_DIR}/added" "${WORK_DIR}/body" "$@" >/dev/null 2>&1
    local actual=$?
    set -e
    if [[ "${actual}" -eq "${expected}" ]]; then
        PASS=$((PASS + 1)); echo "PASS: ${name}"
    else
        FAIL=$((FAIL + 1)); echo "FAIL: ${name} (expected ${expected}, got ${actual})" >&2
    fi
}

ENTRY='## 2026-10-10 — a key due to sign that cannot is skipped (#916, code frozen at `6e16d45`)'

assert_exit "no area:security issue needs no entry" 0 "" "Closes #1"
assert_exit "the entry for the issue passes" 0 "${ENTRY}" "Closes #916" 916
assert_exit "an entry closing on a parenthesis passes" 0 '## 2026-10-10 — something (#916)' "Closes #916" 916
assert_exit "no entry fails" 1 "" "Closes #916" 916
assert_exit "an annotation naming the issue is not an entry" 1 '  `Old_test` [superseded by #916: `New_test`],' "Closes #916" 916
assert_exit "an entry for another issue fails" 1 '## 2026-10-10 — something (#9160, code frozen at `x`)' "Closes #916" 916
assert_exit "a heading naming several issues covers each" 0 '## 2026-09-01 — something (#513, #514, code frozen at `x`)' "Closes #513, closes #514" 513 514
assert_exit "every security issue needs its own entry" 1 "${ENTRY}" "Closes #916, closes #917" 916 917
assert_exit "the opt-out line passes" 0 "" $'Closes #916\n\nNo security sign-off: CI wording only, no trust-boundary decision.' 916
assert_exit "an opt-out with no reason fails" 1 "" $'Closes #916\n\nNo security sign-off:' 916

echo
echo "Smoke test summary: ${PASS} passed, ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]]
