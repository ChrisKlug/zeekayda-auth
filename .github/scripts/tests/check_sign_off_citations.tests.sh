#!/usr/bin/env bash
# Smoke tests for .github/scripts/check_sign_off_citations.sh
#
# Builds synthetic repo layouts (a docs/decisions/security-sign-offs.md plus
# tests/*.cs files) and asserts the citation check passes when every cited test
# exists, fails when one is missing, ignores non-test identifiers and the rules
# preamble, and refuses to pass vacuously when it extracts nothing.
#
# Invoked from CI (`.github/workflows/ci.yml`) and can be run locally:
#   bash .github/scripts/tests/check_sign_off_citations.tests.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
TARGET="${REPO_ROOT}/.github/scripts/check_sign_off_citations.sh"

if [[ ! -f "${TARGET}" ]]; then
    echo "FAIL: cannot find ${TARGET}" >&2
    exit 1
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

write_doc() {
    local dir="$1"
    local entries="$2"
    mkdir -p "${dir}/docs/decisions"
    cat > "${dir}/docs/decisions/security-sign-offs.md" <<EOF
# Security sign-offs

Rules preamble. Cites a hypothetical example (\`Example_preamble_only_test\`)
that never exists anywhere; entries start after the separator.

---

${entries}
EOF
}

write_test_file() {
    local dir="$1"
    local content="$2"
    mkdir -p "${dir}/tests/Pkg.Tests"
    printf '%s\n' "${content}" > "${dir}/tests/Pkg.Tests/SomeTests.cs"
}

PASS=0
FAIL=0
record_pass() { PASS=$((PASS + 1)); echo "PASS: $1"; }
record_fail() { FAIL=$((FAIL + 1)); echo "FAIL: $1" >&2; }

assert_exit() {
    local name="$1"
    local expected="$2"
    local dir="$3"
    set +e
    bash "${TARGET}" "${dir}" >/dev/null 2>&1
    local actual=$?
    set -e
    if [[ "${actual}" -eq "${expected}" ]]; then
        record_pass "${name} (exit ${actual})"
    else
        record_fail "${name} (expected ${expected}, got ${actual})"
    fi
}

# Case 1: every cited test exists -> pass.
CASE1="${WORK_DIR}/case1"
write_doc "${CASE1}" 'Closed — proven by `Foo_does_the_right_thing` and `Bar_rejects_bad_input`.'
write_test_file "${CASE1}" 'public void Foo_does_the_right_thing() {} public void Bar_rejects_bad_input() {}'
assert_exit "all cited tests exist" 0 "${CASE1}"

# Case 2: a cited test is declared nowhere -> fail.
CASE2="${WORK_DIR}/case2"
write_doc "${CASE2}" 'Closed — proven by `Foo_does_the_right_thing` and `Gone_after_a_rename`.'
write_test_file "${CASE2}" 'public void Foo_does_the_right_thing() {}'
assert_exit "missing cited test fails" 1 "${CASE2}"

# Case 3: the preamble's hypothetical example is not a citation -> pass without it existing.
CASE3="${WORK_DIR}/case3"
write_doc "${CASE3}" 'Closed — proven by `Foo_does_the_right_thing`.'
write_test_file "${CASE3}" 'public void Foo_does_the_right_thing() {}'
assert_exit "preamble example is ignored" 0 "${CASE3}"

# Case 4: non-test identifiers — PascalCase members and underscore-prefixed fields — are not
# citations even when they exist in no test file.
CASE4="${WORK_DIR}/case4"
write_doc "${CASE4}" 'The `_readGate` field on `SomeUnreferencedType` — proven by `Foo_does_the_right_thing`.'
write_test_file "${CASE4}" 'public void Foo_does_the_right_thing() {}'
assert_exit "fields and PascalCase identifiers are ignored" 0 "${CASE4}"

# Case 5: extracting zero citations fails rather than passing vacuously.
CASE5="${WORK_DIR}/case5"
write_doc "${CASE5}" 'An entry citing nothing at all.'
write_test_file "${CASE5}" '// no tests'
assert_exit "zero extracted citations fails as vacuous" 1 "${CASE5}"

# Case 6: a name present only in a non-.cs file under tests/ does not count.
CASE6="${WORK_DIR}/case6"
write_doc "${CASE6}" 'Closed — proven by `Only_in_a_text_file`.'
write_test_file "${CASE6}" '// no tests'
printf 'Only_in_a_text_file\n' > "${CASE6}/tests/Pkg.Tests/notes.txt"
assert_exit "name only in a non-.cs file still fails" 1 "${CASE6}"

echo
echo "Smoke test summary: ${PASS} passed, ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]]
