#!/usr/bin/env bash
# Smoke tests for .github/scripts/report_mutation_scores.cs
#
# Builds synthetic Stryker JSON reports laid out the way actions/download-artifact drops the
# mutation.yml legs, and asserts the four behaviours the weekly report depends on: the score
# formula, the core slice roll-up, change detection against the previous run's state block, and
# honest handling of a leg that produced no report.
#
# Invoked from CI (`.github/workflows/ci.yml`) and can be run locally:
#   bash .github/scripts/tests/report_mutation_scores.tests.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
TARGET="${REPO_ROOT}/.github/scripts/report_mutation_scores.cs"

if [[ ! -f "${TARGET}" ]]; then
    echo "FAIL: cannot find ${TARGET}" >&2
    exit 1
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

# Writes a Stryker JSON report for one leg, under the nesting download-artifact produces.
# Statuses beyond the four scored ones are included so their exclusion is actually exercised.
write_report() {
    local artifacts_dir="$1"
    local leg="$2"
    local killed="$3"
    local survived="$4"
    local dir="${artifacts_dir}/mutation-report-${leg}/reports"
    mkdir -p "${dir}"
    {
        printf '{"schemaVersion":"1","files":{"Sample.cs":{"language":"cs","source":"","mutants":['
        local first=1
        emit() {
            if ((first)); then first=0; else printf ','; fi
            printf '{"id":"%s","mutatorName":"Block","status":"%s"}' "$2" "$1"
        }
        for ((i = 0; i < killed; i++)); do emit "Killed" "k${i}"; done
        for ((i = 0; i < survived; i++)); do emit "Survived" "s${i}"; done
        emit "Ignored" "i0"
        emit "CompileError" "c0"
        emit "RuntimeError" "r0"
        printf ']}}}'
    } > "${dir}/mutation-report.json"
}

# A leg whose job failed: the artifact is still uploaded (`if: always()`) but holds no report.
write_empty_leg() {
    mkdir -p "$1/mutation-report-$2/reports"
}

run_report() {
    local artifacts_dir="$1"
    local previous_body="$2"
    local out_dir="$3"
    (
        cd "${REPO_ROOT}"
        # Smoke-test invocation, not the real workflow step — unset GITHUB_OUTPUT so it does not
        # pollute a real job's outputs when this runs inside CI.
        unset GITHUB_OUTPUT
        dotnet run --no-launch-profile "${TARGET}" -- \
            "${artifacts_dir}" "${previous_body}" "${out_dir}" "2026-01-04"
    )
}

PASS=0
FAIL=0
record_pass() { PASS=$((PASS + 1)); echo "PASS: $1"; }
record_fail() { FAIL=$((FAIL + 1)); echo "FAIL: $1" >&2; }

assert_contains() {
    local name="$1"
    local haystack="$2"
    local needle="$3"
    if [[ "${haystack}" == *"${needle}"* ]]; then
        record_pass "${name}"
    else
        record_fail "${name} (expected to find '${needle}' in: ${haystack})"
    fi
}

assert_missing() {
    local name="$1"
    local haystack="$2"
    local needle="$3"
    if [[ "${haystack}" != *"${needle}"* ]]; then
        record_pass "${name}"
    else
        record_fail "${name} (did not expect '${needle}' in: ${haystack})"
    fi
}

# Case 1: a single unsliced leg. 8 killed / 2 survived = 80.00 %, with the Ignored, CompileError
# and RuntimeError mutants excluded from both halves rather than counted as survivors.
CASE1="${WORK_DIR}/case1"
write_report "${CASE1}/artifacts" "ZeeKayDa.Auth.FileSystem.Tests" 8 2
run_report "${CASE1}/artifacts" "${CASE1}/no-such-body.md" "${CASE1}/out" >/dev/null
BODY="$(cat "${CASE1}/out/body.md")"
assert_contains "unscored statuses are excluded from the formula" "${BODY}" "**80.00 %**"
assert_contains "first run records the score in the state block" "${BODY}" '"ZeeKayDa.Auth.FileSystem.Tests":80'
assert_contains "first run posts a comment" "$(ls "${CASE1}/out")" "comment.md"

# Case 2: the three core slices roll up into one ZeeKayDa.Auth.Tests row. Summing raw mutant
# counts (30 killed / 10 survived across the legs) gives 75.00 %, which is NOT the mean of the
# three slice percentages (80.00, 75.00, 71.43 → 75.48) — the distinction this row exists for.
CASE2="${WORK_DIR}/case2"
write_report "${CASE2}/artifacts" "ZeeKayDa.Auth.Tests-tokens" 16 4
write_report "${CASE2}/artifacts" "ZeeKayDa.Auth.Tests-clients" 9 3
write_report "${CASE2}/artifacts" "ZeeKayDa.Auth.Tests-security-authorization" 5 3
run_report "${CASE2}/artifacts" "${CASE2}/no-such-body.md" "${CASE2}/out" >/dev/null
BODY="$(cat "${CASE2}/out/body.md")"
assert_contains "core slices roll up by mutant count, not by mean" "${BODY}" '"ZeeKayDa.Auth.Tests":75'
assert_missing "roll-up is not the mean of the slice percentages" "${BODY}" '"ZeeKayDa.Auth.Tests":75.48'
assert_contains "the slice keeps its own row" "${BODY}" "ZeeKayDa.Auth.Tests-tokens"
assert_contains "a multi-part slice name stays whole" "${BODY}" "ZeeKayDa.Auth.Tests-security-authorization"

# Case 3: an unchanged score posts no comment; a moved one does. The previous body from case 1 is
# the input, so this exercises the real read-back path rather than a hand-written state block.
CASE3="${WORK_DIR}/case3"
write_report "${CASE3}/artifacts" "ZeeKayDa.Auth.FileSystem.Tests" 8 2
run_report "${CASE3}/artifacts" "${CASE1}/out/body.md" "${CASE3}/out" >/dev/null
assert_missing "an unchanged score posts no comment" "$(ls "${CASE3}/out")" "comment.md"

CASE3B="${WORK_DIR}/case3b"
write_report "${CASE3B}/artifacts" "ZeeKayDa.Auth.FileSystem.Tests" 7 3
run_report "${CASE3B}/artifacts" "${CASE1}/out/body.md" "${CASE3B}/out" >/dev/null
COMMENT="$(cat "${CASE3B}/out/comment.md")"
assert_contains "a dropped score posts a comment naming the delta" "${COMMENT}" "80.00 % → 70.00 % (-10.00 pp)"

# Case 4: one core slice fails. Its own row reports no score, and the target row refuses to roll
# up a partial scope rather than publishing a number that silently covers less code.
CASE4="${WORK_DIR}/case4"
write_report "${CASE4}/artifacts" "ZeeKayDa.Auth.Tests-tokens" 16 4
write_report "${CASE4}/artifacts" "ZeeKayDa.Auth.Tests-clients" 9 3
write_empty_leg "${CASE4}/artifacts" "ZeeKayDa.Auth.Tests-security-authorization"
run_report "${CASE4}/artifacts" "${CASE2}/out/body.md" "${CASE4}/out" >/dev/null
BODY="$(cat "${CASE4}/out/body.md")"
COMMENT="$(cat "${CASE4}/out/comment.md")"
assert_contains "a failed leg does not produce a partial roll-up" "${BODY}" '"ZeeKayDa.Auth.Tests":null'
assert_contains "the failed leg reports no score" "${BODY}" '"ZeeKayDa.Auth.Tests-security-authorization":null'
assert_contains "the comment says a leg failed" "${COMMENT}" "a leg likely failed"

# Case 5: nothing to report at all is an error, not a silent green run that wipes the issue body.
CASE5="${WORK_DIR}/case5"
mkdir -p "${CASE5}/artifacts"
set +e
run_report "${CASE5}/artifacts" "${CASE5}/no-such-body.md" "${CASE5}/out" >/dev/null 2>&1
EXIT_CODE=$?
set -e
if [[ "${EXIT_CODE}" -eq 1 ]]; then
    record_pass "no reports and no previous scores fails the job"
else
    record_fail "no reports and no previous scores fails the job (expected 1, got ${EXIT_CODE})"
fi

# Case 6: a corrupted state block is treated as a first run rather than failing the report.
CASE6="${WORK_DIR}/case6"
write_report "${CASE6}/artifacts" "ZeeKayDa.Auth.FileSystem.Tests" 8 2
printf 'Some text\n<!-- mutation-scores: {not json -->\n' > "${CASE6}/previous.md"
run_report "${CASE6}/artifacts" "${CASE6}/previous.md" "${CASE6}/out" >/dev/null
assert_contains "a corrupted state block falls back to a first run" \
    "$(cat "${CASE6}/out/body.md")" '"ZeeKayDa.Auth.FileSystem.Tests":80'

echo
echo "Smoke test summary: ${PASS} passed, ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]]
