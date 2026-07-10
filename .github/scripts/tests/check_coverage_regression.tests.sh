#!/usr/bin/env bash
# Smoke tests for .github/scripts/check_coverage_regression.cs
#
# Builds synthetic Cobertura inputs and asserts that the regression checker
# exits 0 on improvement / no-change and exits 1 on regression.
#
# Invoked from CI (`.github/workflows/ci.yml`) and can be run locally:
#   bash .github/scripts/tests/check_coverage_regression.tests.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
TARGET="${REPO_ROOT}/.github/scripts/check_coverage_regression.cs"

if [[ ! -f "${TARGET}" ]]; then
    echo "FAIL: cannot find ${TARGET}" >&2
    exit 1
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

write_cobertura() {
    local dir="$1"
    local lines_covered="$2"
    local lines_valid="$3"
    local branches_covered="$4"
    local branches_valid="$5"
    mkdir -p "${dir}"
    cat > "${dir}/coverage.cobertura.xml" <<XML
<?xml version="1.0" encoding="utf-8"?>
<coverage line-rate="0" branch-rate="0" lines-covered="${lines_covered}" lines-valid="${lines_valid}" branches-covered="${branches_covered}" branches-valid="${branches_valid}" complexity="0" version="1.9" timestamp="0">
  <packages />
</coverage>
XML
}

run_check() {
    local pr_dir="$1"
    local base_dir="$2"
    local allowed="${3:-}"
    (
        cd "${REPO_ROOT}"
        # This is a smoke-test invocation of the script, not the real CI regression-check step —
        # unset GITHUB_STEP_SUMMARY so it doesn't pollute the actual job summary.
        unset GITHUB_STEP_SUMMARY
        if [[ -n "${allowed}" ]]; then
            COVERAGE_ALLOWED_REGRESSION_PERCENT="${allowed}" \
                dotnet run --no-launch-profile "${TARGET}" -- "${pr_dir}" "${base_dir}" >/dev/null
        else
            dotnet run --no-launch-profile "${TARGET}" -- "${pr_dir}" "${base_dir}" >/dev/null
        fi
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

# Case 1: identical coverage → pass (exit 0)
BASE="${WORK_DIR}/case1/base"
PR="${WORK_DIR}/case1/pr"
write_cobertura "${BASE}" 80 100 40 50
write_cobertura "${PR}"   80 100 40 50
assert_exit "no change passes" 0 run_check "${PR}" "${BASE}"

# Case 2: PR improves coverage → pass (exit 0)
BASE="${WORK_DIR}/case2/base"
PR="${WORK_DIR}/case2/pr"
write_cobertura "${BASE}" 70 100 30 50
write_cobertura "${PR}"   90 100 45 50
assert_exit "improvement passes" 0 run_check "${PR}" "${BASE}"

# Case 3: PR regresses line coverage → fail (exit 1)
BASE="${WORK_DIR}/case3/base"
PR="${WORK_DIR}/case3/pr"
write_cobertura "${BASE}" 90 100 45 50
write_cobertura "${PR}"   70 100 35 50
assert_exit "regression fails" 1 run_check "${PR}" "${BASE}"

# Case 4: Regression within COVERAGE_ALLOWED_REGRESSION_PERCENT → pass (exit 0)
BASE="${WORK_DIR}/case4/base"
PR="${WORK_DIR}/case4/pr"
write_cobertura "${BASE}" 90 100 45 50
write_cobertura "${PR}"   88 100 44 50
assert_exit "regression within tolerance passes" 0 run_check "${PR}" "${BASE}" "5"

# Case 5: Missing Cobertura file → error (exit 1)
EMPTY="${WORK_DIR}/case5/empty"
PR="${WORK_DIR}/case5/pr"
mkdir -p "${EMPTY}"
write_cobertura "${PR}" 80 100 40 50
assert_exit "missing baseline errors" 1 run_check "${PR}" "${EMPTY}"

echo
echo "Smoke test summary: ${PASS} passed, ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]]
