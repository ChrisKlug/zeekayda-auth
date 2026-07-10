#!/usr/bin/env bash
# Smoke tests for .github/scripts/summarize_coverage.cs
#
# Builds synthetic Cobertura inputs and asserts that the summarizer produces
# one row per package (merging same-named packages across files rather than
# duplicating them) and writes a markdown table to GITHUB_STEP_SUMMARY.
#
# Invoked from CI (`.github/workflows/ci.yml`) and can be run locally:
#   bash .github/scripts/tests/summarize_coverage.tests.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
TARGET="${REPO_ROOT}/.github/scripts/summarize_coverage.cs"

if [[ ! -f "${TARGET}" ]]; then
    echo "FAIL: cannot find ${TARGET}" >&2
    exit 1
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

write_cobertura() {
    local dir="$1"
    local package_name="$2"
    local lines_covered="$3"
    local lines_valid="$4"
    mkdir -p "${dir}"
    cat > "${dir}/coverage.cobertura.xml" <<XML
<?xml version="1.0" encoding="utf-8"?>
<coverage line-rate="0" branch-rate="0" lines-covered="0" lines-valid="0" branches-covered="0" branches-valid="0" complexity="0" version="1.9" timestamp="0">
  <packages>
    <package name="${package_name}" line-rate="0" branch-rate="0" complexity="0">
      <classes>
        <class name="Sample" filename="src/Sample.cs" line-rate="0" branch-rate="0" complexity="0">
          <methods />
          <lines>
$(for ((i = 1; i <= lines_valid; i++)); do
    if ((i <= lines_covered)); then
        echo "            <line number=\"${i}\" hits=\"1\" branch=\"false\" />"
    else
        echo "            <line number=\"${i}\" hits=\"0\" branch=\"false\" />"
    fi
done)
          </lines>
        </class>
      </classes>
    </package>
  </packages>
</coverage>
XML
}

run_summarize() {
    local dir="$1"
    local label="${2:-}"
    (
        cd "${REPO_ROOT}"
        # This is a smoke-test invocation of the script, not the real CI build-and-test step —
        # unset GITHUB_STEP_SUMMARY so it doesn't pollute the actual job summary.
        unset GITHUB_STEP_SUMMARY
        if [[ -n "${label}" ]]; then
            dotnet run --no-launch-profile "${TARGET}" -- "${dir}" "${label}"
        else
            dotnet run --no-launch-profile "${TARGET}" -- "${dir}"
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
    "$@" >/dev/null
    local actual=$?
    set -e
    if [[ "${actual}" -eq "${expected}" ]]; then
        record_pass "${name} (exit ${actual})"
    else
        record_fail "${name} (expected ${expected}, got ${actual})"
    fi
}

# Case 1: single package → succeeds
SINGLE="${WORK_DIR}/case1"
write_cobertura "${SINGLE}" "ZeeKayDa.Auth.AspNetCore" 8 10
assert_exit "single package succeeds" 0 run_summarize "${SINGLE}"

# Case 2: two distinct packages across two files → both rows present
MULTI="${WORK_DIR}/case2/pkgA"
MULTI2="${WORK_DIR}/case2/pkgB"
write_cobertura "${MULTI}" "ZeeKayDa.Auth.AspNetCore" 8 10
write_cobertura "${MULTI2}" "ZeeKayDa.Auth.AzureKeyVault" 9 10
OUTPUT="$(run_summarize "${WORK_DIR}/case2")"
if [[ "${OUTPUT}" == *"ZeeKayDa.Auth.AspNetCore"* && "${OUTPUT}" == *"ZeeKayDa.Auth.AzureKeyVault"* ]]; then
    record_pass "two distinct packages both reported"
else
    record_fail "two distinct packages both reported (got: ${OUTPUT})"
fi

# Case 3: same package name split across two files → merged into one row, not duplicated
SPLIT="${WORK_DIR}/case3/part1"
SPLIT2="${WORK_DIR}/case3/part2"
write_cobertura "${SPLIT}" "ZeeKayDa.Auth" 8 10
write_cobertura "${SPLIT2}" "ZeeKayDa.Auth" 2 10
OUTPUT="$(run_summarize "${WORK_DIR}/case3")"
OCCURRENCES="$(grep -o "ZeeKayDa.Auth" <<< "${OUTPUT}" | wc -l | tr -d ' ')"
if [[ "${OCCURRENCES}" -eq 1 && "${OUTPUT}" == *"50.00%"* ]]; then
    record_pass "same-named package merged, not duplicated (10/20 = 50.00%)"
else
    record_fail "same-named package merged, not duplicated (got ${OCCURRENCES} occurrences: ${OUTPUT})"
fi

# Case 4: no coverage files found → error (exit 1)
EMPTY="${WORK_DIR}/case4/empty"
mkdir -p "${EMPTY}"
assert_exit "missing coverage files errors" 1 run_summarize "${EMPTY}"

# Case 5: GITHUB_STEP_SUMMARY is honored when set directly (not via run_summarize's isolation)
SUMMARY_FILE="${WORK_DIR}/case5-summary.md"
write_cobertura "${WORK_DIR}/case5" "ZeeKayDa.Auth.FileSystem" 5 10
(
    cd "${REPO_ROOT}"
    GITHUB_STEP_SUMMARY="${SUMMARY_FILE}" dotnet run --no-launch-profile "${TARGET}" -- "${WORK_DIR}/case5" >/dev/null
)
if [[ -f "${SUMMARY_FILE}" ]] && grep -q "ZeeKayDa.Auth.FileSystem" "${SUMMARY_FILE}"; then
    record_pass "writes markdown table to GITHUB_STEP_SUMMARY when set"
else
    record_fail "writes markdown table to GITHUB_STEP_SUMMARY when set"
fi

# Case 6: an optional label (e.g. runner.os) is embedded in the summary heading, so per-OS
# build-and-test tables are distinguishable when GitHub stacks every job's summary together.
LABEL_SUMMARY_FILE="${WORK_DIR}/case6-summary.md"
write_cobertura "${WORK_DIR}/case6" "ZeeKayDa.Auth.Windows" 4 10
(
    cd "${REPO_ROOT}"
    GITHUB_STEP_SUMMARY="${LABEL_SUMMARY_FILE}" dotnet run --no-launch-profile "${TARGET}" -- "${WORK_DIR}/case6" "Windows" >/dev/null
)
if [[ -f "${LABEL_SUMMARY_FILE}" ]] && grep -q "### Coverage Summary (Windows)" "${LABEL_SUMMARY_FILE}"; then
    record_pass "label is embedded in the summary heading when provided"
else
    record_fail "label is embedded in the summary heading when provided"
fi

echo
echo "Smoke test summary: ${PASS} passed, ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]]
