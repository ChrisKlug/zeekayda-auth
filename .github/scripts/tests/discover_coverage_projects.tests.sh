#!/usr/bin/env bash
# Smoke tests for .github/scripts/discover_coverage_projects.cs
#
# Builds a synthetic repo layout (a ZeeKayDa.Auth.slnx plus paired src/tests
# projects) and asserts the discovery script lists cross-platform packages,
# excludes OS-restricted ones, and fails loudly on convention violations.
#
# Invoked from CI (`.github/workflows/ci.yml`) and can be run locally:
#   bash .github/scripts/tests/discover_coverage_projects.tests.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
TARGET="${REPO_ROOT}/.github/scripts/discover_coverage_projects.cs"

if [[ ! -f "${TARGET}" ]]; then
    echo "FAIL: cannot find ${TARGET}" >&2
    exit 1
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

write_slnx() {
    local dir="$1"
    shift
    local test_project_lines=""

    for name in "$@"; do
        test_project_lines+="    <Project Path=\"tests/${name}.Tests/${name}.Tests.csproj\" />"$'\n'
    done

    mkdir -p "${dir}"
    cat > "${dir}/ZeeKayDa.Auth.slnx" <<XML
<Solution>
  <Folder Name="/tests/">
${test_project_lines}  </Folder>
</Solution>
XML
}

write_project() {
    local dir="$1"
    local package_name="$2"
    local target_frameworks="$3"
    local kind="$4" # "src" or "tests"
    local project_dir

    if [[ "${kind}" == "src" ]]; then
        project_dir="${dir}/src/${package_name}"
        mkdir -p "${project_dir}"
        cat > "${project_dir}/${package_name}.csproj" <<XML
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFrameworks>${target_frameworks}</TargetFrameworks>
  </PropertyGroup>
</Project>
XML
    else
        project_dir="${dir}/tests/${package_name}.Tests"
        mkdir -p "${project_dir}"
        cat > "${project_dir}/${package_name}.Tests.csproj" <<XML
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
  </PropertyGroup>
</Project>
XML
    fi
}

run_discover() {
    local dir="$1"
    (
        cd "${REPO_ROOT}"
        dotnet run --no-launch-profile "${TARGET}" -- "${dir}"
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
    "$@" >/dev/null 2>&1
    local actual=$?
    set -e
    if [[ "${actual}" -eq "${expected}" ]]; then
        record_pass "${name} (exit ${actual})"
    else
        record_fail "${name} (expected ${expected}, got ${actual})"
    fi
}

# Case 1: a mix of cross-platform and Windows-only packages -> only cross-platform ones listed,
# sorted, and the Windows-only one is excluded.
CASE1="${WORK_DIR}/case1"
write_slnx "${CASE1}" "PkgB" "PkgA" "PkgWindows"
write_project "${CASE1}" "PkgA" "net10.0" "src"
write_project "${CASE1}" "PkgA" "" "tests"
write_project "${CASE1}" "PkgB" "net10.0" "src"
write_project "${CASE1}" "PkgB" "" "tests"
write_project "${CASE1}" "PkgWindows" "net10.0-windows" "src"
write_project "${CASE1}" "PkgWindows" "" "tests"
OUTPUT="$(run_discover "${CASE1}")"
EXPECTED=$'PkgA\nPkgB'
if [[ "${OUTPUT}" == "${EXPECTED}" ]]; then
    record_pass "cross-platform packages discovered, sorted, Windows-only excluded"
else
    record_fail "cross-platform packages discovered, sorted, Windows-only excluded (got: ${OUTPUT})"
fi

# Case 2: a multi-targeted package with at least one cross-platform TFM stays eligible even though
# one of its other TFMs is platform-specific.
CASE2="${WORK_DIR}/case2"
write_slnx "${CASE2}" "PkgMulti"
write_project "${CASE2}" "PkgMulti" "net10.0;net10.0-windows" "src"
write_project "${CASE2}" "PkgMulti" "" "tests"
OUTPUT="$(run_discover "${CASE2}")"
if [[ "${OUTPUT}" == "PkgMulti" ]]; then
    record_pass "multi-targeted package with a cross-platform TFM stays eligible"
else
    record_fail "multi-targeted package with a cross-platform TFM stays eligible (got: ${OUTPUT})"
fi

# Case 3: a package whose every TFM is platform-specific is excluded even when multi-targeted.
CASE3="${WORK_DIR}/case3"
write_slnx "${CASE3}" "PkgAllWindows"
write_project "${CASE3}" "PkgAllWindows" "net10.0-windows;net9.0-windows" "src"
write_project "${CASE3}" "PkgAllWindows" "" "tests"
assert_exit "package with only platform-specific TFMs yields no eligible packages" 1 run_discover "${CASE3}"

# Case 4: a test project that doesn't follow the <PackageName>.Tests naming convention fails loudly
# rather than silently mis-deriving a package name.
CASE4="${WORK_DIR}/case4"
mkdir -p "${CASE4}/tests/Oddball"
cat > "${CASE4}/ZeeKayDa.Auth.slnx" <<XML
<Solution>
  <Folder Name="/tests/">
    <Project Path="tests/Oddball/Oddball.csproj" />
  </Folder>
</Solution>
XML
touch "${CASE4}/tests/Oddball/Oddball.csproj"
assert_exit "test project not following naming convention fails" 1 run_discover "${CASE4}"

# Case 5: a test project with no paired src project fails loudly rather than skipping silently.
CASE5="${WORK_DIR}/case5"
write_slnx "${CASE5}" "Orphan"
write_project "${CASE5}" "Orphan" "" "tests"
assert_exit "test project with no paired src project fails" 1 run_discover "${CASE5}"

echo
echo "Smoke test summary: ${PASS} passed, ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]]
