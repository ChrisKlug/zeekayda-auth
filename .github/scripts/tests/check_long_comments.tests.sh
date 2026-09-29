#!/usr/bin/env bash
# Smoke tests for .github/scripts/check_long_comments.sh
#
# Builds a throwaway git repository, commits a base, adds changes on top, and asserts which
# added comment blocks are warned about.
#
# Invoked from CI (`.github/workflows/ci.yml`) and can be run locally:
#   bash .github/scripts/tests/check_long_comments.tests.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${SCRIPT_DIR}/../check_long_comments.sh"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

failures=0

run_case() {
    local name="$1" path="$2" content="$3" expected="$4"
    local repo="${WORK_DIR}/${name}"
    mkdir -p "${repo}"
    git -C "${repo}" init -q
    git -C "${repo}" -c user.name=t -c user.email=t@t commit -q --allow-empty -m base
    mkdir -p "${repo}/$(dirname "${path}")"
    printf '%s\n' "${content}" > "${repo}/${path}"
    git -C "${repo}" add -A
    git -C "${repo}" -c user.name=t -c user.email=t@t commit -q -m change
    local out
    out="$(cd "${repo}" && bash "${TARGET}" HEAD~1)"
    local count
    count="$(printf '%s' "${out}" | grep -c '::warning' || true)"
    if [[ "${count}" != "${expected}" ]]; then
        echo "FAIL: ${name}: expected ${expected} warning(s), got ${count}"
        printf '%s\n' "${out}"
        failures=$((failures + 1))
    else
        echo "ok: ${name}"
    fi
}

run_case three_lines_is_fine src/A.cs $'class A\n{\n    // one\n    // two\n    // three\n    void M() { }\n}' 0

run_case four_lines_warns src/A.cs $'class A\n{\n    // one\n    // two\n    // three\n    // four\n    void M() { }\n}' 1

run_case two_separate_blocks_are_counted_separately src/A.cs $'class A\n{\n    // one\n    // two\n    void M() { }\n    // three\n    // four\n    void N() { }\n}' 0

run_case xml_docs_are_not_counted src/A.cs $'/// <summary>\n/// one\n/// two\n/// three\n/// </summary>\nclass A { }' 0

run_case log_hygiene_justification_is_not_counted src/A.cs $'class A\n{\n    // one\n    // two\n    // three\n    // log-hygiene-ok: reason (#1)\n}' 0

run_case bare_log_hygiene_marker_still_counts src/A.cs $'class A\n{\n    // one\n    // two\n    // log-hygiene-ok\n    // four\n}' 1

run_case marker_text_in_prose_still_counts src/A.cs $'class A\n{\n    // one\n    // two mentions log-hygiene-ok: in passing (#1)\n    // three\n    // four\n}' 1

run_case trailing_code_comments_are_not_counted src/A.cs $'class A\n{\n    int a; // one\n    int b; // two\n    int c; // three\n    int d; // four\n}' 0

run_case tests_are_not_checked tests/A.cs $'class A\n{\n    // one\n    // two\n    // three\n    // four\n}' 0

run_case warning_names_file_and_first_line src/B.cs $'class B\n{\n    // one\n    // two\n    // three\n    // four\n}' 1
out="$(cd "${WORK_DIR}/warning_names_file_and_first_line" && bash "${TARGET}" HEAD~1)"
if [[ "${out}" != *"file=src/B.cs,line=3::"* ]]; then
    echo "FAIL: warning_names_file_and_first_line: ${out}"
    failures=$((failures + 1))
fi

if [[ "${failures}" -ne 0 ]]; then
    echo "${failures} case(s) failed"
    exit 1
fi
echo "All check_long_comments cases passed"
