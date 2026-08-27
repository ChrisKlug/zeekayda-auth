#!/usr/bin/env bash
# Enforces the sign-off citation contract for docs/decisions/security-sign-offs.md (issue #565).
#
# Sign-off entries prove their claims by citing test names in backticks
# ("closed — proven by `Some_test_name`"). Nothing else stops a cited test from
# being deleted or renamed while the sign-off keeps pointing at it, which would
# quietly turn a proven claim into an unproven one. This script extracts every
# cited test name from the entries and fails when one is declared in no
# tests/**/*.cs file.
#
# What counts as a cited test name: a backticked identifier that starts with a
# letter and contains an underscore. Test names in this repo are
# underscore-separated sentences; other cited identifiers (types, members, enum
# values) are PascalCase without underscores, and private fields start with an
# underscore. The file's rules preamble (everything before the first `---`
# separator) is skipped — its example test name is hypothetical by design.
#
# Usage: bash .github/scripts/check_sign_off_citations.sh <repo-root>

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <repo-root>" >&2
    exit 2
fi

ROOT="$1"
DOC="docs/decisions/security-sign-offs.md"

if [[ ! -f "${ROOT}/${DOC}" ]]; then
    echo "::error::${DOC} not found under ${ROOT}" >&2
    exit 2
fi

if [[ ! -d "${ROOT}/tests" ]]; then
    echo "::error::tests/ not found under ${ROOT}" >&2
    exit 2
fi

cited="$(sed '1,/^---$/d' "${ROOT}/${DOC}" \
    | grep -o '`[A-Za-z][A-Za-z0-9_]*`' \
    | tr -d '`' \
    | grep '_' \
    | sort -u || true)"

if [[ -z "${cited}" ]]; then
    # The file is known to cite tests; extracting none means the extraction is
    # broken (or the file was gutted), not that everything passes.
    echo "::error file=${DOC}::No cited test names extracted from ${DOC} — the citation check would be vacuous."
    exit 1
fi

total=0
status=0
while read -r name; do
    total=$((total + 1))
    if ! grep -rqF "${name}" "${ROOT}/tests" --include='*.cs'; then
        line="$(grep -nF "\`${name}\`" "${ROOT}/${DOC}" | head -1 | cut -d: -f1)"
        echo "::error file=${DOC},line=${line}::Cited test \`${name}\` is declared in no tests/**/*.cs file. Sign-off citations must point at existing tests — restore or rename the citation."
        status=1
    fi
done <<< "${cited}"

echo "Checked ${total} distinct cited test names against tests/**/*.cs."
exit "${status}"
