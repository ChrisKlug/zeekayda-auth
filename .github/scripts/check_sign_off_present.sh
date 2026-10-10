#!/usr/bin/env bash
# Fails a PR that closes an area:security issue without adding that issue's security sign-off entry
# (issue #927). The loop writes the entry as the PR's last commit, and it was missed at merge more
# than once with nothing to catch it.
#
# An entry is a heading added to docs/decisions/security-sign-offs.md that names the issue:
#   ## 2026-10-10 — <what was signed off> (#916, code frozen at `6e16d45`)
# A PR whose body has a line "No security sign-off: <reason>" passes: about a third of security
# issues make no trust-boundary decision.
#
# Usage: bash .github/scripts/check_sign_off_present.sh <added-lines-file> <pr-body-file> [issue-number...]
#   <added-lines-file>  the lines the PR adds to security-sign-offs.md, one per line, without the "+"
#   <pr-body-file>      the PR body
#   issue-number        each issue the PR closes that is labelled area:security

set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <added-lines-file> <pr-body-file> [issue-number...]" >&2
    exit 2
fi

ADDED="$1"
BODY="$2"
shift 2

if [[ $# -eq 0 ]]; then
    echo "The PR closes no area:security issue; no sign-off entry is required."
    exit 0
fi

if grep -qE '^[[:space:]]*No security sign-off:[[:space:]]*[^[:space:]]' "${BODY}"; then
    echo "The PR body states no security sign-off is needed: $(grep -m1 -E '^[[:space:]]*No security sign-off:' "${BODY}" | sed -E 's/^[[:space:]]*//')"
    exit 0
fi

status=0
for issue in "$@"; do
    if grep -qE "^## [0-9]{4}-[0-9]{2}-[0-9]{2} — .*\(#${issue}[,) ]" "${ADDED}"; then
        echo "#${issue}: sign-off entry added."
    else
        echo "::error file=docs/decisions/security-sign-offs.md::#${issue} is labelled area:security and this PR adds no sign-off entry for it. Add the entry as the PR's last commit, against frozen code — or, if the change makes no trust-boundary decision, add a line 'No security sign-off: <reason>' to the PR body."
        status=1
    fi
done

exit "${status}"
