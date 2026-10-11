#!/usr/bin/env bash
# Fails a PR that closes an area:security issue without adding that issue's security sign-off entry
# (issue #927). The loop writes the entry as the PR's last commit, and it was missed at merge more
# than once with nothing to catch it.
#
# An entry is a heading added to docs/decisions/security-sign-offs.md that names the issue:
#   ## 2026-10-10 — <what was signed off> (#916, code frozen at `6e16d45`)
# One heading may name several issues: (#513, #514, ...).
# A PR whose body has a line "No security sign-off: <reason>" passes: about a third of security
# issues make no trust-boundary decision.
#
# The heading must be new: a PR that edits an old heading to name the issue adds no entry, so the
# headings it adds must outnumber those it removes. Bracketed notes in old entries are not headings.
#
# Usage: bash .github/scripts/check_sign_off_present.sh <diff-file> <pr-body-file> [issue-number...]
#   <diff-file>     the PR's unified diff of docs/decisions/security-sign-offs.md
#   <pr-body-file>  the PR body
#   issue-number        each issue the PR closes that is labelled area:security

set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <diff-file> <pr-body-file> [issue-number...]" >&2
    exit 2
fi

DIFF="$1"
BODY="$2"
shift 2

HEADING='## [0-9]{4}-[0-9]{2}-[0-9]{2} — '

if [[ $# -eq 0 ]]; then
    echo "The PR closes no area:security issue; no sign-off entry is required."
    exit 0
fi

if grep -qE '^[[:space:]]*No security sign-off:[[:space:]]*[^[:space:]]' "${BODY}"; then
    echo "The PR body states no security sign-off is needed: $(grep -m1 -E '^[[:space:]]*No security sign-off:' "${BODY}" | sed -E 's/^[[:space:]]*//')"
    exit 0
fi

added=$(grep -cE "^\+${HEADING}" "${DIFF}" || true)
removed=$(grep -cE "^-${HEADING}" "${DIFF}" || true)
if [[ "${added}" -le "${removed}" ]]; then
    echo "::error file=docs/decisions/security-sign-offs.md::This PR closes an area:security issue but adds no new sign-off heading (${added} added, ${removed} removed); editing an old entry's heading does not sign off this change. Append the entry as the PR's last commit — or, if the change makes no trust-boundary decision, add a line 'No security sign-off: <reason>' to the PR body."
    exit 1
fi

status=0
for issue in "$@"; do
    if grep -qE "^\+${HEADING}.*[(, ]#${issue}[,) ]" "${DIFF}"; then
        echo "#${issue}: sign-off entry added."
    else
        echo "::error file=docs/decisions/security-sign-offs.md::#${issue} is labelled area:security and this PR adds no sign-off entry for it. Add the entry as the PR's last commit, against frozen code — or, if the change makes no trust-boundary decision, add a line 'No security sign-off: <reason>' to the PR body."
        status=1
    fi
done

exit "${status}"
