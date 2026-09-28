#!/usr/bin/env bash
# Warns about added blocks of more than three consecutive `//` comment lines in src/**/*.cs.
#
# Comments drift back to verbose after every cleanup, and prose rules alone have not held them.
# This is advisory: a long comment that is genuinely a permanent *why* stays, and the author says
# so in the PR. `///` XML docs and `log-hygiene-ok` suppression justifications are not counted.
#
# Usage: bash .github/scripts/check_long_comments.sh <base-ref>
# Emits one GitHub `::warning` annotation per block and always exits 0.

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <base-ref>" >&2
    exit 2
fi

MAX_LINES=3
RULE=".claude/agents/developer.md (Comments and XML Docs)"

git diff --no-color --unified=0 "$1" HEAD -- ':(glob)src/**/*.cs' | awk -v max="${MAX_LINES}" -v rule="${RULE}" '
    function flush() {
        if (run > max)
            printf "::warning file=%s,line=%d::Added comment block of %d lines (more than %d). Try a name or an extraction first; keep it only if it is a permanent why. See %s.\n", file, start, run, max, rule
        run = 0
    }
    /^\+\+\+ / { flush(); file = substr($0, 7); next }
    /^@@ / {
        flush()
        split($3, parts, ",")
        line = substr(parts[1], 2) + 0
        next
    }
    /^\+/ {
        text = substr($0, 2)
        sub(/^[ \t]+/, "", text)
        if (text ~ /^\/\// && text !~ /^\/\/\// && text !~ /log-hygiene-ok/) {
            if (run == 0) start = line
            run++
        } else {
            flush()
        }
        line++
        next
    }
    { flush() }
    END { flush() }
'
