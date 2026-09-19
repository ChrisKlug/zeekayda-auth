#!/usr/bin/env bash
# PreToolUse guard on the Agent tool, attached in .claude/settings.json.
#
# Denies spawning a code-navigating specialist in the background. LSP cannot be
# loaded in a background agent — ToolSearch("select:LSP") returns no match there
# regardless of the agent's tools: list — so the agent silently drops to text
# search. work-on-issue has always said "foreground, never background"; this is
# what makes the rule hold rather than depend on the orchestrator remembering it.
#
# Everything else passes without comment, including a background `claude`,
# `Explore`, `general-purpose` or `housekeeper` agent, none of which navigate C#
# by symbol.

input=$(cat)

if command -v jq > /dev/null 2>&1; then
  subagent=$(printf '%s' "$input" | jq -r '.tool_input.subagent_type // ""')
  background=$(printf '%s' "$input" | jq -r '.tool_input.run_in_background // false')
else
  # No jq: fail open rather than block every agent spawn on a parsing detail.
  exit 0
fi

case "$subagent" in
developer | tester | architect | security | docs) ;;
*) exit 0 ;;
esac

[ "$background" = "true" ] || exit 0

cat <<EOF
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Spawn '$subagent' in the foreground: pass run_in_background: false. A background agent cannot load the LSP tool — ToolSearch(\"select:LSP\") returns no match there whatever its tools: list says — so it navigates C# by text search and reads the code less well. If you wanted several of these running at once, that is the trade being refused: run them one at a time in the foreground, or split the work so each foreground agent is smaller."
  }
}
EOF
