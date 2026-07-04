#!/usr/bin/env bash
# PreToolUse guard attached in .claude/agents/developer.md and tester.md
# frontmatter (matchers: Grep and Bash).
#
# - Grep tool call        -> deny, redirect to LSP (or Bash rg for plain text)
# - Bash running grep/rg  -> allow, but inject a reminder that symbol lookups
#                            belong in LSP (some harnesses have no Grep tool,
#                            so this is the only interception point)
# - any other Bash call   -> no output, no opinion

input=$(cat)

if command -v jq > /dev/null 2>&1; then
  tool_name=$(printf '%s' "$input" | jq -r '.tool_name // ""')
  bash_command=$(printf '%s' "$input" | jq -r '.tool_input.command // ""')
else
  tool_name=$(printf '%s' "$input" | grep -o '"tool_name"[^,}]*' | head -1)
  bash_command=$input
fi

case "$tool_name" in
*Grep*)
  cat <<'EOF'
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Use the LSP tool for symbol lookups (classes, methods, references) — if it is not loaded yet, load it first with ToolSearch(\"select:LSP\"). For plain-text searches (strings, comments, config values), use rg via the Bash tool instead. If LSP seems stale or broken, run the /restart-lsp skill."
  }
}
EOF
  ;;
*Bash*)
  if printf '%s' "$bash_command" | grep -qE '(^|[;&| ])(grep|rg|egrep|fgrep) '; then
    cat <<'EOF'
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "additionalContext": "Reminder: if this search is looking for a symbol (class, method, member, usages), use the LSP tool instead — load it with ToolSearch(\"select:LSP\") if needed. grep/rg is fine for plain text (strings, comments, config values)."
  }
}
EOF
  fi
  ;;
esac

exit 0
