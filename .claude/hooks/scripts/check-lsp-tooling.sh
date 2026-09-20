#!/usr/bin/env bash
# SessionStart guard for the C# navigation tooling (.claude/machine-setup.md §2, §2a).
#
# Both failures below are SILENT at the point of use: a missing `csharp-ls` or
# `csharp-lsp-mcp` makes an agent quietly fall back to grep and report a clean
# result, so a broken machine looks like a working one for weeks. This hook
# turns that into a message at the top of the session.
#
# It never blocks: exit 0 always, warnings go to stdout as session context.

set -uo pipefail

missing=""

command -v csharp-ls > /dev/null 2>&1 ||
  missing="${missing}
- \`csharp-ls\` is not on PATH — the native LSP tool has no language server.
  Fix: \`dotnet tool install --global csharp-ls\` (see .claude/machine-setup.md §2)."

command -v csharp-lsp-mcp > /dev/null 2>&1 ||
  missing="${missing}
- \`csharp-lsp-mcp\` is not on PATH — background and parallel subagents
  (architect, security, developer, tester) have NO code navigation at all and
  will silently grep instead. Fix: the clone/patch/publish/symlink block in
  .claude/machine-setup.md §2a. A restart does not fix this."

[ -n "$missing" ] || exit 0

cat <<MSG
C# navigation tooling is incomplete on this machine:
${missing}

Until it is fixed, treat any subagent's claim to have used the LSP with suspicion.
MSG

exit 0
