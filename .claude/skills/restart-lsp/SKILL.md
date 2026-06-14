---
name: restart-lsp
description: Restart the C# language server when it is misbehaving — stale cache after branch switches, missing symbols, broken go-to-definition. Use when the user says the LSP is stuck, wrong, or slow, or when IntelliSense stops resolving correctly after a branch change.
user-invocable: true
disable-model-invocation: false
allowed-tools:
  - Bash(pkill *)
  - Bash(rm -rf *)
  - Bash(ps *)
  - Bash(find *)
---

# /restart-lsp — Restart the C# Language Server

Kills the running C# language server process so Claude Code restarts it fresh.
Optionally wipes the Roslyn/OmniSharp disk cache first when the index is corrupt.

Arguments passed: `$ARGUMENTS`

---

## Dispatch on arguments

Parse `$ARGUMENTS`. Supported flags:

- *(no args)* — kill the language server process only; let it restart naturally
- `--clear-cache` — wipe the Roslyn and OmniSharp caches before killing the process

---

## Steps

### 1. Find the language server process

Run:

```sh
ps aux | grep -E 'Microsoft\.CodeAnalysis\.LanguageServer|OmniSharp' | grep -v grep
```

Report what you find (process name + PID). If nothing is found, tell the user
"No C# language server process found — it may already be stopped or not yet started."
and stop.

### 2. If `--clear-cache` was passed — wipe caches

Wipe the following locations **only if they exist** (check first, never error on missing paths):

- `~/.local/share/Microsoft/Microsoft.CodeAnalysis.LanguageServer/` — Roslyn LSP cache
- `~/.omnisharp/` — OmniSharp cache
- Any `.roslyn/` directory under the current project root

Report each path removed.

### 3. Kill the language server

```sh
pkill -f 'Microsoft\.CodeAnalysis\.LanguageServer'
pkill -f 'OmniSharp'
```

Report how many processes were killed.

### 4. Confirm

Tell the user:
- What was killed
- Whether cache was cleared (and which paths)
- That Claude Code will restart the language server automatically on the next LSP operation

---

## Notes

- Do not kill generic `dotnet` processes — only target the named language server binaries.
- The user most commonly needs this after switching branches or rebasing, when Roslyn's
  in-memory index drifts from the actual source tree.
- `--clear-cache` is the heavier option: use it when a plain restart doesn't fix the issue.
