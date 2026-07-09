---
name: code-navigation
description: LSP-first code navigation for ZeeKayDa.Auth — load the LSP tool up front and use it for all symbol-level lookups. Applies to every agent that reads or writes C# in this repository.
user-invocable: false
---

# Code Navigation — LSP First

These rules apply to **every agent working with C# code in this repository**, regardless of role.

## Mandatory first step

**Before your first code search or file exploration, run `ToolSearch("select:LSP")` to load the LSP tool.** The LSP tool arrives deferred in this environment — it is not callable until its schema is loaded — and skipping this step is why agents fall back to grep. Load it up front, every session, before touching any code. The ToolSearch result gives you the exact parameter schema, so never guess parameter names from memory.

## Symbol lookups: LSP, not text search

Use the **LSP tool** for all symbol-level navigation: `goToDefinition`, `findReferences`, `workspaceSymbol`, `documentSymbol`, `hover`, `incomingCalls`/`outgoingCalls`. Point LSP calls at a specific `.cs` file (absolute path), never a directory or a `.csproj`.

- Before renaming or changing a signature, run `findReferences` on it first.
- After editing, check LSP diagnostics and fix errors immediately.
- If LSP returns stale results (after a branch switch, or when symbols stop resolving), run the `/restart-lsp` skill — do not fall back to text search.

## When text search is fine

Use `rg` via Bash for **plain-text** searches only: strings, comments, config values, log-message text, and pattern hunting that isn't symbol-shaped (e.g. `new Random`, `==` on secrets). If the thing you are looking for is a class, method, member, or its usages, that is a symbol lookup — use LSP.

## No delegation needed

You do not need to delegate code exploration to another agent — you have all the tools to explore the codebase yourself.
