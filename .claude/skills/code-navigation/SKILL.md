---
name: code-navigation
description: LSP-first code navigation for ZeeKayDa.Auth — load the LSP tool up front and use it for all symbol-level lookups. Applies to every agent that reads or writes C# in this repository.
user-invocable: false
---

# Code Navigation — LSP First

These rules apply to **every agent working with C# code in this repository**, regardless of role.

## Mandatory first step

**Before your first code search or file exploration, run `ToolSearch("select:LSP")` to load the LSP tool.** The LSP tool arrives deferred in this environment — it is not callable until its schema is loaded — and skipping this step is why agents fall back to grep. Load it up front, every session, before touching any code. The ToolSearch result gives you the exact parameter schema, so never guess parameter names from memory.

**If that returns "No matching deferred tools found", you are a background subagent** — Claude Code strips the native `LSP` tool from those by design, and retrying never helps. Do not fall back to grep. Load the MCP language server your agent definition carries instead: `ToolSearch("csharp")` returns the `mcp__csharp-lsp-<your agent name>__*` tools. It is the same `csharp-ls` server behind a different front, with three differences that matter:

1. **Call `csharp_set_workspace` first**, once, with the absolute path of the checkout you are working in — the worktree root if you are in one, never the primary repository when your files are in a worktree. The server holds one workspace at a time, and this is what points it at your checkout.
2. **Positions are 0-based** (`line` and `character`), where the native `LSP` tool is 1-based. Line 30 in `Read` output is `line: 29`. A wrong position returns "No references found" or references to a different symbol rather than an error, so check that the result names the symbol you asked about.
3. **Leave `content` out.** The server then reads the file from disk. Anything you pass as `content` *replaces* the file for that lookup, so a stub or an excerpt gives "No references found" or line numbers that do not match the file.

Point `character` at the first letter of the identifier. Results come back with 1-based lines and columns, so they match `Read` output although the input is 0-based; a property's `get` and `set` accessors are listed as extra hits on its declaration line. If `csharp_references` answers `Internal error: AggregateException`, that is `csharp-ls` failing on that one symbol — the native tool fails on it identically — so use `rg` for that symbol and carry on with the server for the rest.

The operations map as `findReferences` → `csharp_references`, `goToDefinition` → `csharp_definition`, `documentSymbol` → `csharp_symbols`, `hover` → `csharp_hover`, diagnostics → `csharp_diagnostics`. There is no `workspaceSymbol` or call hierarchy; find the declaration with `rg` and run `csharp_references` on it. Say in your result which of the two you used.

## Symbol lookups: LSP, not text search

Use the **LSP tool** for all symbol-level navigation: `goToDefinition`, `findReferences`, `workspaceSymbol`, `documentSymbol`, `hover`, `incomingCalls`/`outgoingCalls`. Point LSP calls at a specific `.cs` file (absolute path), never a directory or a `.csproj`.

- Before renaming or changing a signature, run `findReferences` on it first.
- After editing, check LSP diagnostics and fix errors immediately.
- If LSP returns stale results (after a branch switch, or when symbols stop resolving), run the `/restart-lsp` skill — do not fall back to text search.

## When text search is fine

Use `rg` via Bash for **plain-text** searches only: strings, comments, config values, log-message text, and pattern hunting that isn't symbol-shaped (e.g. `new Random`, `==` on secrets). If the thing you are looking for is a class, method, member, or its usages, that is a symbol lookup — use LSP.

## No delegation needed

You do not need to delegate code exploration to another agent — you have all the tools to explore the codebase yourself.
