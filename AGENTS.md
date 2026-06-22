# ZeeKayDa.Auth — Agent Instructions

## Project Overview

ZeeKayDa.Auth is an open-source OpenID Connect identity provider framework for .NET. It is designed to be easy to use while being production-grade, spec-compliant, and security-first.

## Governing Specifications

All features and behaviour must be grounded in the relevant specification. When in doubt, the spec wins over convention or convenience.

| Spec | Reference |
|---|---|
| OpenID Connect Core 1.0 | https://openid.net/specs/openid-connect-core-1_0.html |
| OpenID Connect Discovery 1.0 | https://openid.net/specs/openid-connect-discovery-1_0.html |
| OAuth 2.0 (RFC 6749) | https://www.rfc-editor.org/rfc/rfc6749 |
| OAuth 2.1 *(draft — follow to extent possible, and ask there are any ambiguity)* | https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/ |
| OAuth 2.0 Bearer Tokens (RFC 6750) | https://www.rfc-editor.org/rfc/rfc6750 |
| PKCE (RFC 7636) | https://www.rfc-editor.org/rfc/rfc7636 |
| JSON Web Token (RFC 7519) | https://www.rfc-editor.org/rfc/rfc7519 |
| JSON Web Signature (RFC 7515) | https://www.rfc-editor.org/rfc/rfc7515 |
| OAuth 2.0 Threat Model (RFC 6819) | https://www.rfc-editor.org/rfc/rfc6819 |
| OAuth 2.0 Security Best Current Practice (RFC 9700) | https://www.rfc-editor.org/rfc/rfc9700 |
| OAuth 2.0 Authorization Server Issuer (RFC 9207) | https://www.rfc-editor.org/rfc/rfc9207 |

Every issue, design decision, and implementation must reference the relevant spec section where applicable.

## Technology Stack

- **Language**: C# / current .NET 10
- **Package format**: NuGet
- **Test framework**: xUnit3
- **Target**: library/framework (not a standalone application)
- **Specs**: OpenID Connect Core 1.0, OAuth 2.0 (RFC 6749), PKCE (RFC 7636), and related RFCs

## Repository Layout (planned)

```
src/
  ZeeKayDa.Auth/              # Core library
  ZeeKayDa.Auth.AspNetCore/   # ASP.NET Core integration
tests/
  ZeeKayDa.Auth.Tests/
  ZeeKayDa.Auth.AspNetCore.Tests/
samples/
docs/
```

**Note:** `ZeeKayDa.Auth` has `InternalsVisibleTo` set to allow `ZeeKayDa.Auth.AspNetCore` to access internals. Do not add `public` to types solely to make them accessible from the ASP.NET Core project — use the existing internal visibility instead.

## Project Conventions

- Every change starts with a GitHub issue; no direct commits to `main`
- Semantic versioning (SemVer) strictly enforced
- Security issues go through the private security advisory process — never a public issue

## NuGet Publishing

- Merge to `main` → publish to preview feed (GitHub Packages) with `-preview` suffix
- Git tag `v*.*.*` → publish to NuGet.org as stable release

## Development Workflow

Work follows six phases. **The main agent is an orchestrator — it routes work and synthesises results. It does not execute phases itself.** Full workflow rules live in each specialist agent's config (`.claude/agents/<agent>.md`)

```
1. IDEA      ──►  maintainer   Assess ADR need; write the right issue type.
2. DESIGN    ──►  architect    Write the ADR doc and open the ADR PR.
             ──►  security     Threat-model the design; sign off before code is written.
3. POST-ADR  ──►  maintainer   Create implementation issues from the settled ADR.
4. BUILD     ──►  developer    Implement against the issue's acceptance criteria.
             ──►  docs         Write documentation alongside the code.
5. VERIFY    ──►  tester       Confirm acceptance criteria; write missing tests.
6. PR        ──►  security     Review any PR touching tokens, crypto, or endpoints.
             ──►  docs         Gate-check that documentation is complete before merge.
```

## AGENT TOOL INITIALIZATION REQUIREMENT
If you are operating as a subagent, your initial context does NOT contain your full toolset due to deferred tool loading. You cannot execute file writes or web searches immediately.

CRITICAL STEPS:
1. Before performing any task analysis, you MUST invoke the `ToolSearch` or `Agent` mechanism to search for the tools required for this objective (e.g., search for "write_file", "view_file", "WebSearch").
2. Do not attempt to guess tool parameters until you have explicitly queried and loaded the tool definition into your active session.
3. If tool execution fails with a missing tool error, report the exact schema you need to the parent agent immediately instead of hallucinating a solution.

## Auditing and Code Review

Before reviewing any code, identify the correct branch that contains the changes to be reviewed — this may be `main`, a feature branch, or a PR branch. Do not assume the currently checked-out branch is correct.

**Workflow:**
1. Identify the target branch (ask the user if unclear — e.g. "which branch / PR should I review?")
2. Create a worktree for it: `git worktree add <path> <branch>`
3. Do all review work inside the worktree
4. Remove the worktree when done: `git worktree remove <path>`

Reviewing a stale or unrelated branch produces false negatives — changes that are already implemented appear missing. Always confirm the right branch first.

## Code navigation

**Always** prefer LSP over Grep/Glob/Read for code navigation.

**Important!** LSP is a deferred tool — its schema is not pre-loaded. Before making any LSP call, you must load it first:
```
ToolSearch("select:LSP")
```
Calling LSP without doing this first will fail with `InputValidationError`. Do this once at the start of any session where you need code navigation.

Capabilities to use:
- `goToDefinition` / `goToImplementation` to jump to source
- `findReferences` to see all usages across the codebase
- `workspaceSymbol` to find where something is defined
- `documentSymbol` to list all symbols in a file
- `hover` for type info without reading the file
- `incomingCalls` / `outgoingCalls` for call hierarchy

Before renaming or changing a function signature, use `findReferences` to find all call sites first.

Use Grep/Glob only for text/pattern searches (comments, strings, config values) where LSP doesn't help.

After writing or editing code, check LSP diagnostics before moving on. Fix any type errors or missing imports immediately.

**Important!** If the LSP seems to be giving you stale information, use the `/restart-lsp` skill to restart the LSP before starting to use `bash` and `grep`

And just to make it clear, this is **REALLY** important! Stop using `grep` unless you have to!!!

## Agent Orchestration

**The main agent routes and synthesises. It never does specialist work itself.** Executing a task directly — rather than delegating — bypasses that agent's system prompt, coding standards, and domain rules. The whole point of specialist agents is lost.

| Task | Agent |
|---|---|
| Writing or changing C# code (features, bug fixes, refactors, tests) | `developer` |
| Designing abstractions, reviewing API shape, writing ADRs | `architect` |
| Writing or updating Markdown documentation | `docs` |
| Security review, threat modelling, OAuth/OIDC correctness | `security` |
| Writing or verifying tests, checking acceptance criteria | `tester` |
| GitHub issues, triage, PR management, project process | `maintainer` |

**Specialist vs specs.** If there is a conflict between the output of a specialist and a spec, the spec always wins!

**The threshold for delegation is low.** A one-line C# fix still goes to `developer`. A simple new issue still goes to `maintainer`. A docs typo still goes to `docs`. Task type determines the agent — not complexity or size.

When in doubt which agent applies, read the `description` field in `.claude/agents/<agent>.md` — it states exactly when to invoke that agent.

**Missing specialist.** If no specialist seems to fit that is is needed, let the user know and ask for guidance. It might be a gap in the process!

**Note for specialist subagents:** The delegation rule above applies to the main orchestrator session only. If you are a specialist agent (developer, tester, architect, etc.), execute your own domain work directly — do not spawn other specialist agents. Spawning agents that can spawn back to you creates circular chains that waste tokens and produce no useful output. Complete your work, then return your results to whoever called you.

## User Interaction

**VERY IMPORTANT!** This applies to *ALL* agents. Always adere to these principles!

### Ask before deciding

It is of utmost importance that you do not make decisions that stem from ambiguous information. If there are any questions that arise, it is always better to ask than to build something that is not what is needed. There is always a human in the loop. Ask them.

### Never fabricate facts, specs, or API details

> **Never fabricate, invent, or guess factual information.**
>
> If you are uncertain, stop and ask the user rather than inferring something and presenting it as established fact. Ask before deciding, and ask before asserting.

### Never commit or push code without approval

>**Never commit or push code without explicit approval from the user.** 
>
>Always let the user know that changes are ready for review and wait for their confirmation before running `git commit` or `git push`.
