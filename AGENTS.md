# ZeeKayDa.Auth — Agent Instructions

This file holds what is true for **every task, in every tool that reads it**, and is capped at 200
lines by CI. Anything narrower lives where it is seen: a rule about a code area in a comment on that
code (and the decision register if it is durable behaviour); a coding standard in
`.claude/agents/developer.md`; a rule about one activity in the skill that runs it; a machine or
shell gotcha in the user's own `~/.claude/CLAUDE.md`.

## Project Overview

ZeeKayDa.Auth is an open-source OpenID Connect identity provider framework for .NET. It is designed to be easy to use while being production-grade, spec-compliant, and security-first.

- **Language**: C# / current .NET 10 · **Package format**: NuGet · **Test framework**: xUnit3
- **Target**: library/framework (not a standalone application)
- Merge to `main` → publish preview to GitHub Packages (`-preview` suffix); git tag `v*.*.*` → stable release on NuGet.org

## Pre-release — nothing is load-bearing yet

**ZeeKayDa.Auth has not shipped. There are no users, no external implementers, and no
compatibility to preserve.** Treat every public type, interface, options class, and extension
method as freely changeable until the 1.0 tag exists.

This is not permission to be careless — it is permission to be *decisive*. Concretely:

- **Never** justify a design by "changing it would be a breaking change." It would not be.
- **Never** add a side-interface, an optional capability probe, or an overload to avoid touching an
  existing contract. Change the contract.
- Rework beats accretion. If a fix is the fourth patch onto the same design, stop and re-cut the
  design instead — that is the cheaper option right now and will never be cheaper again.
- Delete aggressively: dead abstractions, speculative extension points, options nobody sets.
  Git is the history.

Once 1.0 ships this section is deleted and SemVer applies in full.

## Governing Specifications

All features and behaviour must be grounded in the relevant specification. **The spec always wins** — over convention, convenience, .NET idiom, a specialist agent's output, and your own opinion. Every issue, design decision, and implementation must reference the relevant spec section where applicable.

| Spec | Reference |
|---|---|
| OpenID Connect Core 1.0 | https://openid.net/specs/openid-connect-core-1_0.html |
| OpenID Connect Discovery 1.0 | https://openid.net/specs/openid-connect-discovery-1_0.html |
| OAuth 2.0 (RFC 6749) | https://www.rfc-editor.org/rfc/rfc6749 |
| OAuth 2.1 *(draft — follow to the extent possible; ask on ambiguity)* | https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/ |
| OAuth 2.0 Bearer Tokens (RFC 6750) | https://www.rfc-editor.org/rfc/rfc6750 |
| PKCE (RFC 7636) | https://www.rfc-editor.org/rfc/rfc7636 |
| JSON Web Token (RFC 7519) | https://www.rfc-editor.org/rfc/rfc7519 |
| JSON Web Signature (RFC 7515) | https://www.rfc-editor.org/rfc/rfc7515 |
| OAuth 2.0 Threat Model (RFC 6819) | https://www.rfc-editor.org/rfc/rfc6819 |
| OAuth 2.0 Security Best Current Practice (RFC 9700) | https://www.rfc-editor.org/rfc/rfc9700 |
| OAuth 2.0 Authorization Server Issuer (RFC 9207) | https://www.rfc-editor.org/rfc/rfc9207 |

## Repository Layout

```
src/
  ZeeKayDa.Auth/                    # Core library
  ZeeKayDa.Auth.AspNetCore/         # ASP.NET Core integration
  ZeeKayDa.Auth.Analyzers/          # Roslyn analyzers
  ZeeKayDa.Auth.AzureKeyVault/      # Azure Key Vault signing provider
  ZeeKayDa.Auth.Windows/            # Windows Certificate Store signing provider (Windows-only)
tests/                              # One test project per src project
samples/
docs/
```

**Note:** `ZeeKayDa.Auth` has `InternalsVisibleTo` for the other `src/` projects. Do not make types `public` solely for cross-project access — use the existing internal visibility.

`ZeeKayDa.Auth.slnx` is the single canonical solution — build/test/format against it locally. The platform `.slnf` solution filters and the OS-specific-TFM rules are in `docs/decisions/build-and-ci.md`; read it before adding or changing a platform-specific package.

## Project Conventions

- Every change starts with a GitHub issue; no direct commits to `main`.
- Every commit carries a `Signed-off-by` trailer (`git commit --signoff`): the DCO check blocks a
  PR without it, and adding it afterwards means rewriting the branch.
- **Exception — agent configuration.** `.claude/**` and this file go straight to `main`: commit and
  push, no issue, no PR, no review, and never carried inside a feature branch's PR — a reviewer
  reading the PR should see only the issue's work. These files steer how agents work rather than
  shipping in any package, and routing them through the full loop costs more than it protects. The
  push reports that it bypassed branch protection; that is expected for this class of change.
  Everything else — `src/`, `tests/`, `docs/`, `samples/`, build and CI files — follows the loop.
- Semantic versioning (SemVer) strictly enforced.
- Security issues go through the private security advisory process — **never** a public issue.
- **The coding standards in `.claude/agents/developer.md` bind everyone who writes C# in this
  repository** — the main session, `tester`, and any agent making a fix — not only the `developer`
  agent whose file they live in. Test code is not exempt: the standards that keep CodeQL quiet
  apply to a test helper exactly as they do to `src/`. That is a rule for *writing* tests. A
  static-analysis finding raised afterwards on a test — CodeQL, CodeScene — is advisory: fix it by
  hand if it names a real standards violation, never through GitHub's commit-suggestion button, and
  never as a review round. `work-on-issue` Stage 3 says the same from the review side.

## Development Workflow

**Vertical slices, milestone first.** Work is organised into vertical-slice milestones — each slice
ends with something demonstrable end-to-end. The current milestone is the only active work: an issue
outside it is deferred, not started (exception: a genuine security hole in already-written code).
Problems discovered mid-work become **one-line issues** — title, one sentence, a label — never a
workstream. The framework's biggest historical failure mode is moving sideways: polishing internals
to gem quality while the endpoints that make it *an OIDC provider* stay unbuilt.

Work on an issue runs through the loop in the **`/work-on-issue`** skill, which is the full rule
set for building, reviewing, and handing over. The short version:

> **Talk the shape through with the maintainer in chat → build in the main session → one
> severity-gated review round → maintainer reads the diff → PR (verdicts posted, not re-reviewed) →
> merge.**

Three stages stop until the maintainer answers: the shape, the diff, and the merge. Design is a
*conversation* — one signature, one call site, one question at a time, in plain language. A
question from the maintainer gets an answer and a stop, never a build.

| Change | Process |
|---|---|
| Internal / mechanical — bug fix, refactor, test, chore | Main session just builds it. No design gate, no Claude reviewers; one Copilot lens — `code` if the diff has code, `text` if it does not. |
| New or changed **public API** / behaviour | Shape agreed in chat first; short `### Agreed shape` bookmark comment on the issue. |
| Touches **tokens, crypto, endpoints, or storage** | `security` reviews — **one round**; High/Critical fixed inline, the rest is the maintainer's call. |
| Changes **structure or an extension point** | `architect` reviews, same single-round rule. |
| Both surfaces *and* >~150 lines of implementation logic | Both reviewers, in parallel, one message. |

Reviews do not loop, and a finding that states a checkable behaviour is fixed *with a test named for
it* — tests are the durable record, prose is not.

## Decision register

`docs/decisions/` records **what is true now** — not how we got here. One file per topic area, two
sections: `Decisions in force` and `Tried, didn't work`. Format and rules are in
`docs/decisions/README.md`; the essentials: rewrite in place, no dates or issue numbers, written in
the **same PR as the change it describes**, files capped at 150 lines by CI. Most issues touch it
not at all — it holds durable framework behaviour, not per-issue choices.

**Security sign-off entries** (`docs/decisions/security-sign-offs.md`) are the one dated, append-only
record — and they are written **last, once, against frozen code**, after review concludes, never in a
commit still under review. An entry written before the code settled has been falsified by later
fixes three separate times, at a full review round each.

## Routing — MAIN ORCHESTRATOR ONLY

> **STOP. If you are a specialist agent (`developer`, `tester`, `architect`, `security`, `docs`), this section does not apply to you. Execute your own domain work directly and return your results to whoever called you — never delegate to another specialist from here.**

The main session owns **design, decisions, and the code itself**. Design is talked through with the
maintainer in chat — never routed to `architect` to be thought about. C# is written by the main
session directly: it has LSP, the design conversation, and the full context, and a subagent spawn
that must re-derive all of that costs more than it protects. The specialists are for two things
only: **independent review** (`architect`, `security` — a review's value is a context that did *not*
write the code) and **large mechanical builds** (`developer`, foreground, only when the work is big,
fully specified, and would pollute the main context — roughly 300+ lines of implementation logic).

**Don't over-orchestrate.** Fix rounds, nits, doc rewording, and small changes are never delegated.
Every agent hop is tokens and latency, and each spawn starts from zero.

**Building happens on Opus; Fable is for design and review.** The main session runs on whatever
model the maintainer picked, and only they can change it — a session cannot re-price itself. When
the maintainer starts a session on Fable, what they want from it is its reasoning: the design
conversation, the judgement calls, reading the review findings. Typing the code, running the suite,
formatting and coverage are not that, *whatever the code touches* — the reviewers run on Fable and
are the safety net for the subject matter; the builder does not need to be. So at the moment
building is about to start — right after the `### Agreed shape` comment is posted, or at the start
of a mechanical change that has no design gate — check which model this session is on (it is named
in your system prompt). If it is Fable, say so in one line: the shape is agreed, the build does not
need Fable, please switch the session to Opus in the model menu. Then end the turn, so the switch
lands before the first edit rather than mid-build. Stay on Opus through the review round, the
maintainer's read of the diff, and the merge: fixing findings and summarising a diff are Opus work
too. If the maintainer declines for an issue, build on Fable and do not raise it again for that
issue.

| Task | Route |
|---|---|
| Designing an API shape | main session, in conversation with the maintainer |
| Writing or changing C# (features, fixes, refactors, review fixes) | main session, directly — on Opus (see the model rule above) |
| Large, mechanical, fully-specified implementation | `developer` agent (foreground) |
| Reviewing a change | the table in Development Workflow — `security` and/or `architect`, one round |
| Writing or verifying tests on demand | `tester` agent, or main session |
| User-facing documentation | **dormant until the walking skeleton ships** — `docs` agent only on the maintainer's explicit request |
| Starting work on an issue | `/work-on-issue` skill |
| Filing an issue discovered mid-work | one line with `gh issue create`, no ceremony |
| Deliberately fleshing out a new feature idea | `/write-issue` skill |
| After a PR merges | `/post-merge-checks` skill (main session) |
| Reviewing a branch or PR other than the current checkout | `/review-branch` skill, then the right review agent |

If no route fits, tell the user — it might be a gap in the process.

## Deferred tools

Some tools (e.g. `LSP`, `WebFetch`) may arrive deferred — the schema is not loaded and calling them fails with `InputValidationError`. Load such a tool once with `ToolSearch("select:<ToolName>")` before its first call; don't guess parameters from memory. If it still fails after that, report the exact error to whoever called you instead of silently working around it.

**Never delegate an MCP call (`mcp__*`) to a specialist agent** — an agent with an explicit
`tools:` list in its frontmatter (developer, tester, architect, security, docs) cannot reach MCP
tools, and the delegated call fails silently, coming back looking like a clean result. Keep MCP
calls with the main orchestrator. If a task you are given depends on one, say so and return it —
do not report the underlying check as done.

## Code navigation

Prefer the LSP tool over text search for symbol-level navigation; text search is for strings, comments, and config values. Stale results: run `/restart-lsp`. Still unavailable: say so and wait for guidance rather than silently falling back.

## User Interaction

- **Be terse.** Short, precise answers; no progress narration; the user will ask if they need more.
- **Text that leaves the conversation stands alone.** A PR or issue comment, a commit message, an `### Agreed shape` bookmark, a brief for a reviewer or builder, a Stage 4 summary, a register entry: each is read by someone without this session's context — the maintainer coming back to it later, an agent starting from zero, a lens that sees only the diff. Put the thing, the reason, and what the reader must do or decide in the text itself. Never "as discussed", "the change above", "the earlier finding". If understanding the text needs a fact from this conversation, the fact goes in the text.
- **Ask before deciding.** Never resolve ambiguity by guessing. In the main session, ask the user. In a specialist agent, return the open question as your result — the orchestrator will route it.
- **Never fabricate** facts, spec content, or API details. If uncertain, say so and ask.
- **The maintainer sees the code before GitHub does.** Commit locally on the feature branch and keep it there; the maintainer reads the branch in their own editor and approves *before* a PR is opened. Never open a PR, merge one, or create a release tag without explicit approval.
- **Bring every review finding to the maintainer**, with severity, not pre-filtered to what you judged worth fixing. The maintainer decides what gets fixed; fixes land as new commits, visible in the history.
- **Approval gates are harness-enforced.** The permission policy in `.claude/settings.json` makes `gh pr create`, `git tag`, force-pushes, `gh pr merge`, and `gh release` always prompt the user — even when a broader allow rule exists. A permission prompt at one of these points is the review gate working as intended; never look for an alternative command to avoid it.
