# ZeeKayDa.Auth — Agent Instructions

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

### Platform-specific signing providers and solution filters

Some signing-provider packages only make sense on one OS (`ZeeKayDa.Auth.Windows` today; a cross-platform file-based provider is planned). `ZeeKayDa.Auth.slnx` remains the single canonical solution — always build/test/format against it locally unless you have a specific reason to scope down. `ZeeKayDa.Auth.Windows.slnf`, `ZeeKayDa.Auth.MacOS.slnf`, and `ZeeKayDa.Auth.Linux.slnf` are thin solution *filters* (no duplicated project metadata) that CI uses to build/test each platform-specific package only on its own OS's runner, so a package never gets pulled onto the wrong platform's leg. Introduced in PR #318.

**A macOS Keychain provider (#290) was implemented, reviewed, and then descoped** as a product-scope call — a production ASP.NET Core auth server is not a realistic macOS-hosted workload, and the only remaining audience (developers on macOS) is already covered by the local-dev provider and #291 without native interop. `ZeeKayDa.Auth.MacOS.slnf` still exists and still runs the OS-agnostic core packages' tests on a real macOS CI runner — that's independently valuable and unrelated to the killed provider — it just doesn't build a macOS-specific package (yet; #291 may end up added to it, since #291 is cross-platform).

**Before targeting an OS-specific TFM for a new platform package, verify its workload requirements empirically, don't assume the Windows precedent generalizes.** `net10.0-windows` needs no `dotnet workload install` (Windows Desktop reference assemblies ship via plain NuGet), but `net10.0-macos` does (confirmed via `dotnet workload list` showing zero installed, and a scratch project with that TFM failing restore with `NETSDK1147`) — and CI installs no workloads. Check `dotnet workload list` and try restoring a throwaway project with the candidate TFM before committing to it in a decision entry or a `.csproj`.

## Project Conventions

- Every change starts with a GitHub issue; no direct commits to `main`
- **Exception — agent configuration.** `.claude/**` and `AGENTS.md` go straight to `main`: commit and
  push, no issue, no PR, no review. These files steer how agents work rather than shipping in any
  package, and routing them through the full loop costs more than it protects. This bypasses the
  branch-protection ruleset by design; the push output will say so. Everything else — `src/`,
  `tests/`, `docs/`, `samples/`, build and CI files — follows the normal loop.
- Semantic versioning (SemVer) strictly enforced
- Security issues go through the private security advisory process — **never** a public issue

## Development Workflow

**Vertical slices, milestone first.** Work is organised into vertical-slice milestones — each slice
ends with something demonstrable end-to-end. The current milestone is the only active work: an issue
outside it is deferred, not started (exception: a genuine security hole in already-written code).
Problems discovered mid-work become **one-line issues** — title, one sentence, a label — never a
workstream. The framework's biggest historical failure mode is moving sideways: polishing internals
to gem quality while the endpoints that make it *an OIDC provider* stay unbuilt.

Work on an issue runs through the loop in the **`/work-on-issue`** skill. The short version:

> **Talk the shape through with the maintainer in chat → build in the main session → one
> severity-gated review round → maintainer reads the diff → PR (verdicts posted, not re-reviewed) →
> merge.**

Three stages stop until the maintainer answers: the shape, the diff, and the merge. Design is a
*conversation* — one signature, one call site, one question at a time, in plain language. Never
deliver the maintainer a pre-baked design artifact that assumes they have the issue memorised.

| Change | Process |
|---|---|
| Internal / mechanical — bug fix, refactor, test, chore | Main session just builds it. No design gate, no reviewers. |
| New or changed **public API** / behaviour | Shape agreed in chat first; short `### Agreed shape` bookmark comment on the issue. |
| Touches **tokens, crypto, endpoints, or storage** | `security` reviews — **one round**; High/Critical fixed inline, the rest is the maintainer's call. |
| Changes **structure or an extension point** | `architect` reviews, same single-round rule. |
| Both surfaces *and* >~150 lines of implementation logic | Both reviewers, in parallel, one message. |

- **Reviews do not loop.** One round, High/Critical fixed and verified against the fix diff only,
  Medium/Low listed for the maintainer. A fresh reviewer always finds something — that is sampling,
  not convergence. The backstops are tests, the per-milestone security audit, and the OpenID
  conformance suite.
- **Findings become tests.** Any review finding stating a checkable behaviour is fixed *with a test
  named for it*. Tests are the durable record; prose is not.
- After a PR merges, run `/post-merge-checks`.

## Decision register

`docs/decisions/` records **what is true now** — not how we got here. One file per topic area, two sections: `Decisions in force` and `Tried, didn't work`.

- No numbers, no `Status`, no `Date`, no issue references, no changelog, no amendment log.
- A decision changed? **Rewrite it in place.** Git is the history.
- A decision was abandoned? Move it to `Tried, didn't work` with one line on why — so nobody re-proposes it.
- Written in the **same PR as the change it describes**. There is no separate design PR, and no design-issue-then-implementation-issue lifecycle.
- Most issues touch the register not at all. It holds durable framework behaviour, not per-issue choices.
- Files are capped at 150 lines, enforced by CI. At the cap, cut words or split the topic — never raise the cap.

The format is in `docs/decisions/README.md`. It is deliberately minimal: the previous ADR format grew to 4,270 lines and was being amended roughly five times for every one that was written.

**Security sign-off entries** (`docs/decisions/security-sign-offs.md`) are the one dated, append-only
record — and they are written **last, once, against frozen code**, after review concludes, never in a
commit still under review. Maximum ~15 lines per entry; every claim cites a test name as its proof
rather than prose a future reviewer must re-probe. An entry written before the code settled has been
falsified by later fixes three separate times, at a full review round each — the ordering rule exists
because of that.

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

| Task | Route |
|---|---|
| Designing an API shape | main session, in conversation with the maintainer |
| Writing or changing C# (features, fixes, refactors, review fixes) | main session, directly |
| Large, mechanical, fully-specified implementation | `developer` agent (foreground) |
| Security review of a token/crypto/endpoint/storage change | `security` agent — one round |
| Structural / extension-point review | `architect` agent — one round |
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

**MCP tools (`mcp__*`) are not reachable from an agent whose frontmatter has an explicit `tools:`
list** — that covers developer, tester, architect, security and docs. `ToolSearch` returns "No
matching deferred tools found". Adding the MCP tool name to the `tools:` list is the documented
workaround, but agent definitions are cached per session, so it takes effect only in a fresh session.

Practical rule when writing agent instructions: **never delegate an MCP call to one of these
agents.** A delegated call fails silently and comes back looking like a clean result. Keep MCP calls
with the main orchestrator. If a task you are given depends on one, say so and return it — do not
report the underlying check as done.

## Code navigation

Prefer the LSP tool over text search for symbol-level navigation (definitions, references, symbols, call hierarchy); use text search only for strings, comments, and config values. If LSP gives stale results, run `/restart-lsp`. If LSP is unavailable and restarting doesn't fix it, say so explicitly and wait for guidance rather than silently falling back.

## User Interaction

- **Be terse.** Short, precise answers; no progress narration; the user will ask if they need more.
- **Ask before deciding.** Never resolve ambiguity by guessing. In the main session, ask the user. In a specialist agent, return the open question as your result — the orchestrator will route it.
- **Never fabricate** facts, spec content, or API details. If uncertain, say so and ask.
- **The maintainer sees the code before GitHub does.** Commit locally on the feature branch and keep it there — the first review round happens between agents and never reaches the PR. The maintainer reviews the working branch in their own editor and approves *before* a PR is opened. Never commit directly to `main`, and never open a PR, merge one, or create a release tag without explicit approval.
- **Bring every review finding to the maintainer.** Once the PR is open, reviewers post all findings on it with severity — not pre-filtered to what you judged worth fixing. Summarise all of them and let the maintainer decide what gets fixed, rather than silently applying the ones you picked. Fixes land as new commits on the same PR, visible in its history.
- **Approval gates are harness-enforced.** The permission policy in `.claude/settings.json` makes `gh pr create`, `git tag`, force-pushes, `gh pr merge`, and `gh release` always prompt the user — even when a broader allow rule exists. A permission prompt at one of these points is the review gate working as intended; never look for an alternative command to avoid it.
