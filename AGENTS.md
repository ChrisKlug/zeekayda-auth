# ZeeKayDa.Auth — Agent Instructions

## Project Overview

ZeeKayDa.Auth is an open-source OpenID Connect identity provider framework for .NET. It is designed to be easy to use while being production-grade, spec-compliant, and security-first.

- **Language**: C# / current .NET 10 · **Package format**: NuGet · **Test framework**: xUnit3
- **Target**: library/framework (not a standalone application)
- Merge to `main` → publish preview to GitHub Packages (`-preview` suffix); git tag `v*.*.*` → stable release on NuGet.org

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

Some signing-provider packages only make sense on one OS (`ZeeKayDa.Auth.Windows` today; a Linux/cross-platform file-based provider is planned in #291 per ADR 0012). `ZeeKayDa.Auth.slnx` remains the single canonical solution — always build/test/format against it locally unless you have a specific reason to scope down. `ZeeKayDa.Auth.Windows.slnf`, `ZeeKayDa.Auth.MacOS.slnf`, and `ZeeKayDa.Auth.Linux.slnf` are thin solution *filters* (no duplicated project metadata) that CI uses to build/test each platform-specific package only on its own OS's runner, so a package never gets pulled onto the wrong platform's leg. Introduced in PR #318.

**A macOS Keychain provider (#290) was implemented, reviewed, and then descoped** as a product-scope call — a production ASP.NET Core auth server is not a realistic macOS-hosted workload, and the only remaining audience (developers on macOS) is already covered by the local-dev provider and #291 without native interop. See ADR 0011 Amendment 7 and ADR 0012 Amendment 1 for the record. `ZeeKayDa.Auth.MacOS.slnf` still exists and still runs the OS-agnostic core packages' tests on a real macOS CI runner — that's independently valuable and unrelated to the killed provider — it just doesn't build a macOS-specific package (yet; #291 may end up added to it, since #291 is cross-platform).

**Before targeting an OS-specific TFM for a new platform package, verify its workload requirements empirically, don't assume the Windows precedent generalizes.** `net10.0-windows` needs no `dotnet workload install` (Windows Desktop reference assemblies ship via plain NuGet), but `net10.0-macos` does (confirmed via `dotnet workload list` showing zero installed, and a scratch project with that TFM failing restore with `NETSDK1147`) — and CI installs no workloads. Check `dotnet workload list` and try restoring a throwaway project with the candidate TFM before committing to it in an ADR or a `.csproj`.

## Project Conventions

- Every change starts with a GitHub issue; no direct commits to `main`
- Semantic versioning (SemVer) strictly enforced
- Security issues go through the private security advisory process — **never** a public issue

## Development Workflow

**Ceremony scales with blast radius.** Match the process to the risk — don't spend a day of design docs on a one-file fix, and don't land a new public API without agreeing its shape first.

| Change | Process |
|---|---|
| Internal / mechanical — bug fix, refactor, test, chore | Just build it (`developer`). No design gate, no ADR. |
| New or changed **public API** / behaviour | Agree the shape with the maintainer first — a short discussion in the issue (the "mini-ADR": what, why, one line on the alternative). Then build. |
| Touches **tokens, crypto, or endpoints** | A `security` look — at the shape, the PR, or both. |
| A **big or hard-to-reverse** decision | Record a lean ADR (below). Rare. |

- **One narrow issue = one buildable thing.** No epics by default; sequence with `blocked by` / `blocks` relationships, not epic hierarchies.
- The shape discussion happens in the **main session with the maintainer** and is captured in the **issue thread** — not a separate document. That is the maintainer's one involvement point; keep them out of the build/review loop otherwise.
- After a PR merges, run `/post-merge-checks`.

### Lean ADRs

An ADR records a decision worth remembering — not a design essay. Half a page, decision first:

```
# ADR NNNN — <title>
Status: Accepted   ·   Date: YYYY-MM-DD   ·   Issue: #N

## Decision
<what we decided — 1–3 sentences>

## Why
<the reasoning and the main rejected alternative — a few bullets>

## Consequences
<only if non-obvious — what changes, what to watch>
```

No mandatory usage/extension-sketch sections, no security banners, no changelog appendix. Sketches are a design *technique* (pressure-test an API shape during the discussion), not required ADR content. If an ADR runs long it's doing too much — split the decision or cut words.

## Routing — MAIN ORCHESTRATOR ONLY

> **STOP. If you are a specialist agent (`developer`, `tester`, `architect`, `security`, `docs`), this section does not apply to you. Execute your own domain work directly and return your results to whoever called you — never delegate to another specialist from here.**

The main session and the maintainer own **design discussion and decisions** — hold those here, directly, in conversation. Don't route a design question to the `architect` just to have it thought about. What the main session does *not* do is specialist **execution**: writing or changing C# goes to `developer`, a security review to `security`, and so on — that keeps each specialist's standards in force.

**Don't over-orchestrate.** Converge on the decision with the maintainer first, then delegate execution *once*. Do not reflexively chain `architect` → `security` → spike → review on a change; add each hop only when the blast-radius table above calls for it. Spikes are for genuinely novel or risky mechanisms, not routine work. Every extra agent hop is tokens and latency.

| Task | Route |
|---|---|
| Writing or changing C# code (features, bug fixes, refactors) | `developer` agent |
| A genuinely hard API/abstraction design needing specialist depth | `architect` agent (otherwise just discuss it here with the maintainer) |
| Writing or updating Markdown documentation | `docs` agent |
| Security review of a token/crypto/endpoint change | `security` agent |
| Writing or verifying tests, checking acceptance criteria | `tester` agent |
| Writing or triaging a GitHub issue | `/write-issue` skill, or write it directly if the shape is already clear |
| After a PR merges | `/post-merge-checks` skill (main session) |
| Reviewing a branch or PR other than the current checkout | `/review-branch` skill, then the right review agent |

If no route fits, tell the user — it might be a gap in the process.

## Deferred tools

Some tools (e.g. `LSP`, `WebFetch`) may arrive deferred — the schema is not loaded and calling them fails with `InputValidationError`. Load such a tool once with `ToolSearch("select:<ToolName>")` before its first call; don't guess parameters from memory. If it still fails after that, report the exact error to whoever called you instead of silently working around it.

## Code navigation

Prefer the LSP tool over text search for symbol-level navigation (definitions, references, symbols, call hierarchy); use text search only for strings, comments, and config values. If LSP gives stale results, run `/restart-lsp`. If LSP is unavailable and restarting doesn't fix it, say so explicitly and wait for guidance rather than silently falling back.

## User Interaction

- **Be terse.** Short, precise answers; no progress narration; the user will ask if they need more.
- **Ask before deciding.** Never resolve ambiguity by guessing. In the main session, ask the user. In a specialist agent, return the open question as your result — the orchestrator will route it.
- **Never fabricate** facts, spec content, or API details. If uncertain, say so and ask.
- **Review happens on the PR.** Commit and push freely on feature branches — the user reviews diffs in the pull request, not in the working tree. Never commit directly to `main`, and never merge a PR or create a release tag without explicit approval.
- **Approval gates are harness-enforced.** The permission policy in `.claude/settings.json` makes `git tag`, force-pushes, `gh pr merge`, and `gh release` always prompt the user — even when a broader allow rule exists. A permission prompt at one of these points is the review gate working as intended; never look for an alternative command to avoid it.
