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

Work follows six phases plus one conditional checkpoint. Phases 1 and 3 run in the main session via the `/write-issue` skill; the rest are delegated to specialist agents.

```
1. IDEA      ──►  /write-issue   Assess ADR need; write the right issue type.
2. DESIGN    ──►  architect      Write the ADR doc (context → usage sketch → extension sketch →
                                  decision → consequences) and open the ADR PR.
             ──►  security       Threat-model the design; sign off before code is written.
3. POST-ADR  ──►  /write-issue   Create implementation issues from the settled ADR.

   SKETCH GATE (type:task issues only, conditional) ──►  architect
     If the issue adds or changes any public API surface — a new public type/member, a new/changed
     interface, anything a 3rd-party developer would subclass, implement, or call — the architect
     writes a usage sketch (and an extension sketch, if it's an extension point), posts both as a
     comment on the issue, and waits for the maintainer's explicit sign-off before BUILD starts.
     Skipped entirely for issues with no public API surface change (bug fixes, internal refactors,
     test-only work) — those go straight to BUILD.

4. BUILD     ──►  developer      Implement against the issue's acceptance criteria (and the
                                  signed-off sketch, if the gate above applied). Refuses to start a
                                  public-API-surface issue with no signed-off sketch yet.
             ──►  docs           Write documentation alongside the code.
5. VERIFY    ──►  tester         Confirm acceptance criteria; write missing tests.
6. PR        ──►  security       Review any PR touching tokens, crypto, or endpoints.
             ──►  docs           Gate-check that documentation is complete before merge.
```

After any PR merges, run the `/post-merge-checks` skill.

## Routing — MAIN ORCHESTRATOR ONLY

> **STOP. If you are a specialist agent (`developer`, `tester`, `architect`, `security`, `docs`), this section does not apply to you. Execute your own domain work directly and return your results to whoever called you — never delegate to another specialist from here.**

The main session routes and synthesises; it does not do specialist work itself, because that bypasses the specialist's system prompt and standards. **The threshold for delegation is low** — task *type* determines the route, not size. A one-line C# fix still goes to `developer`; a docs typo still goes to `docs`. You do not need to inspect the code before delegating — pick the route and hand it off with enough context from the conversation.

| Task | Route |
|---|---|
| Writing or changing C# code (features, bug fixes, refactors) | `developer` agent |
| Designing abstractions, API shape, writing ADRs | `architect` agent |
| A `type:task` issue that adds/changes public API surface, before a developer picks it up | `architect` agent first (usage/extension sketch, wait for maintainer sign-off), then `developer` |
| Writing or updating Markdown documentation | `docs` agent |
| Security review, threat modelling, OAuth/OIDC correctness | `security` agent |
| Writing or verifying tests, checking acceptance criteria | `tester` agent |
| GitHub issues, triage, epics, sub-issue linking | `/write-issue` skill (main session) |
| After a PR merges | `/post-merge-checks` skill (main session) |
| Reviewing a branch or PR other than the current checkout | `/review-branch` skill, then the right review agent |

If no route fits, tell the user and ask for guidance — it might be a gap in the process.

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
