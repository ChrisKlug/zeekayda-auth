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
| OAuth 2.1 *(draft — align with, not yet normative)* | https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/ |
| OAuth 2.0 Bearer Tokens (RFC 6750) | https://www.rfc-editor.org/rfc/rfc6750 |
| PKCE (RFC 7636) | https://www.rfc-editor.org/rfc/rfc7636 |
| JSON Web Token (RFC 7519) | https://www.rfc-editor.org/rfc/rfc7519 |
| JSON Web Signature (RFC 7515) | https://www.rfc-editor.org/rfc/rfc7515 |
| OAuth 2.0 Threat Model (RFC 6819) | https://www.rfc-editor.org/rfc/rfc6819 |
| OAuth 2.0 Security Best Current Practice (RFC 9700) | https://www.rfc-editor.org/rfc/rfc9700 |
| OAuth 2.0 Authorization Server Issuer (RFC 9207) | https://www.rfc-editor.org/rfc/rfc9207 |

Every issue, design decision, and implementation must reference the relevant spec section where applicable.

## Technology Stack

- **Language**: C# / current .NET latest LTS
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

## Conventions

- All public API changes require a GitHub issue first
- All changes go through a PR; no direct commits to `main`
- PRs must pass CI (build + tests + security scan)
- Semantic versioning (SemVer) strictly enforced
- XML doc comments on all public types and members
- Tests must cover happy path, edge cases, and security-relevant negative cases
- Security issues go through the private security advisory process (never a public issue)

## NuGet Publishing

- Merge to `main` → publish to preview feed (GitHub Packages) with `-preview` suffix
- Git tag `v*.*.*` → publish to NuGet.org as stable release

## Development Workflow

Every feature or change follows this lifecycle. Agents are responsible for their phase — do not skip phases.

```
1. IDEA      ──►  maintainer   Flesh out the idea. Assess whether an ADR is needed (see below).
                                
                                If ADR needed:
                                  Write an *ADR issue*: problem statement, spec references,
                                  open design questions, and sign-off criteria.
                                  ⚠ No implementation acceptance criteria — those belong in a
                                    separate implementation issue created after the ADR settles.

                                If no ADR needed:
                                  Write an *implementation issue* directly with full acceptance
                                  criteria, spec alignment, and docs requirement.

2. DESIGN    ──►  architect    (ADR path only) Design the solution. Write the ADR doc. Open an ADR PR.
             ──►  security     Threat model the design. Sign off on the ADR PR before any
                                code is written.
                  [ADR PR reviewed and merged — ADR is now accepted]
                                        ↓
3. (post-ADR) ──► maintainer   Create one or more *implementation issues* grounded in the
                                accepted ADR. Acceptance criteria are stable and precise
                                because the design is now settled.

4. BUILD     ──►  developer    Implement against the implementation issue's acceptance criteria.
             ──►  docs         Write or update documentation alongside the code.
                                ⚠ Docs must be complete before a PR is opened.

5. VERIFY    ──►  tester       Confirm acceptance criteria are met. Write missing tests.
                                Security-negative test cases are mandatory.

6. PR        ──►  security     Review the PR for security concerns.
             ──►  docs         Confirm documentation is complete and accurate.
                                ⚠ A PR cannot be merged without docs sign-off.
```

**When is an ADR needed?** An ADR is warranted when the work involves a non-obvious design decision with lasting consequences — new abstractions, storage contracts, public API shape, security-sensitive designs, or anything where "why did we choose this?" will matter in 6 months. It is *not* needed for routine work where the right approach is obvious: adding a property to an existing model, fixing a bug, implementing something fully prescribed by the spec with no real choices, or adding tests.

**When uncertain, the maintainer asks.** If it is not clear whether a new idea needs an ADR, the maintainer asks the user rather than guessing.

**Key rules:**
- Not all work needs an ADR — the maintainer assesses this first
- When an ADR *is* needed, implementation issues are only created after the ADR PR merges
- ADR issues contain design questions, spec references, and sign-off criteria **only** — never implementation acceptance criteria
- Implementation issues (whether ADR-derived or direct) carry the precise acceptance criteria developers and testers work from
- No implementation starts without an accepted ADR and architect + security design sign-off (for ADR-path work)
- Docs are written alongside code — the PR is not opened until docs are ready
- The tester verifies acceptance criteria — not the developer
- Security reviews every PR that touches tokens, cryptography, or endpoints

**Why two issues for ADR-path work?** ADRs evolve during review. Writing implementation acceptance criteria before the design is settled produces stale, misleading guidance. The two-phase model ensures implementation issues are always grounded in settled decisions. An ADR issue closes when its ADR PR merges; an implementation issue closes when its implementation PR merges.

### Issue taxonomy (three-tier model)

Issues follow a three-tier hierarchy:

```
type:epic    →  One per feature area. Permanent coordination point. Accumulates notes and
                links to design and task sub-issues. Never closed until the whole feature
                area is done. Progress shown by sub-issue rollup.
                Title prefix: "Epic: "

type:design  →  ADR / architecture planning issue. Must be a sub-issue of a type:epic.
                Produces an ADR doc + merged PR. Closes when its ADR PR merges.

type:task    →  Concrete implementation work (code, tests, docs, nits, chores).
                Must be a sub-issue of a type:epic. These are what developers pick up.
```

**Sub-issue ordering** reflects execution sequence — design issues precede tasks, foundational tasks precede dependent ones.

**`status:idea`** marks epics, design issues, and tasks representing future ideas not yet ready to design or implement. These stay safe in the repo but are excluded from the active-work view:

```
Active work query: is:open -label:status:idea
```

**`status:needs-triage` is retired.** Unscoped future ideas use `status:idea`; active work uses `status:ready` or `status:blocked`.

**Documentation is not optional.** Every public-facing feature, configuration option, endpoint, or behaviour change must ship with Markdown documentation.

- Docs live in `docs/` and are structured for Jekyll (`just-the-docs` theme) using the Diátaxis framework
- The `docs` agent must be involved in every PR that touches the public API or behaviour
- A PR that adds public-facing functionality without docs is incomplete

## Issue & PR Discipline

- Every change starts with an issue
- Issues use the project's label taxonomy (area:*, type:*, priority:*)
- Issue titles are imperative sentence case and must not duplicate label metadata (`feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `security:`, `design:`, or `type:*`/`area:*`/`priority:*`/`status:*` in the title)
- PRs reference their issue (`Closes #N`)
- PR titles follow Conventional Commits format: `feat:`, `fix:`, `docs:`, `test:`, `chore:`, `security:`
- PRs touching public API must include or reference documentation changes
- Epic issues use an `Epic:` title prefix; every `type:design` and `type:task` issue must be a sub-issue of a `type:epic`
- `status:needs-triage` is retired — use `status:idea` for unscoped future work
- Active work query: `is:open -label:status:idea`

### Branch sync hygiene

Before starting new implementation work (or creating a new branch), first sync from the latest default branch:

1. `git checkout main`
2. `git pull --ff-only`

New branches must be created from this up-to-date `main` unless the user explicitly requests a stacked/alternate base branch.

### Blocker resolution on merge

Whenever you are notified that a PR has been merged, you must automatically:

1. Note both the merged PR number **and** any issue numbers it closes (e.g. `Closes #N` in the PR body).
2. Search all open draft PRs for a `## Blockers` section that references the merged PR number **or** any of those closed issue numbers (e.g. `blocked by #N`).
3. For each matching PR, remove that blocker entry from the PR body.
4. If the PR has no remaining blockers after removal, mark it as ready for review (`gh pr ready`).

Do this without being asked — it is part of the standard merge flow.

## User interaction

### Ask before deciding

It is of utmost importance that you do not make decisions that stem from ambiguous information. If there are any questions that arise, it is always better to ask than to build something that is not what is needed. There is always a human in the loop. Ask them.

### Never fabricate facts, specs, or API details

> **This applies to all agents. Never fabricate, invent, or guess factual information.**
>
> If you are uncertain, stop and ask the user rather than inferring something and presenting it as established fact. Ask before deciding, and ask before asserting.

**Never commit or push code without explicit approval from the user.** Always let the user know that changes are ready for review and wait for their confirmation before running `git commit` or `git push`.

## Agent selection

The solution contains several custom agents in `.claude/agents/`. Make sure you have a look at those before doing any work, to see if one of them might be better suited for the task.

## Standing reminders

### Extensibility docs (#111)

Issue #111 tracks a dedicated **Extensibility** section in the docs covering how to implement custom stores, repositories, and other extension points.

**When a new public interface is added or a new extension point is stabilised**, check whether it needs a how-to page under the Extensibility section and, if so, either create a child issue on #111 or add the task to the current PR. The overview page in the Extensibility section must also be kept up to date.
