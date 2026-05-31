# ZeeKayDa.Auth — Copilot Instructions

## Project Overview

ZeeKayDa.Auth is an open-source OpenID Connect identity provider framework for .NET. It is designed to be easy to use while being production-grade, spec-compliant, and security-first. The name "ZeeKayDa" is derived from the phonetic spelling of "ZKDA" (Zero Knowledge Driven Auth).

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
1. IDEA  ──►  maintainer   Flesh out the idea. Write the GitHub issue with full
                            acceptance criteria, spec references, and a docs requirement.

2. DESIGN ──► architect    Design the solution. Write or update ADRs.
          ──► security     Threat model the design. Sign off before any code is written.
              (both must be satisfied before implementation begins)

3. BUILD  ──► developer    Implement against the issue's acceptance criteria.
          ──► docs         Write or update documentation alongside the code.
                            ⚠ Docs must be complete before a PR is opened.

4. VERIFY ──► tester       Confirm acceptance criteria are met. Write missing tests.
                            Security-negative test cases are mandatory.

5. PR     ──► security     Review the PR for security concerns.
          ──► docs         Confirm documentation is complete and accurate.
                            ⚠ A PR cannot be merged without docs sign-off.
```

**Key rules:**
- No implementation starts without architect + security design sign-off
- Docs are written alongside code — the PR is not opened until docs are ready
- The tester verifies acceptance criteria — not the developer
- Security reviews every PR that touches tokens, cryptography, or endpoints



**Documentation is not optional.** Every public-facing feature, configuration option, endpoint, or behaviour change must ship with Markdown documentation.

- Docs live in `docs/` and are structured for Jekyll (`just-the-docs` theme) using the Diátaxis framework
- The `docs` agent must be involved in every PR that touches the public API or behaviour
- A PR that adds public-facing functionality without docs is incomplete

## Issue & PR Discipline

- Every change starts with an issue
- Issues use the project's label taxonomy (area:*, type:*, priority:*)
- PRs reference their issue (`Closes #N`)
- PR titles follow Conventional Commits format: `feat:`, `fix:`, `docs:`, `test:`, `chore:`, `security:`
- PRs touching public API must include or reference documentation changes

### Blocker resolution on merge

Whenever you are notified that a PR has been merged, you must automatically:

1. Search all open draft PRs for a `## Blockers` section that references the merged PR number (e.g. `blocked by #N`).
2. For each matching PR, remove that blocker entry from the PR body.
3. If the PR has no remaining blockers after removal, mark it as ready for review (`gh pr ready`).

Do this without being asked — it is part of the standard merge flow.

## User interaction

### Ask before deciding

It is of utmost importance that you do not make decisions that stem from ambiguous information. If there are any questions that arise, it is always better to ask than to build something that is not what is needed. There is always a human in the loop. Ask them.

### Never fabricate facts, specs, or API details

> **This applies to all agents. Never fabricate, invent, or guess factual information.**
>
> If you are uncertain, stop and ask the user rather than inferring something and presenting it as established fact. Ask before deciding, and ask before asserting.

**Never commit or push code without explicit approval from the user.** Always let the user know that changes are ready for review and wait for their confirmation before running `git commit` or `git push`.

## Agents selection

The solution contains several custom agents. Make sure you have a look at those before doing any work, to see if one of them might be better suited for the task.
