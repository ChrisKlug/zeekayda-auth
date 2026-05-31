# Contributing to ZeeKayDa.Auth

Thank you for your interest in contributing! ZeeKayDa.Auth is an open-source project and we welcome contributions of all kinds — bug reports, feature ideas, documentation improvements, and code.

Please take a few minutes to read this guide before you start. It helps us review contributions faster and keeps the project healthy.

---

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Issue-First Policy](#issue-first-policy)
3. [Reporting Bugs](#reporting-bugs)
4. [Suggesting Features](#suggesting-features)
5. [Pull Request Process](#pull-request-process)
6. [Branch Naming](#branch-naming)
7. [Commit Messages](#commit-messages)
8. [Developer Certificate of Origin (DCO)](#developer-certificate-of-origin-dco)
9. [Code Style](#code-style)
10. [CI](#ci)
11. [Release Process](#release-process)
12. [Security Vulnerabilities](#security-vulnerabilities)

---

## Code of Conduct

This project follows the [Contributor Covenant v2.1](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code. Please report unacceptable behaviour to [chris@59north.com](mailto:chris@59north.com).

---

## Issue-First Policy

**Before writing any code, open an issue.**

This applies to everything except trivial typo fixes. Opening an issue first:

- Lets maintainers confirm the problem or feature is in scope
- Avoids duplicate work
- Gives the community a chance to shape the solution before time is invested

If you want to work on an existing issue, leave a comment to say so. A maintainer will assign it to you.

---

## Reporting Bugs

Use the **Bug Report** issue template. Please include:

- A clear, concise description of the problem
- Steps to reproduce (the shorter the better)
- Expected behaviour vs actual behaviour
- Environment details: .NET version, OS, ZeeKayDa.Auth version
- Relevant log output or stack traces (redact any sensitive data)

> ⚠️ If the bug is a **security vulnerability**, do **not** open a public issue. See [SECURITY.md](SECURITY.md).

---

## Suggesting Features

Use the **Feature Request** issue template. Please include:

- The problem you are trying to solve (not just the solution you have in mind)
- Any relevant spec references (RFC number, OpenID Connect section, etc.)
- Whether you are willing to implement it yourself

---

## Pull Request Process

1. **Open an issue first** (see above) and get a go-ahead from a maintainer
2. **Fork** the repository and create your branch from `main` (see [Branch Naming](#branch-naming))
3. **Write tests** — all new behaviour must be covered. PRs that reduce test coverage will not be merged
4. **Run the full test suite locally** before pushing
5. **Update documentation** as needed — see the `area:docs` label; the docs agent must be involved for all public-facing changes
6. **Open the PR** against `main` using the PR template; reference the issue with `Closes #<number>`
7. **Sign your commits** with the DCO trailer (see below)
8. Address review feedback promptly; stale PRs (no activity for 30 days) may be closed

A PR is ready to merge when:
- All CI checks pass
- At least one maintainer has approved
- The security agent has signed off (required for any protocol-level or auth-related change)
- Documentation is complete

---

## Branch Naming

Use one of these prefixes, followed by a short slug and the issue number:

| Prefix | Use for |
|---|---|
| `feat/` | New features |
| `fix/` | Bug fixes |
| `chore/` | Maintenance, tooling, repo hygiene |
| `docs/` | Documentation-only changes |
| `test/` | Test-only changes |
| `refactor/` | Code restructuring with no behaviour change |
| `security/` | Security fixes or hardening |

**Examples:**
```
feat/issue-42-pkce-enforcement
fix/issue-17-token-expiry-off-by-one
chore/issue-1-oss-health-files
```

---

## Commit Messages

We follow the [Conventional Commits](https://www.conventionalcommits.org/) format:

```
<type>(<scope>): <short summary>

[optional body]

[optional footers]
```

**Types:** `feat`, `fix`, `chore`, `docs`, `test`, `refactor`, `security`, `ci`

**Examples:**
```
feat(token): add PKCE code verifier validation per RFC 7636 §4.6
fix(discovery): return correct issuer URL when behind a reverse proxy
chore: add OSS community health files
```

Keep the summary line under 72 characters. Use the body to explain *why*, not *what*.

---

## Developer Certificate of Origin (DCO)

All commits must include a `Signed-off-by` trailer. This is a lightweight way of certifying that you have the right to submit the contribution under the project's license (Apache 2.0).

Add the trailer with the `-s` flag:

```bash
git commit -s -m "feat(token): add PKCE enforcement"
```

This produces:
```
feat(token): add PKCE enforcement

Signed-off-by: Your Name <your.email@example.com>
```

By signing off you are agreeing to the [Developer Certificate of Origin v1.1](https://developercertificate.org/). This is **not** a CLA — it is just a statement that you wrote the code (or have the right to submit it) and are contributing it under the project's open-source license.

---

## Code Style

- **Language:** C# (latest LTS feature set unless otherwise decided in an ADR)
- **Formatter:** The `.editorconfig` in the repo root is authoritative — your IDE should pick it up automatically
- **Nullable reference types:** Enabled — no `#nullable disable` suppressions without a comment explaining why
- **No `this.` prefix** on member access
- **XML doc comments** on all public API members — the docs agent relies on these
- **No `TODO` comments in merged code** — open an issue instead

If you are unsure about a style decision, check how the surrounding code is written and follow the same pattern. When in doubt, ask in the issue before writing the code.

---

## CI

Every pull request and every push to `main` runs two GitHub Actions jobs defined in `.github/workflows/ci.yml`:

| Job | What it checks |
|---|---|
| `build-and-test` | Restores, builds (warnings-as-errors), and runs the full test suite with code coverage on `ubuntu-latest`. |
| `format-check` | Runs `dotnet format --verify-no-changes` to ensure all code matches the `.editorconfig` rules. |
| `codeql` | Runs GitHub CodeQL static analysis (`security-and-quality` query suite). Findings must be fixed or explicitly justified before a PR can be merged. See [SECURITY.md](SECURITY.md). |

**All jobs must be green before a PR can be merged.**

To check formatting locally before pushing:

```bash
dotnet format --verify-no-changes
```

To fix formatting issues automatically:

```bash
dotnet format
```

Coverage reports are uploaded as build artifacts and can be downloaded from the Actions run summary.

---

## Release Process

This section is for maintainers.

### Cutting a stable release

1. Ensure `<VersionPrefix>` in `Directory.Build.props` reflects the intended release version (e.g. `1.0.0`).
2. Update `CHANGELOG.md` — move all entries under `[Unreleased]` to a new versioned section (e.g. `[1.0.0] - 2026-05-31`), then commit and merge to `main`.
3. Create and push a version tag that **exactly matches** the `<VersionPrefix>` value, prefixed with `v`:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```
4. The `publish-release.yml` workflow fires automatically, validates the tag against `Directory.Build.props`, builds, packs (with `.snupkg` symbols), and pushes to [NuGet.org](https://www.nuget.org/).
5. Create a matching GitHub Release from the tag and add release notes.

> If the tag version does not match `<VersionPrefix>` in `Directory.Build.props`, the workflow will fail with a clear error message. Fix the mismatch and re-push the tag.

### Preview builds

Every push to `main` automatically publishes a preview package to the [GitHub Packages NuGet feed](https://github.com/ChrisKlug/zeekayda-auth/pkgs/nuget). Preview packages follow the versioning scheme:

```
<VersionPrefix>-preview.<run_number>
```

For example: `0.1.0-preview.42`. Preview packages include `.snupkg` symbol packages so you can step into ZeeKayDa.Auth source in a debugger.

### Consuming preview packages

To install a preview build, add the GitHub Packages NuGet source. Authentication requires a GitHub Personal Access Token (PAT) with at least `read:packages` scope.

```bash
dotnet nuget add source https://nuget.pkg.github.com/ChrisKlug/index.json \
  --name ZeeKayDa-preview \
  --username <your-github-username> \
  --password <your-PAT> \
  --store-password-in-clear-text
```

> The `--store-password-in-clear-text` flag is required on Linux and macOS where no system credential store is available.

Then install the package as usual, specifying the preview version explicitly if needed:

```bash
dotnet add package ZeeKayDa.Auth --version 0.1.0-preview.42
```

---

## Security Vulnerabilities

**Do not open a public GitHub issue for security vulnerabilities.**

See [SECURITY.md](SECURITY.md) for the responsible disclosure process. Thank you for helping keep ZeeKayDa.Auth and its users safe.
