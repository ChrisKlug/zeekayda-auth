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
10. [Security Vulnerabilities](#security-vulnerabilities)

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

## Security Vulnerabilities

**Do not open a public GitHub issue for security vulnerabilities.**

See [SECURITY.md](SECURITY.md) for the responsible disclosure process. Thank you for helping keep ZeeKayDa.Auth and its users safe.
