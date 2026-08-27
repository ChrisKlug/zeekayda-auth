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
10. [Building Locally](#building-locally)
11. [Test Naming Convention](#test-naming-convention)
12. [CI](#ci)
13. [Mutation Testing (Stryker.NET)](#mutation-testing-strykernet)
14. [Release Process](#release-process)
15. [Security Vulnerabilities](#security-vulnerabilities)

---

## Code of Conduct

This project follows the [Contributor Covenant v2.1](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code. Please report unacceptable behaviour to [chris@zeekayda.com](mailto:chris@zeekayda.com).

---

## Issue-First Policy

**Before writing any code, open an issue.**

This applies to everything except trivial typo fixes. Opening an issue first:

- Lets maintainers confirm the problem or feature is in scope
- Avoids duplicate work
- Gives the community a chance to shape the solution before time is invested

If you want to work on an existing issue, leave a comment to say so. A maintainer will assign it to you.

### Ceremony scales with blast radius

Process is matched to the risk of the change, not applied uniformly:

| Change | Process |
|---|---|
| Internal / mechanical — bug fix, refactor, test, chore | Just build it. No design gate, no review round. |
| New or changed **public API** / behaviour | Agree the shape with a maintainer *before writing code*. The agreed shape — sample usage, concrete signatures, and the rejected alternative — is posted on the issue as an `### Agreed shape` comment, and that comment is what gets built. |
| Touches **tokens, crypto, or endpoints** | A security review, in two rounds: once locally before the PR exists, then on the open PR. |
| Changes **structure or an extension point** | An architecture review, same two rounds. |

**One narrow issue = one buildable thing.** There is no epic tier by default — issues are sequenced with GitHub's native `blocked by` / `blocks` relationships instead of an epic hierarchy. The shape discussion happens in conversation and lands on the issue thread, never in a separate design document.

There is **no design-document lifecycle**. Work is not blocked on a decision record being written and merged first. Where a change makes a durable difference to how the framework behaves, the [decision register](docs/decisions/README.md) is updated in the same pull request as the change itself — and most changes don't touch it at all.

**Ideas that are not yet ready** for design or implementation are tagged `status:idea`. They are excluded from the active-work view (`is:open -label:status:idea`).

> 💡 If you are an external contributor with a feature idea, open a **Feature Request** — a maintainer will determine what process the change needs and shape the issue accordingly.

### Pre-1.0 Stability Policy

ZeeKayDa.Auth has not yet tagged a release — `CHANGELOG.md` is still entirely under
`[Unreleased]`, and there are no external consumers depending on a published version. This has
concrete, temporary implications for how we work:

- Breaking API changes need **no deprecation shims**, `[Obsolete]` attributes, or migration
  guides. If a shape is wrong, we fix it directly rather than carrying the old shape alongside
  the new one.
- The [decision register](docs/decisions/README.md) is **rewritten in place** to describe the
  current design, rather than amended in perpetuity. Entries record what is true now; git history
  holds what used to be true.

This is a deliberate but temporary relaxation — it exists only because nothing yet depends on the
current shapes being stable.

> ⚠️ **Removal trigger:** Once the first version is tagged (see
> [Cutting a stable release](#cutting-a-stable-release) — `CHANGELOG.md`'s `[Unreleased]` section
> moves to a versioned section and a `git tag` is pushed), this policy no longer applies and this
> section must be removed or revisited. From that point on, external consumers exist and normal
> semantic-versioning deprecation discipline applies to breaking changes.

### Issue Title Format

Issue titles must be written in imperative sentence case and describe the work directly.

- ✅ `Add PKCE enforcement to authorization endpoint`
- ❌ `feat: add PKCE enforcement to authorization endpoint`
- ❌ `type:feature area:core Add PKCE enforcement to authorization endpoint`

Classification belongs in labels (`type:*`, `area:*`, `priority:*`, `status:*`), not in the title.

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

> ℹ️ Features that need significant design work get their shape agreed with the maintainer before any code is written — the agreed API shape is posted on the issue, and implementation follows from it. This protects your effort from being based on a design that changes during review.

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

- **Language:** C# (latest LTS feature set unless otherwise decided)
- **Formatter:** The `.editorconfig` in the repo root is authoritative — your IDE should pick it up automatically
- **Nullable reference types:** Enabled — no `#nullable disable` suppressions without a comment explaining why
- **No `this.` prefix** on member access
- **XML doc comments** on all public API members — the docs agent relies on these
- **No `TODO` comments in merged code** — open an issue instead

If you are unsure about a style decision, check how the surrounding code is written and follow the same pattern. When in doubt, ask in the issue before writing the code.

### Public API tracking

`ZeeKayDa.Auth`, `ZeeKayDa.Auth.AspNetCore`, `ZeeKayDa.Auth.AzureKeyVault`, `ZeeKayDa.Auth.FileSystem`, `ZeeKayDa.Auth.Windows`, and `ZeeKayDa.Auth.TestKit` each carry a `PublicAPI.Shipped.txt` and `PublicAPI.Unshipped.txt`, enforced by [`Microsoft.CodeAnalysis.PublicApiAnalyzers`](https://github.com/dotnet/roslyn-analyzers/blob/main/src/PublicApiAnalyzers/PublicApiAnalyzers.Help.md). The build fails if a public member is added, removed, or changes shape without a matching entry — for example, an accidental narrowing from `public` to `internal`.

- **Adding, removing, or changing** a public member: add/update the corresponding entry in that project's `PublicAPI.Unshipped.txt`. The compiler error (`RS0016`/`RS0017`/`RS0025`/`RS0036`) names the exact line to add — copy it verbatim.
- **On release**: move every entry from `PublicAPI.Unshipped.txt` to `PublicAPI.Shipped.txt` as part of [cutting a stable release](#cutting-a-stable-release).
- `ZeeKayDa.Auth.Analyzers` is not covered — it has no public surface of the kind this guards.
- `ZeeKayDa.Auth.TestKit`'s tracked surface includes its `[Fact]` conformance test methods, not just the `abstract`/`virtual` inheritance hooks a third-party implementer overrides — the test methods are `public` because xUnit only discovers and runs `public` test methods, which makes them public API in the sense this analyzer guards.

---

## Building Locally

`ZeeKayDa.Auth.slnx` is the single canonical solution — build, test, and format against it unless you have a specific reason to scope down:

```bash
dotnet build ZeeKayDa.Auth.slnx
dotnet test ZeeKayDa.Auth.slnx
```

Some signing-provider packages only make sense on one OS (`ZeeKayDa.Auth.Windows` today; a macOS Keychain provider and a Linux/cross-platform file-based provider are planned). `ZeeKayDa.Auth.Windows.slnf`, `ZeeKayDa.Auth.MacOS.slnf`, and `ZeeKayDa.Auth.Linux.slnf` are thin solution *filters* over the same canonical solution — no duplicated project metadata — that scope a build/test run to only the projects valid on that OS. CI uses them so a platform-specific package is never built or tested on the wrong runner. You generally don't need them locally unless you're working on a platform-specific provider and want to confirm your change builds cleanly without the other platforms' projects in the mix, e.g.:

```bash
dotnet build ZeeKayDa.Auth.Windows.slnf
```

`dotnet format` does not auto-discover a single solution when both `.slnx` and `.slnf` files are present in the same directory — always pass `ZeeKayDa.Auth.slnx` explicitly:

```bash
dotnet format ZeeKayDa.Auth.slnx --verify-no-changes
```

The repository-root `NuGet.config` pins restore to `nuget.org` only, overriding any other sources configured on your machine (e.g. a corporate feed added globally) unless you pass `--source`/`RestoreSources` explicitly. This is a defense against dependency confusion, so it applies even if you normally restore from an internal feed — if you need a package that genuinely only lives on another feed, open an issue to discuss it rather than adding the source locally.

---

## Test Naming Convention

All test methods follow the `Method_verb_object_condition` pattern. The name should read like a plain-English sentence that answers *"what does this method do, and under what condition?"*

**Rules:**
- Connector words (`if`, `when`, `and`, `for`, `with`) are **lowercase**
- Type names and proper nouns stay **PascalCase**
- Underscores are used only as word-group separators — never inside a word

**Examples:**

```csharp
public Task GetIssuerUri_throws_ZeeKayDaConfigurationException_if_Issuer_is_null_or_whitespace()

public Task GetDiscoveryDocument_publishes_repository_scopes_when_using_InMemoryScopeRepository()

public Task Validate_returns_success_when_token_is_valid()

public Task AddClient_throws_if_ClientId_is_already_registered
```

---

## CI

Every pull request and every push to `main` runs the following GitHub Actions jobs defined in `.github/workflows/ci.yml`:

| Job | What it checks |
|---|---|
| `build-and-test` | Restores, builds (warnings-as-errors), and runs the full test suite with code coverage on a matrix of `ubuntu-latest`, `windows-latest`, and `macos-latest`, each using its own OS-specific solution filter (see [Building Locally](#building-locally)) so platform-specific provider packages only build/test on their own OS. |
| `coverage-regression` | Runs PR and base-branch coverage, writes a coverage delta summary, and fails if line coverage decreases. |
| `coverage-regression-script-tests` | Runs the fixture-driven smoke tests for `.github/scripts/check_coverage_regression.cs`. |
| `format-check` | Runs `dotnet format --verify-no-changes` to ensure all code matches the `.editorconfig` rules. |
| `codeql` | Runs GitHub CodeQL static analysis (`security-and-quality` query suite). Findings must be fixed or explicitly justified before a PR can be merged. See [SECURITY.md](SECURITY.md). |
| `log-hygiene` | Runs `.github/scripts/check_log_hygiene.cs` — fails if any `src`/`samples` project uses a sensitive OAuth/OIDC parameter name (`client_secret`, `access_token`, etc.) as a structured-log placeholder, resolves ZEEKAYDA0001/ZEEKAYDA0002 below Error anywhere MSBuild/Roslyn would resolve severity, or lacks a required suppression justification — then runs the log-hygiene canary as a backstop. |
| `log-hygiene-script-tests` | Runs the fixture-driven smoke tests for `.github/scripts/check_log_hygiene.cs`. |

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

### Coverage regression check

The `coverage-regression` job protects critical paths from silent coverage drops. It does **not** compare the PR against a committed baseline file; instead, on every PR it measures coverage for both the PR head and the PR base branch (live) and fails if line coverage drops.

**How the check works:**

1. The job runs the full test suite twice — once on the PR branch, once on a clean checkout of the base branch (`github.base_ref`) in a worktree at `../coverage-base`.
2. Both runs collect `coverage.cobertura.xml` via the existing `XPlat Code Coverage` collector.
3. [`.github/scripts/check_coverage_regression.cs`](.github/scripts/check_coverage_regression.cs) — a standalone [file-based C# program](https://learn.microsoft.com/dotnet/core/tutorials/file-based-programs) — sums `lines-covered` / `lines-valid` across every Cobertura file in each results tree, computes the line-coverage percentage for each side, and compares the delta against `COVERAGE_ALLOWED_REGRESSION_PERCENT` (default `0` — no regression allowed).
4. A markdown summary is written to `$GITHUB_STEP_SUMMARY` showing the base value, PR value, and delta for both line and branch coverage.
5. The job fails with an actionable `::error::` annotation if the line-coverage delta is more negative than the allowed regression.

**Reproducing locally:**

```bash
# 1. Run tests with coverage on your branch
dotnet test --configuration Release --collect:"XPlat Code Coverage" --results-directory ./TestResults/pr

# 2. Run the same on a clean checkout of main
git worktree add ../coverage-base origin/main
( cd ../coverage-base && dotnet test --configuration Release --collect:"XPlat Code Coverage" --results-directory ./TestResults/base )

# 3. Run the regression check
dotnet run .github/scripts/check_coverage_regression.cs -- ./TestResults/pr ../coverage-base/TestResults/base

# 4. Tear down the worktree when finished
git worktree remove ../coverage-base
```

**Reading a failure:**

The CI log emits a single error line of the form:

```
::error::Line coverage regressed by 1.42 percentage points (allowed: 0.00).
```

To diagnose which files lost coverage:

1. Download both `coverage` artifacts from the Actions run (PR run and the latest `main` run).
2. Generate an HTML report with `dotnet tool install -g dotnet-reportgenerator-globaltool` then `reportgenerator -reports:**/coverage.cobertura.xml -targetdir:./coverage-html`.
3. Compare the two reports file by file — the regressed lines will be the new uncovered ones in the PR.

The fix is almost always to add a test that exercises the new or changed code path.

**Maintainer process for tolerating a regression:**

There is **no committed baseline file**. To intentionally accept a coverage decrease in a specific PR, set `COVERAGE_ALLOWED_REGRESSION_PERCENT` for that PR run — either by editing `.github/workflows/ci.yml`'s `env:` block for the duration of the PR and reverting before merge, or by negotiating a permanent floor change in a separate PR with justification in the description (e.g. "deleting a fully-covered subsystem mechanically reduces the percentage").

The `coverage-regression-script-tests` job runs [`.github/scripts/tests/check_coverage_regression.tests.sh`](.github/scripts/tests/check_coverage_regression.tests.sh) — a fixture-driven smoke test covering the script's no-change, improvement, regression, within-tolerance, and missing-input cases. Run it locally with:

```bash
bash .github/scripts/tests/check_coverage_regression.tests.sh
```

### Log hygiene check

The `log-hygiene` job runs [`.github/scripts/check_log_hygiene.cs`](.github/scripts/check_log_hygiene.cs) — a standalone [file-based C# program](https://learn.microsoft.com/dotnet/core/tutorials/file-based-programs), following the same pattern as `check_coverage_regression.cs` — to ensure that sensitive OAuth/OIDC parameter names (such as `client_secret`, `access_token`, `code_verifier`, etc.) never appear as structured-log placeholders in production code, and that ZEEKAYDA0001/ZEEKAYDA0002 (see [Analyzer rules](docs/reference/analyzer-rules.md)) cannot be silently downgraded or disabled project-wide. This is a defence-in-depth measure that complements those two Roslyn analyzers.

Its predecessor (`check_log_hygiene.sh`) enumerated four suppression *syntaxes* by text pattern; an independent review found 12 additional ways to bypass it. This script instead reads MSBuild's and Roslyn's own *resolution* of effective severity — asking the same question the compiler would ask, rather than pattern-matching the ways a suppression can be spelled. It runs three passes plus a canary backstop:

- **Pass A** — walks `Log*`/`BeginScope`/`LoggerMessage.Define*`/`[LoggerMessage]`/`StartupVerificationContext.AddWarning` call sites in a references-free compilation (used only for constant folding, so `const string` templates are resolved) and flags a sensitive placeholder name.
- **Pass B** — requires the structured `// log-hygiene-ok: <reason> (#N)` comment on any `#pragma`/`[SuppressMessage]` (including bare pragmas and multi-line/const-indirected forms) that touches either rule, and hard-fails on any `DiagnosticSuppressor`/`SuppressionDescriptor` naming either rule (no justification escape hatch for those).
- **Pass C** — asks `dotnet msbuild` for each project's evaluated `NoWarn`, `RunAnalyzers`, analyzer-reference, ruleset, and `.editorconfig`/`.globalconfig` state and asserts neither rule is downgraded below Error anywhere in that resolution. **There is no project-wide escape hatch for pass C** — a project-wide downgrade fails even with a justification comment.
- **Canary** — a small fixture project (`.github/scripts/canary/ZeeKayDa.Auth.LogHygieneCanary/`) containing one known-bad `ILogger<T>` injection and one known-bad interpolated log call, built as a discrete CI step; its build output must contain both diagnostic IDs. This is the only defence against a suppression channel pass C doesn't model.

Coverage scope is every project under the `/src/` folder of `ZeeKayDa.Auth.slnx` (this includes `ZeeKayDa.Auth.Analyzers` itself — it has no log-call sites today, so this is currently a no-op, and needs no special case to become meaningful the day it grows one) plus `samples/**/*.csproj`. `tests/` is intentionally exempt: test projects legitimately suppress these rules to assert analyzer behaviour, and test code does not ship.

Run the checker locally with:

```bash
dotnet run .github/scripts/check_log_hygiene.cs -- .
```

**When is a suppression appropriate?**

Suppressions should be rare and are only justified when:

- The code is a test fixture that never reaches production and the sensitive value is synthetic.
- The code is deliberately logging a redacted or hashed representation, not the raw secret.
- A comment explaining the safety context would be lost if the structured placeholder were renamed.

Do not suppress violations just to unblock a build. If you are unsure, ask a maintainer.

**Required suppression format:**

Append a structured comment to the offending line:

```csharp
// log-hygiene-ok: <non-empty reason> (#<issue-or-pr-number>)
```

Both a non-empty reason and a parenthesised issue or PR number are required. The bare form `// log-hygiene-ok` is **rejected** and will fail CI.

> **Note:** The CI check validates format only — that the reason field is non-empty and that a `(#N)` reference is present. It does **not** validate whether the justification is legitimate. Human code review is the real gate: reviewers are expected to assess whether the stated reason actually warrants the suppression.

**Examples:**

```csharp
// Accepted — reason and issue ref present:
_logger.LogDebug("Verifier: {code_verifier}", verifier); // log-hygiene-ok: test fixture, value is synthetic (#179)

// Rejected — bare form, no reason or ref:
_logger.LogDebug("Verifier: {code_verifier}", verifier); // log-hygiene-ok

// Rejected — reason present but no issue ref:
_logger.LogDebug("Verifier: {code_verifier}", verifier); // log-hygiene-ok: test fixture only

// Rejected — issue ref present but reason is empty:
_logger.LogDebug("Verifier: {code_verifier}", verifier); // log-hygiene-ok: (#179)
```

**Pass B — in-source suppression justification**: any `#pragma warning disable` (with or without naming `ZEEKAYDA0001`/`ZEEKAYDA0002` explicitly — a bare `#pragma warning disable` suppresses everything, including these two rules, and is caught too) or `[SuppressMessage]` attribute naming either rule must carry the same structured `// log-hygiene-ok: <reason> (#N)` comment, or the build fails. A `DiagnosticSuppressor`/`SuppressionDescriptor` naming either rule has **no** justification-comment escape hatch at all — remove it, or suppress narrowly at the call site instead.

```csharp
// Accepted:
#pragma warning disable ZEEKAYDA0002 // log-hygiene-ok: composes a constant prefix with another unformatted template; all values stay structured args (#444)

// Rejected — no structured comment at all:
#pragma warning disable ZEEKAYDA0002

// Rejected — bare pragma with no rule ID and no comment:
#pragma warning disable
```

**Pass C — no project-wide escape hatch**: a project-wide `<NoWarn>`/`<WarningsNotAsErrors>` entry, a `RunAnalyzers=false`/`RunAnalyzersDuringBuild=false` property, a `.editorconfig`/`.globalconfig` severity override (including the `dotnet_analyzer_diagnostic.severity`/`dotnet_analyzer_diagnostic.category-loghygiene.severity` bulk-severity keys), a removed analyzer reference, or a `<CodeAnalysisRuleSet>` entry downgrading either rule **always fails pass C, even with a `// log-hygiene-ok`/XML-comment justification next to it.** Only a narrowly-scoped, justified `#pragma`/`[SuppressMessage]` at the actual call site is a sanctioned suppression route.

**Review requirement:**

The hygiene checker (`.github/scripts/check_log_hygiene.cs`), its canary (`.github/scripts/canary/`), and their smoke tests are listed in CODEOWNERS. Any PR that modifies any of them requires approval from a security owner. This ensures that suppression format rules cannot be silently relaxed.

---

## Mutation Testing (Stryker.NET)

Coverage measures what code tests execute; mutation score measures whether the tests would
*notice the code being wrong*. For a security library the latter is the meaningful metric on
critical paths. Mutation testing is **not** a CI gate (see #309, deferred) — it runs locally and,
once #567 lands, on a weekly scheduled workflow.

[Stryker.NET](https://stryker-mutator.io/docs/stryker-net/introduction/) is installed as a dotnet
local tool. Each mutated target has a `stryker-config.json` in its paired test project. Run one
target from its test project directory:

```bash
cd tests/ZeeKayDa.Auth.Tests && dotnet tool run dotnet-stryker
```

| Target (config location) | Mutated scope | Baseline (2026-08-27) |
|---|---|---|
| `tests/ZeeKayDa.Auth.Tests` | `Tokens/`, `Security/`, `Clients/`, `Authorization/` | **75.77 %** |
| `tests/ZeeKayDa.Auth.AspNetCore.Tests` | `ClientAuthentication/` | **100.00 %** |
| `tests/ZeeKayDa.Auth.AzureKeyVault.Tests` | whole project | **43.55 %** |
| `tests/ZeeKayDa.Auth.FileSystem.Tests` | whole project | **62.78 %** |

Baselines are recorded from the `mutation.yml` workflow on `ubuntu-latest` — that is the canonical
environment. Local runs on macOS/Windows produce different numbers (platform-conditional tests
skip differently; at the #308 baseline FileSystem scored 74.50 % on macOS against 54.49 % on Linux), so compare local
results only against local results. In the workflow the core target runs as three per-directory
slices for wall-clock reasons; the recorded core number is from a whole-target run.

Reports land under `<test project>/StrykerOutput/` (gitignored) — open
`reports/mutation-report.html` to inspect individual mutants.

Notes on the setup, so its quirks aren't rediscovered:

- **`"test-runner": "mtp"` is required.** The default VSTest runner cannot drive this repo's
  xUnit v3 test hosts — coverage capture fails and every mutant falsely survives
  ([stryker-net#3117](https://github.com/stryker-mutator/stryker-net/issues/3117)). The MTP
  runner is correct but cannot yet filter tests per mutant
  ([stryker-net#3629](https://github.com/stryker-mutator/stryker-net/issues/3629)), so covered
  mutants run the full suite — fine for these fast suites.
- **`Endpoints/**` in AspNetCore is excluded** (explicit negation glob in its config) while the
  authorize/token endpoints are stubs. Add the glob when real implementations land.
- **`ZeeKayDa.Auth.Windows` has no config**: a third of its tests skip off-Windows, which would
  report false survivors. Its baseline comes from the Windows leg of the scheduled workflow
  (#567).
- A surviving mutant in signing/validation logic is a test gap worth an issue (see #569 for the
  baseline triage). A surviving string mutation in message text is usually not — the
  test standards deliberately don't want message-wording tests on non-security types.

---

## Release Process

This section is for maintainers.

### Cutting a stable release

1. Ensure `<VersionPrefix>` in `Directory.Build.props` reflects the intended release version (e.g. `1.0.0`).
2. Update `CHANGELOG.md` — move all entries under `[Unreleased]` to a new versioned section (e.g. `[1.0.0] - 2026-05-31`), then commit and merge to `main`.
3. Move every entry in each project's `PublicAPI.Unshipped.txt` to its `PublicAPI.Shipped.txt` (see [Public API tracking](#public-api-tracking)), then commit and merge to `main`.
4. Create and push a version tag that **exactly matches** the `<VersionPrefix>` value, prefixed with `v`:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```
5. The `publish-release.yml` workflow fires automatically, validates the tag against `Directory.Build.props`, builds, packs (with `.snupkg` symbols), and pushes to [NuGet.org](https://www.nuget.org/) using [Trusted Publishing](https://learn.microsoft.com/en-us/nuget/nuget-org/trusted-publishing) — no API key secret required.
6. Create a matching GitHub Release from the tag and add release notes.

> If the tag version does not match `<VersionPrefix>` in `Directory.Build.props`, the workflow will fail with a clear error message. Fix the mismatch and re-push the tag.

> **Prerequisites:** The Trusted Publishing policy and `NUGET_USERNAME` secret must be configured once before the first release — see the maintainer setup notes in the repository wiki.

### Preview builds

Every push to `main` automatically publishes a preview package to the [GitHub Packages NuGet feed](https://github.com/ChrisKlug/zeekayda-auth/pkgs/nuget). Preview packages follow the versioning scheme:

```
<VersionPrefix>-preview.<run_number>
```

For example: `0.1.0-preview.42`. Preview packages include `.snupkg` symbol packages so you can step into ZeeKayDa.Auth source in a debugger.

### Consuming preview packages

This section is for consuming a preview build **from your own project**, not from a clone of this
repository. Authentication requires a GitHub Personal Access Token (PAT) with at least
`read:packages` scope.

> **Never run this inside a clone of `zeekayda-auth`.** `dotnet nuget add source` without
> `--configfile` writes the source entry to the nearest `NuGet.config` in the directory
> hierarchy — inside this repo, that's the tracked, repo-root `NuGet.config` (see
> [Building Locally](#building-locally)) — weakening the repo's pinned restore source, visibly, in
> `git status`. The credential itself is stored separately, in your user-level
> `~/.nuget/NuGet/NuGet.Config` (not tracked by git), so simply reverting the tracked file does
> **not** remove the PAT from disk. Run `dotnet nuget remove source ZeeKayDa-preview` to undo both
> if you run this by mistake inside the repo.

```bash
dotnet nuget add source https://nuget.pkg.github.com/ChrisKlug/index.json \
  --name ZeeKayDa-preview \
  --username <your-github-username> \
  --password "$GITHUB_PACKAGES_PAT" \
  --store-password-in-clear-text
```

> The `--store-password-in-clear-text` flag is required on Linux and macOS where no system credential store is available. Pass your PAT via an environment variable (as above) rather than typing it literally, so it doesn't end up in shell history.

Then install the package as usual, specifying the preview version explicitly if needed:

```bash
dotnet add package ZeeKayDa.Auth --version 0.1.0-preview.42
```

---

## Security Vulnerabilities

**Do not open a public GitHub issue for security vulnerabilities.**

See [SECURITY.md](SECURITY.md) for the responsible disclosure process. Thank you for helping keep ZeeKayDa.Auth and its users safe.
