---
title: "Analyzer rules"
description: "Reference for the Roslyn analyzer rules shipped with ZeeKayDa.Auth (ZEEKAYDA0001, ZEEKAYDA0002, ZEEKAYDA0003)."
parent: "Reference"
nav_order: 4
---

*Added in Unreleased.*

ZeeKayDa.Auth ships a Roslyn analyzer package that enforces compile-time log-hygiene requirements
for code inside the `ZeeKayDa.*` namespace. Violations are reported as build errors so that
credential-leak paths are caught during development rather than in production.

The analyzer targets code written inside the library itself, not application code that consumes
ZeeKayDa.Auth. Consumer-side log hygiene is covered in
[Configure host-level log hygiene](../how-to/configure-host-log-hygiene.md).

---

## ZEEKAYDA0001 — Direct `ILogger<T>` use

| Attribute | Value |
|---|---|
| Rule ID | `ZEEKAYDA0001` |
| Category | `LogHygiene` |
| Severity | Error |

### What it enforces

`ILogger<T>` must not be injected directly into a ZeeKayDa.Auth service. All internal services
must accept `ISanitizingLogger<T>` instead. `ISanitizingLogger<T>` wraps the underlying logger
with `SecretSanitizingLogger`, which redacts known-sensitive OAuth parameters before any log entry
reaches the log sink.

Bypassing this wrapper by injecting `ILogger<T>` directly creates a path through which sensitive
values — `client_secret`, `code_verifier`, `Authorization`, and others — can reach the log sink
unredacted.

### Violation

```csharp
// ZEEKAYDA0001: ILogger<T> injected directly.
public sealed class TokenEndpointHandler
{
    private readonly ILogger<TokenEndpointHandler> _logger;

    public TokenEndpointHandler(ILogger<TokenEndpointHandler> logger)
    {
        _logger = logger;
    }
}
```

### Compliant alternative

```csharp
// Correct: ISanitizingLogger<T> used instead.
public sealed class TokenEndpointHandler
{
    private readonly ISanitizingLogger<TokenEndpointHandler> _logger;

    public TokenEndpointHandler(ISanitizingLogger<TokenEndpointHandler> logger)
    {
        _logger = logger;
    }
}
```

> ⚠️ **Warning:** `ISanitizingLogger<T>` only redacts values passed via named structured-logging
> placeholders. Log calls that embed sensitive values through string interpolation bypass the
> redaction layer entirely. See [ZEEKAYDA0002](#zeekayda0002--non-constant-string-in-log-call)
> for the rule that catches this.

### Suppression

Suppressions require justification and team review. A CI check
(`.github/scripts/check_log_hygiene.sh`) enforces this for a specific set of suppression forms: a
single-line `#pragma warning disable` naming `ZEEKAYDA0001` or `ZEEKAYDA0002`; a single-line
`[SuppressMessage(...)]` attribute (bare or fully qualified); a single-line `<NoWarn>` entry in a
`.csproj`/`Directory.Build.props`; and a single-line `.editorconfig` severity override below
`error`. Each must carry a structured `// log-hygiene-ok: <reason> (#<issue-or-pr-number>)`
comment on the same line — or, for `<NoWarn>`, a trailing `<!-- log-hygiene-ok: ... -->` XML
comment, and for `.editorconfig`, a standalone comment line immediately above the override
(`.editorconfig` doesn't support trailing inline comments). Any of these forms without the
required justification fails the build.

This check is a grep-based script, not a semantic analysis, and it does not cover every way to
silence the analyzer. It does **not** detect: suppressions split across multiple lines;
`.globalconfig` files; `Directory.Build.targets`; `<NoWarn>$(SomeProperty)</NoWarn>`-style MSBuild
property indirection; a category-wide `dotnet_analyzer_diagnostic.category-LogHygiene.severity`
override; analyzer-disabling switches such as `<RunAnalyzers>false</RunAnalyzers>` or
`<EnforceCodeStyleInBuild>false</EnforceCodeStyleInBuild>`; or suppressions placed outside the
paths this script searches (for example, test or sample projects). None of those routes need to
mention `ZEEKAYDA0001`/`ZEEKAYDA0002` in the diff at all, so treat a clean run of this script as
evidence against the specific forms above, not as proof that no suppression exists. Closing this
gap with a structural, compiler-driven check (rather than pattern matching) is tracked in a
follow-up issue.

```csharp
#pragma warning disable ZEEKAYDA0001 // log-hygiene-ok: legacy adapter predates ISanitizingLogger<T>, migration tracked (#123)
private readonly ILogger<TokenEndpointHandler> _logger;
#pragma warning restore ZEEKAYDA0001
```

`.editorconfig` suppression:

```ini
[src/ZeeKayDa.Auth/**/*.cs]
; log-hygiene-ok: legacy adapter predates ISanitizingLogger<T>, migration tracked (#123)
dotnet_diagnostic.ZEEKAYDA0001.severity = none
```

> ⚠️ **Warning:** Suppressing this rule removes the compile-time safety net for the affected
> type. Any suppression must be reviewed and justified in a code comment explaining why the
> `ISanitizingLogger<T>` wrapper is not applicable.

---

## ZEEKAYDA0002 — Non-constant string in log call

| Attribute | Value |
|---|---|
| Rule ID | `ZEEKAYDA0002` |
| Category | `LogHygiene` |
| Severity | Error |

### What it enforces

`Log*` message templates inside `ZeeKayDa.*` namespaces must be compile-time constant strings.
Interpolated strings, variable references, string concatenation with non-literal operands,
`string.Format`, and any other non-constant expression are all flagged regardless of the
identifier names involved.

The rule also constrains one specific non-`Log*` method by symbol rather than by name/receiver
heuristic: `StartupVerificationContext.AddWarning`'s `messageTemplate` parameter. `AddWarning` is
how an `IStartupVerifier`/`IStartupVerificationGate` implementation reports a warning for the
startup-verification runner to log on its behalf (see [ADR
0016](../decisions/0016-unified-startup-verification.md) §3, §9) — its template flows into the same
redaction-sensitive log call the `Log*` branch above protects, so it needs the same constant-string
guarantee even though it isn't itself a call to `ILogger`.

### Rationale

`SecretSanitizingLogger` redacts sensitive values by inspecting the structured-logging message
template and its named arguments at the point the log entry is written. An interpolated string is
fully expanded by the C# compiler before it is passed to the logger — the logger receives a
plain `string` with the sensitive value already embedded. The message template is gone; there
are no named placeholders to inspect. The redaction layer therefore has no mechanism to detect
or remove the value.

This is a silent credential-leak path: the code compiles and runs without error, log calls
appear to work normally, and sensitive values arrive at the log sink in plaintext.

### Violation

```csharp
// ZEEKAYDA0002: interpolated string is not a compile-time constant.
_logger.LogInformation($"Verifying client_secret: {clientSecret}");

// ZEEKAYDA0002: concatenation with a variable is not a compile-time constant.
_logger.LogDebug("Processing request for client: " + clientId);

// ZEEKAYDA0002: local variable (even if it holds a literal) is not a compile-time constant.
var msg = "Starting request";
_logger.LogInformation(msg);
```

### Compliant alternative

```csharp
// Correct: string literal is a compile-time constant.
_logger.LogInformation("Verifying client_secret: {ClientSecret}", redacted);

// Correct: two string literals concatenated are still a compile-time constant.
_logger.LogInformation("part one {X} " + "part two {Y}", x, y);

// Correct: pass dynamic values as structured-logging arguments, not in the template.
_logger.LogDebug("Processing request for client {ClientId}", clientId);
```

> 💡 **Tip:** If you genuinely need to include a sensitive value for a diagnostic purpose, pass
> a pre-redacted representation — for example, the first four characters followed by `***` — as
> the structured argument rather than the raw value. Never pass the raw credential.

### Suppression

Suppressions require justification and team review, using the same structured
`// log-hygiene-ok: <reason> (#<issue-or-pr-number>)` comment form described under
[ZEEKAYDA0001's Suppression section](#suppression), including the same coverage limits of the CI
check that enforces it. See `StartupVerificationHostedService.LogWarning` for a real example of
the required form.

```csharp
#pragma warning disable ZEEKAYDA0002 // log-hygiene-ok: diagnostic-only, key material never leaves this dev-only build config (#123)
_logger.LogDebug($"Diagnostic — raw key material: {keyMaterial}");
#pragma warning restore ZEEKAYDA0002
```

`.editorconfig` suppression:

```ini
[src/ZeeKayDa.Auth/**/*.cs]
; log-hygiene-ok: diagnostic-only, key material never leaves this dev-only build config (#123)
dotnet_diagnostic.ZEEKAYDA0002.severity = none
```

> ⚠️ **Warning:** Suppressing this rule disables the compile-time check for the affected call
> sites. Any suppression must be accompanied by a code comment explaining why the non-constant
> string is safe at that specific location and confirming that no sensitive value can reach
> the log sink through the suppressed call.

---

## ZEEKAYDA0003 — `IClientRepository` does not reference `IClientRegistrationValidator`

| Attribute | Value |
|---|---|
| Rule ID | `ZEEKAYDA0003` |
| Category | `Extensibility` |
| Severity | Warning |

### What it checks

Any out-of-assembly `IClientRepository` implementation whose type body contains no reference to
`IClientRegistrationValidator` is flagged. ADR 0007 §6.1 requires every custom repository to resolve
the validator from DI and call it before persisting a new or updated client registration. A
repository that never references the validator at all is almost certainly missing this step.

The rule fires on classes, records, structs, and record structs that implement `IClientRepository`
(directly or transitively through an intermediate interface).

### In-assembly exemption

Types compiled into an assembly named `ZeeKayDa.Auth` are exempt — these are the in-framework
repository implementations, which are validated by other means. The exemption is an exact
simple-name match on the assembly name; there is no public-key-token check. This is consistent with
the precedent set by [ZEEKAYDA0001](#zeekayda0001--direct-iloggert-use) and
[ZEEKAYDA0002](#zeekayda0002--non-constant-string-in-log-call).

The exemption keys on the **assembly name**, not the namespace. An implementation placed in a
`ZeeKayDa.Auth.*`-prefixed namespace but compiled into a consumer assembly is still flagged.

### Violation

```csharp
// ZEEKAYDA0003: implements IClientRepository but never references IClientRegistrationValidator.
public sealed class MyClientRepository : IClientRepository
{
    public ValueTask<IClientRegistration?> FindByClientIdAsync(
        string clientId, CancellationToken cancellationToken = default)
        => ValueTask.FromResult<IClientRegistration?>(null);
}
```

### Compliant alternative

```csharp
// Correct: the validator is resolved and available to validate before persisting.
public sealed class MyClientRepository : IClientRepository
{
    private readonly IClientRegistrationValidator _validator;

    public MyClientRepository(IClientRegistrationValidator validator)
        => _validator = validator;

    public ValueTask<IClientRegistration?> FindByClientIdAsync(
        string clientId, CancellationToken cancellationToken = default)
        => ValueTask.FromResult<IClientRegistration?>(null);
}
```

### Heuristic limitation

> ⚠️ **Warning:** This rule is a presence check, not a correctness check. It looks for **any**
> reference to `IClientRegistrationValidator` in the type body — a constructor parameter, a field,
> a property, a local variable, a method call on a stored instance, or even a bare `typeof()`
> reference. It does **not** verify that the validator is ever invoked, nor that it is invoked
> before a registration is persisted, nor that it is invoked at every relevant call site.
>
> A clean build proves only that a reference exists. It does **not** prove that validation is
> correctly wired. Treat a passing ZEEKAYDA0003 as a reminder that you still own the
> responsibility of calling the validator before persisting, and review your write paths
> accordingly.

### False positives

The check is satisfied only by the exact `IClientRegistrationValidator` type from the
`ZeeKayDa.Auth.Clients` namespace. If your repository depends on a wrapper or derived interface —
for example `IMyValidator : IClientRegistrationValidator` — the analyzer does not see the base type
through the derived reference and fires a false positive. In that case, reference the
`IClientRegistrationValidator` type directly, or suppress the diagnostic with a justification
comment (see below).

### Suppression

Suppressions require justification and team review.

```csharp
#pragma warning disable ZEEKAYDA0003 // IClientRepository does not reference IClientRegistrationValidator
public sealed class MyClientRepository : IClientRepository
#pragma warning restore ZEEKAYDA0003
```

`.editorconfig` suppression:

```ini
[**/*.cs]
; IClientRepository does not reference IClientRegistrationValidator
dotnet_diagnostic.ZEEKAYDA0003.severity = none
```

> ⚠️ **Warning:** Suppressing this rule removes the reminder for the affected type. Any suppression
> must be accompanied by a code comment explaining the intentional custom validation strategy and
> confirming that client registrations cannot be persisted without validation.

---

## Related pages

- [Configure host-level log hygiene](../how-to/configure-host-log-hygiene.md) — runtime log
  hygiene steps for ASP.NET Core host surfaces outside ZeeKayDa.Auth's redaction boundary
- [AuthorizationServerOptions reference](configuration.md) — core authorization server configuration
- [Public API tracking](../../CONTRIBUTING.md#public-api-tracking) — `Microsoft.CodeAnalysis.PublicApiAnalyzers`
  workflow that fails the build on an undeclared public API change (`RS0016`/`RS0017`/`RS0025`/`RS0036`)
