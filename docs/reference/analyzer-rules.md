---
title: "Analyzer rules"
description: "Reference for the Roslyn analyzer rules shipped with ZeeKayDa.Auth (ZEEKAYDA0001, ZEEKAYDA0002)."
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

Suppressions require justification and team review.

```csharp
#pragma warning disable ZEEKAYDA0001 // Direct ILogger<T> use
private readonly ILogger<TokenEndpointHandler> _logger;
#pragma warning restore ZEEKAYDA0001
```

`.editorconfig` suppression:

```ini
[src/ZeeKayDa.Auth/**/*.cs]
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

Suppressions require justification and team review.

```csharp
#pragma warning disable ZEEKAYDA0002 // Non-constant string in log call
_logger.LogDebug($"Diagnostic — raw key material: {keyMaterial}");
#pragma warning restore ZEEKAYDA0002
```

`.editorconfig` suppression:

```ini
[src/ZeeKayDa.Auth/**/*.cs]
dotnet_diagnostic.ZEEKAYDA0002.severity = none  // Non-constant string in log call
```

> ⚠️ **Warning:** Suppressing this rule disables the compile-time check for the affected call
> sites. Any suppression must be accompanied by a code comment explaining why the non-constant
> string is safe at that specific location and confirming that no sensitive value can reach
> the log sink through the suppressed call.

---

## Related pages

- [Configure host-level log hygiene](../how-to/configure-host-log-hygiene.md) — runtime log
  hygiene steps for ASP.NET Core host surfaces outside ZeeKayDa.Auth's redaction boundary
- [AuthorizationServerOptions reference](configuration.md) — core authorization server configuration
