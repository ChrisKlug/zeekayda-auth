# ADR 0009 — Exception Message Sanitization in `SecretSanitizingLogger`

**Status:** Accepted  
**Date:** 2026-06-18

---

## Context

Issue #173 identified a gap in `SecretSanitizingLogger<T>`: the `Exception? exception` parameter
passed to `ILogger.Log<TState>` is forwarded to the inner logger completely untouched.
`SecretSanitizingLogger` redacts sensitive structured-log state (key-value pairs in the `TState`
parameter) but does not inspect or transform the exception argument. If an exception's `Message`
contains raw credential material — for example, a `ZeeKayDaConfigurationException` whose message
was constructed by a throw site that inadvertently includes a secret, or a custom `Exception`
subclass from a third-party library that formats credential values into its message — that
credential material reaches every log sink verbatim and unredacted.

The gap is present in all three branches of the current `Log<TState>` implementation:

- When structured state contains sensitive keys and is replaced with a redacted copy (the primary
  redaction path), the `exception` argument is still forwarded unchanged.
- When state is opaque or non-enumerable and is replaced with the
  `[ZeeKayDa: unscrubbable log state blocked]` placeholder, the `exception` argument is still
  forwarded unchanged.
- When state is a plain string or sanitized structured state that required no redaction, the
  `exception` argument is still forwarded unchanged.

Three options were evaluated in issue #173:

**Option A — Suppress the exception message; preserve structure.** Wrap the exception in a
sanitizing proxy that replaces `Exception.Message` with a fixed placeholder but preserves the
stack trace, inner exception chain, and original exception type name. The wrapper is applied
unconditionally.

**Option B — Conditional inspection.** Inspect the exception message against the sensitive-key
list used for structured state. Wrap only when a known sensitive keyword is found in the message
text.

**Option C — Full exception suppression.** Pass `null` to the inner logger in place of any
non-null exception, discarding all exception information from the log entry.

The project owner chose a variant of Option A.

**Terminology.** Throughout this ADR, *sanitizing* refers to replacing sensitive structured-log
key values with `[REDACTED]` — the key-value redaction already performed by
`SecretSanitizingLogger<T>`. *Redacting* (as applied to exception messages) refers to suppressing
the exception `Message` text entirely, replacing it with a fixed placeholder. These are distinct
operations with different threat models; they must not be treated as synonyms.

---

## Decision

### 1. Chosen option: unconditional message suppression with structural preservation (variant of Option A)

When `SecretSanitizingLogger<T>` receives a non-null `Exception?` argument in `Log<TState>`, it
wraps the exception in a `RedactedExceptionWrapper` before passing it to the inner logger. The
wrapper:

- Replaces `Exception.Message` with the fixed placeholder:
  `[exception message redacted by SecretSanitizingLogger]`
- Preserves the original `Exception.StackTrace` verbatim via a `StackTrace` property override.
- Preserves the full inner exception chain. Each inner exception is also wrapped by
  `RedactedExceptionWrapper` recursively, so no exception message at any depth in the chain
  reaches the log sink unredacted.
- Exposes the original exception's fully-qualified type name as the string property
  `OriginalExceptionType`, accessible to structured log sinks that interrogate exception object
  properties (Serilog, Seq, Application Insights structured exception enrichers, and similar).

When a `ZeeKayDaException` subtype is wrapped, the structured data defined in ADR 0006
(`AggregatedFailures.Code` etc.) remains accessible on the original exception; only `Message` is
suppressed from log sinks by this wrapper. See ADR 0006 for the full exception hierarchy and the
structured data each subtype carries.

The wrapper is applied **unconditionally** to every non-null exception. It is not conditional on
whether the structured log state contains a sensitive key, whether the exception type is a
`ZeeKayDaException` subtype, or whether the message matches any keyword pattern.

`RedactedExceptionWrapper` is an `internal sealed` class in `ZeeKayDa.Auth`. It is not part of
the public API surface.

### 2. Why unconditional and not conditional (Option B rejected)

Conditional wrapping — applying the wrapper only when the structured log state contains a
sensitive key — creates a structural gap. The `Exception?` argument and the structured `TState`
are independent inputs supplied by the call site. A call site can pass a benign log template with
no sensitive structured keys while simultaneously passing an exception whose message contains raw
credential material embedded by a lower-level library, a third-party dependency, or a custom
exception subclass. Under conditional wrapping, that exception reaches the log sink unredacted.

Additionally, keyword matching against exception message text requires applying the `SensitiveKeys`
set (or a derived list) as a text-search heuristic over prose. Exception messages are free-form
strings generated by arbitrary code throughout the stack. They do not reliably embed credentials
using the same key names as structured log parameters. Any heuristic list misses patterns it has
not anticipated. The list must grow with every new credential type added to the framework and
cannot anticipate patterns introduced by third-party code.

Unconditional wrapping closes the gap structurally. Every exception that enters
`SecretSanitizingLogger<T>.Log<TState>` with a non-null value has its message suppressed,
regardless of origin, exception type, or log state contents. The protection cannot be bypassed at
a new call site through a novel exception type or an unexpected message format.

The cost of this unconditional policy — diagnostic loss of exception message text — is real,
bounded, and mitigatable (see §4). The cost of conditional wrapping — a protection gap that grows
with the call surface — is unbounded.

### 3. Why not full suppression (Option C rejected)

Full suppression — passing `null` to the inner logger — eliminates all exception-origin
information from the log entry. The exception type name, stack trace, and inner exception chain
are all discarded. For a production identity server where a single unexplained `error=server_error`
response must be diagnosable from logs, this is operationally unacceptable.

An operator who receives `error=server_error` from a client and finds only a log entry with no
exception information has no automated path to root-cause the failure from logs alone. The
message-suppression approach preserves exactly the information that is safe to log — type name,
stack trace, inner exception chain — while suppressing only the message text.

### 4. Diagnostic loss: acknowledgement and operator guidance

Suppressing exception messages is a real operational trade-off. Exception messages are often the
most human-readable diagnosis of a failure. Under this design, that text is not written to the
log sink by ZeeKayDa.Auth services.

Operators who require the original exception message for post-incident diagnosis have the
following paths:

- **APM / exception tracking integrations — integration path matters.** Tools such as Application
  Insights, Sentry, and Datadog can be integrated in two distinct ways, and only one of them
  bypasses `SecretSanitizingLogger<T>`.

  - **ILogger sink path (common).** When an APM tool is registered as an `ILogger` sink — for
    example via `services.AddApplicationInsightsTelemetry()`, Serilog's Application Insights sink,
    or Sentry's `logging.AddSentry()` integration — it receives log entries through the
    `Microsoft.Extensions.Logging` pipeline. Every log entry passes through
    `SecretSanitizingLogger<T>` before reaching the sink. The APM tool will receive the
    `RedactedExceptionWrapper` with the redacted placeholder message, not the original exception.
    **Operators must not assume that APM captures via the ILogger sink path preserve original
    exception messages.**

  - **Out-of-band capture path (limited coverage).** Some APM tools also capture exceptions via
    separate mechanisms that operate outside the logging pipeline: ASP.NET Core exception-handling
    middleware, `TelemetryClient.TrackException()` called directly, Sentry's ASP.NET Core
    middleware, or Datadog's tracer hooks. These captures occur independently of
    `SecretSanitizingLogger<T>` and will record the original exception message. However, this path
    only covers exceptions that propagate unhandled to the middleware layer. Exceptions that
    ZeeKayDa.Auth catches internally and logs via `ILogger` — the normal case for authentication
    and authorization failures — do not propagate to that layer and are not captured out-of-band.

  APM tooling therefore provides only partial coverage and is not a reliable general-purpose
  recovery path for original exception messages from ZeeKayDa.Auth's internal logging.

- **Structured exception stores.** Any middleware that captures and stores exceptions directly (a
  custom `IExceptionFilter` writing to a secure database, an exception-tracking service) operates
  outside the structured log pipeline and is unaffected by this wrapper. The same coverage
  limitation applies: only exceptions that propagate to that middleware layer are captured.
- **`AuthorizationServerOptions.Logging.DisableExceptionSanitizing` in development.** The opt-out
  mechanism described in §5 is intended for local development environments where credential
  exposure in logs is acceptable in exchange for full diagnostic detail. Set it to `true` in
  `appsettings.Development.json`. **This is the recommended path for reproducing and diagnosing
  an exception message from ZeeKayDa.Auth's internal logging** — if a production incident
  requires the original exception message, reproduce the failure in a non-production environment
  with `DisableExceptionSanitizing: true` active rather than relying on APM to have captured it
  in production.
- **`OriginalExceptionType` on the wrapper.** The fully-qualified type name of the original
  exception is preserved and emitted by structured sinks that enumerate exception properties.
  Operators can filter and alert on exception types (e.g.
  `OriginalExceptionType = "ZeeKayDa.Auth.ZeeKayDaStoreException"`) without requiring the message
  text.

The `SecretSanitizingLogger` XML documentation and the `configure-host-log-hygiene.md` how-to
guide must disclose the exception message redaction behaviour and point operators to these recovery
paths. The redaction must not be a surprise in production.

### 5. Opt-out: `AuthorizationServerOptions.Logging.DisableExceptionSanitizing`

The opt-out is a `bool` property on a `LoggingOptions` group exposed as a get-only property on
`AuthorizationServerOptions`:

```csharp
// appsettings.Development.json
{
  "ZeeKayDaAuth": {
    "Logging": {
      "DisableExceptionSanitizing": true
    }
  }
}
```

When `true`, `SecretSanitizingLogger<T>.Log<TState>` passes the original `Exception?` argument
to the inner logger unchanged — the `RedactedExceptionWrapper` is bypassed entirely.

The placement of this opt-out as a framework-behavior group on `AuthorizationServerOptions`
follows the convention established in ADR 0002 §5 and the 2026-06-13 framework-behavior-groups
amendment. Configuration data (what the server is configured with) belongs on
`AuthorizationServerOptions`; DI service registrations (what the server is composed of) belong on
`ZeeKayDaAuthBuilder`. Placing a runtime-configuration flag on the builder — as the initial
implementation did — violated this boundary.

`LoggingOptions` is a `public sealed` class so that it is bindable from `IConfiguration`. The
property name `DisableExceptionSanitizing` is deliberately explicit: it must read as a conscious
escalation of risk in configuration review, not a neutral toggle.

### 6. Startup warning when exception sanitization is disabled

`ExceptionSanitizingDisabledWarningService` is always registered by `AddZeeKayDaAuth()` as an
`IHostedService`. In `StartAsync`, it reads `AuthorizationServerOptions.Logging.DisableExceptionSanitizing`
and emits a single `LogLevel.Warning` if the flag is set, using
`ISanitizingLogger<ExceptionSanitizingDisabledWarningService>` as the log category. The warning
message:

> Exception message sanitization is disabled via AuthorizationServerOptions.Logging.DisableExceptionSanitizing.
> Exception messages logged by ZeeKayDa.Auth services may contain credential material and will reach
> log sinks unredacted.

This follows the exact pattern established by `InsecureIssuerWarningService`, which emits an
equivalent startup warning when `AllowInsecureIssuer` is set: an `internal sealed class`
implementing `IHostedService`, checking the condition in `StartAsync`, emitting the warning at
`LogLevel.Warning` if the flag is active.

`LogLevel.Warning` is used unconditionally regardless of environment. Escalating to `LogLevel.Error`
in production was considered but rejected: `DisableExceptionSanitizing` set to `true` in a
production `appsettings.json` is a configuration error, not a runtime failure, and should be
prevented by environment-scoped configuration files rather than severity escalation in the service
itself. `LogLevel.Warning` is consistent with `InsecureIssuerWarningService` and avoids triggering
on-call paging for a deliberate opt-out.

### 7. Interaction with `LoggerMessage.Define<T>` and `[LoggerMessage]` source-generated callers

Both `LoggerMessage.Define<T>` and the C# `[LoggerMessage]` source generator produce state
objects that implement `IReadOnlyList<KeyValuePair<string, object?>>`, which also satisfies
`IEnumerable<KeyValuePair<string, object?>>`. These callers are already handled by the
structured-state redaction path in `SecretSanitizingLogger<T>` — they land in the
`IEnumerable<KeyValuePair<string, object?>>` branch and have sensitive key-value pairs redacted.

The exception sanitization introduced by this ADR operates on the `Exception?` parameter, which
is entirely independent of the `TState` type and structured state. Whether the caller is a
high-performance source-generated log method, a `LoggerMessage.Define<T>` delegate, or a direct
`logger.LogWarning(exception, "message")` call, the exception-wrapping logic is identical: if
`exception != null` and sanitization is enabled, replace it with a `RedactedExceptionWrapper`.

There is no allocation concern specific to source-generated or `LoggerMessage.Define<T>` callers
beyond what applies to all log calls: one `RedactedExceptionWrapper` is allocated per non-null
exception argument, plus one per depth level in the inner exception chain. This is appropriate for
a logging code path where a non-null exception is a minority of calls.

The `Func<TState, Exception?, string> formatter` parameter in `ILogger.Log<TState>` also receives
the exception argument. When `SecretSanitizingLogger<T>` substitutes the wrapped exception, all
`inner.Log(...)` call sites pass `safeException` (the wrapped form) consistently — both as the
explicit `exception` argument and as the value the inner logger's formatter will receive.

### 8. `BeginScope` does not carry the same risk

The `ILogger.BeginScope<TState>` method signature does not include an `Exception?` parameter.
The `ILogger` contract defined in `Microsoft.Extensions.Logging.Abstractions` has no exception
surface on `BeginScope`. An exception cannot reach a log sink through the `BeginScope` path.

The existing `SecretSanitizingLogger<T>.BeginScope<TState>` implementation correctly inspects and
redacts sensitive key-value pairs in the scope state. This is sufficient for that surface. No
modification to `BeginScope` is required or in scope for this ADR.

No parallel fix is needed for `BeginScope`. If a future version of
`Microsoft.Extensions.Logging.Abstractions` adds an exception surface to `BeginScope`, a new ADR
must be written to assess the risk at that time. For all .NET 10 targets, `BeginScope` is not a
risk surface for exception message leakage.

---

## Full Implementation Surface

The following describes exactly what must be added or modified. No other files are affected by
this ADR.

### New file: `src/ZeeKayDa.Auth/Logging/RedactedExceptionWrapper.cs`

An `internal sealed` class in the `ZeeKayDa.Auth.Logging` namespace that inherits from
`Exception`. Being `internal sealed` is a deliberate design choice: sinks receive the wrapper as
`Exception` and can only observe the sanitized `Message`, the original `StackTrace`, and
`OriginalExceptionType`. The `OriginalExceptionType` property exists specifically to support the
`SecretSanitizingLogger` formatter rendering the original type name in the sanitized log line,
so that operators retain type-based filtering and alerting capability without the message text.
Consumers of the library cannot reference or pattern-match on `RedactedExceptionWrapper` by name.

Inheritance from `Exception` is required so that structured log sinks which pattern-match on
`Exception` continue to handle the wrapper correctly (serialising the stack trace, recording an
inner exception chain). Key members:

- Constructor: `RedactedExceptionWrapper(Exception original)` — calls
  `base("[exception message redacted by SecretSanitizingLogger]", original.InnerException is not null ? new RedactedExceptionWrapper(original.InnerException) : null)`
  and stores the original for property delegation.
- `StackTrace` property override: returns `_original.StackTrace`.
- `OriginalExceptionType` property: `public string OriginalExceptionType => _original.GetType().FullName ?? _original.GetType().Name;`

The parameterless constructor and the legacy `SerializationInfo`/`StreamingContext`
deserialization constructor are omitted, consistent with the rules established in ADR 0006 §1.

Implementers should add a depth limit (e.g. 50 inner exception levels) to protect against
pathologically deep exception chains. Beyond the limit, the innermost exception may be truncated
with a note in its wrapper message.

### New file: `src/ZeeKayDa.Auth/Logging/LoggingOptions.cs`

A `public sealed` class in the `ZeeKayDa.Auth.Logging` namespace exposed as a get-only
framework-behavior group on `AuthorizationServerOptions`:

```csharp
public sealed class LoggingOptions
{
    public bool DisableExceptionSanitizing { get; set; }
}
```

### Modified: `src/ZeeKayDa.Auth/AuthorizationServerOptions.cs`

`AuthorizationServerOptions` gains a `Logging` framework-behavior group:

```csharp
public LoggingOptions Logging { get; } = new();
```

### Modified: `src/ZeeKayDa.Auth/Extensions/ZeeKayDaAuthCoreServiceCollectionExtensions.cs`

In `AddZeeKayDaAuthCore()`, add `services.AddOptions<AuthorizationServerOptions>();` to ensure that
`SecretSanitizingLogger<T>` can resolve `IOptions<AuthorizationServerOptions>` even when
`AddZeeKayDaAuthCore()` is called standalone without `AddZeeKayDaAuth()`. `AddOptions<T>()` is
idempotent.

### Modified: `src/ZeeKayDa.Auth/Logging/SecretSanitizingLogger.cs`

`SecretSanitizingLogger<T>` takes `IOptions<AuthorizationServerOptions>` instead of
`IOptions<SecretSanitizingLoggerOptions>`. In `Log<TState>`, an `IsEnabled` guard is added at the
top to avoid allocating `RedactedExceptionWrapper` when the inner logger would discard the entry
anyway. The `WrapException` method reads `options.Value.Logging.DisableExceptionSanitizing`.

### Modified: `src/ZeeKayDa.Auth.AspNetCore/ExceptionSanitizingDisabledWarningService.cs`

Takes `IOptions<AuthorizationServerOptions>` instead of `IOptions<SecretSanitizingLoggerOptions>`,
and no longer injects `IHostEnvironment`. `LogLevel.Warning` is used unconditionally. The service
is registered unconditionally by `AddZeeKayDaAuth()` and reads the flag at `StartAsync` time.

---

## Rejected Alternatives

### Option B — Conditional wrapping based on sensitive-key matching in the exception message

**Rejected.** The `Exception?` argument and the structured `TState` are independent inputs. A
call site can pass an exception whose message contains a raw `client_secret` while logging a
benign template with no sensitive structured keys; under conditional logic, that exception reaches
the sink unredacted. Keyword matching against exception message prose is a heuristic that misses
novel patterns and requires ongoing list maintenance as new credential types are added to the
framework. Unconditional wrapping has no list-maintenance burden and cannot be bypassed by any
call site through a novel exception type or unexpected message format.

### Option C — Full exception suppression (pass `null`)

**Rejected.** Full suppression eliminates exception type names, stack traces, and inner exception
chains from the log entry. For a production identity server, these are load-bearing for
post-incident diagnosis. An operator who receives `error=server_error` without any exception
information in the log has no automated path to root-cause the failure. The wrapper approach
preserves all diagnostically-useful, non-sensitive information.

### Conditional wrapping based on whether the call state contains a sensitive key

**Rejected** for the same reason as Option B. There is no invariant that a log call with no
sensitive structured keys also has an exception with no sensitive message. The two inputs are
independently chosen at the call site.

### Making `LoggingOptions.DisableExceptionSanitizing` internal

**Rejected.** Making the opt-out an `internal`-only mechanism was considered to prevent consumers
from directly configuring it. However, because `AuthorizationServerOptions` is bindable from
`IConfiguration` — its primary consumption model — the opt-out property must be `public` for
`IConfiguration` binding to work. The risk of accidental production activation is mitigated by
the `appsettings.Development.json` environment-scoped configuration pattern documented in §5 and
the startup warning emitted by `ExceptionSanitizingDisabledWarningService`.

### Placing the startup warning in `IValidateOptions<AuthorizationServerOptions>`

**Rejected.** `IValidateOptions<T>.Validate` must return a `ValidateOptionsResult` and must not
emit log entries as a side-effect. Warning emission is an out-of-band effect inappropriate in a
validation method. The `IHostedService` pattern, established by `InsecureIssuerWarningService`
and `ScopePresenceStartupValidator`, is the correct location for startup-time side-effects.

### Applying exception wrapping in `BeginScope` as a parallel fix

**Not applicable.** `ILogger.BeginScope<TState>` does not accept an `Exception?` parameter. There
is no exception surface to wrap. See §8.

---

## Consequences

### Positive

- **The gap identified in issue #173 is closed structurally.** Exception messages no longer reach
  log sinks through `SecretSanitizingLogger<T>` regardless of call pattern, exception type, or
  log state contents. The protection applies uniformly to `LoggerMessage.Define<T>` and source-
  generated `[LoggerMessage]` callers with no special handling required.
- **Diagnostic structure is preserved.** Stack traces, inner exception chains, and exception type
  names all remain in the log entry. Operators can identify exception origin and type from logs
  without requiring the message text.
- **The opt-out is explicit and auditable.** `AuthorizationServerOptions.Logging.DisableExceptionSanitizing`
  is bindable from `IConfiguration`, follows the framework-behavior-groups convention (ADR 0002),
  and emits a startup warning when active.
- **Consistent with existing patterns.** The startup warning service follows the
  `InsecureIssuerWarningService` precedent exactly. The internal options type follows the
  `Configure<T>` pattern established elsewhere.
- **No change to `BeginScope`.** The existing `BeginScope` implementation is correct and
  complete. No new risk surface was found.

### Negative / Trade-offs

- **Exception messages are never logged by ZeeKayDa.Auth services in normal operation.** This is
  a real diagnostic cost. Operators who relied on exception messages appearing in log aggregators
  for post-incident diagnosis must adapt their runbooks to use APM exception captures or
  structured exception stores. The deployment documentation must make this explicit.
- **`RedactedExceptionWrapper` type name appears in structured sink output.** Structured log
  sinks recording exception type names will show `RedactedExceptionWrapper` rather than the
  original type name. The `OriginalExceptionType` property on the wrapper carries the original
  type name for this reason. Sinks that do not consume exception properties will show only the
  placeholder message.
- **Recursive inner exception wrapping allocates proportionally to exception chain depth.** A
  deeply nested exception will produce a corresponding number of `RedactedExceptionWrapper`
  instances. Acceptable for a logging path. A depth limit must be implemented.
- **`DisableExceptionSanitizing` takes effect at DI configuration time and cannot be toggled at
  runtime.** The flag is read from `IOptions<AuthorizationServerOptions>`, which is singleton-bound.
  This is the correct constraint for a security policy switch, but it must be documented.
- **Redaction may surprise operators unaware of this design.** The placeholder string is
  unambiguous but will be unexpected to operators who have not read the framework documentation.
  The `SecretSanitizingLogger` XML remarks and the `configure-host-log-hygiene.md` guide must
  prominently disclose this behaviour.
