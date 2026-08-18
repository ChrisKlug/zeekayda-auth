# ADR 0009 — Exception Message Sanitization in `SecretSanitizingLogger`

Status: Accepted   ·   Date: 2026-06-18   ·   Issue: #173

## Decision

`SecretSanitizingLogger<T>` redacts sensitive key-value pairs in structured log state, but forwards
the `Exception?` argument passed to `ILogger.Log<TState>` to the inner logger untouched — so an
exception whose `Message` embeds raw credential material (a misconstructed throw site, a
third-party exception type) reaches every log sink unredacted, regardless of what the structured
state contains.

`SecretSanitizingLogger<T>` now wraps every non-null exception, **unconditionally**, in an
`internal sealed RedactedExceptionWrapper`:

- `Message` is replaced with a fixed placeholder.
- `StackTrace` and the full inner-exception chain are preserved (each inner exception wrapped
  recursively, depth-limited).
- `OriginalExceptionType` exposes the original exception's fully-qualified type name, so structured
  sinks retain type-based filtering/alerting without the message text.

The wrapping is unconditional — never gated on whether the log state contains a sensitive key,
the exception type, or a keyword match against the message. An opt-out,
`AuthorizationServerOptions.Logging.DisableExceptionSanitizing`, exists for local development
(`appsettings.Development.json`) and always emits a `LogLevel.Critical`-adjacent
`LogLevel.Warning` startup warning when enabled, via the same `IStartupVerifier` pattern used
elsewhere (e.g. `InsecureIssuerWarningService`).

`BeginScope<TState>` carries no `Exception?` parameter in the `ILogger` contract, so it has no
equivalent risk surface and needed no change.

## Why

- **Conditional wrapping (gate on sensitive-key match) was rejected.** The `Exception?` argument and
  the structured `TState` are independent inputs chosen at the call site — a benign log template can
  carry an exception whose message embeds a raw secret. Keyword-matching exception message prose is
  also a heuristic that misses novel patterns and needs ongoing maintenance as new credential types
  are added. Unconditional wrapping closes the gap structurally and cannot be bypassed by a new call
  site or exception type.
- **Full suppression (pass `null` to the inner logger) was rejected.** It would discard exception
  type, stack trace, and inner-exception chain — information that is load-bearing for diagnosing a
  production `error=server_error` from logs alone. The wrapper preserves everything that is safe to
  log and suppresses only the message text.
- **The opt-out lives on `AuthorizationServerOptions.Logging`, not the builder.** Configuration data
  belongs on `AuthorizationServerOptions`; DI registrations belong on `ZeeKayDaAuthBuilder` (see ADR
  0002). `LoggingOptions` must stay `public` (not `internal`) because `AuthorizationServerOptions` is
  bound from `IConfiguration`, and the explicit, unambiguous property name is deliberate so it reads
  as a conscious risk escalation in configuration review.
- **The startup warning lives in an `IStartupVerifier`, not `IValidateOptions<T>`.** `Validate` must
  return a `ValidateOptionsResult` with no logging side-effect; emitting a warning is an out-of-band
  effect that belongs in the same startup-verification path `InsecureIssuerWarningService` already
  uses.

## Consequences

- Exception messages are never logged by ZeeKayDa.Auth services in normal operation. Operators who
  need the original message for post-incident diagnosis must reproduce the failure in a
  non-production environment with `DisableExceptionSanitizing: true`, or rely on an APM integration
  that captures exceptions out-of-band (middleware-level capture, not the `ILogger` sink path — an
  APM tool registered as an `ILogger` sink receives the same redacted wrapper as everything else).
  This must be disclosed in `SecretSanitizingLogger`'s XML docs and the log-hygiene how-to guide.
- Structured sinks that record exception type names will show `RedactedExceptionWrapper`, not the
  original type — `OriginalExceptionType` carries the real name for operators who need it.
- `DisableExceptionSanitizing` is read from `IOptions<AuthorizationServerOptions>` (singleton-bound)
  and cannot be toggled at runtime — the correct constraint for a security policy switch, but worth
  documenting so it isn't mistaken for a live toggle.
