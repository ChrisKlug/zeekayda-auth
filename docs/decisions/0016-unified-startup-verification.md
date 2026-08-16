# ADR 0016 — Unified Startup Verification: One Runner, One Public Verifier, One Internal Gate

**Status:** Proposed (issue #441; awaiting security sign-off)
**Date:** 2026-08-16

> **Relationship to `IValidateOptions<T>`.** This ADR does **not** replace options validation.
> `IValidateOptions<T>` (with `ValidateOnStart()`) remains the framework's *primary* mechanism for
> anything that can be decided synchronously from options values alone — `AuthorizationServerOptions
> Validator`, `ClientRepositoryPresenceValidator`, and their peers are unchanged and stay where they
> are. The abstraction defined here is the deliberate **complement** for the checks
> `IValidateOptions<T>` structurally cannot host: async I/O (its `Validate` is synchronous, and
> blocking on async repository calls risks deadlocks), checks that need a DI **scope**, and checks
> whose whole purpose is a **side effect** (forcing construction, performing a real sign operation).
> If a check fits `IValidateOptions<T>`, it stays there. `IStartupVerifier` is not a second front
> door for options validation.

---

## Context

The framework has accumulated roughly a dozen hand-rolled `IHostedService` classes whose entire job
is to check one thing at startup and then either throw a `ZeeKayDaConfigurationException` or log a
warning. Each one re-implements the same shell — `StartAsync`, a no-op `StopAsync`, and its own
private decision about whether to throw or log — around a handful of lines of actual logic.

That is roughly ~10 lines of boilerplate per class, which on its own would not justify an
abstraction. Three things do:

1. **The pattern is not uniform, and its non-uniformity is load-bearing.** Some checks
   constructor-inject singletons; some deliberately resolve from a short-lived
   `IServiceScopeFactory` scope, either to avoid capturing a scoped implementation as a root
   singleton (`ClientRepositoryStartupActivator`) or to keep a DI resolution failure out of the
   constructor so that a friendlier `IValidateOptions<T>` message wins first. Each new check has to
   rediscover which of those it needs. The scope-resolution discipline is a footgun that is
   currently *documented in remarks* on two classes rather than made structural.

2. **A security-critical invariant currently rests on registration order.**
   `SanitizingLoggerRegistrationStartupValidator` is registered first in
   `ZeeKayDaAuthServiceCollectionExtensions` with a comment explaining that "hosted services start
   in registration order," so that no other startup check logs through a shadowed, non-redacting
   `ISanitizingLogger<>` before the shadow is detected and startup aborted. That is a convention
   plus a comment — precisely the class of invariant this project's design principles say must be
   made structurally true. It is also fragile in a way that is easy to miss: it depends on a host
   never setting `HostOptions.ServicesStartConcurrently = true`, a setting owned by the host and not
   by us.

3. **Failure semantics are accidental rather than chosen.** Today the first hosted service that
   throws aborts the host, so an operator with five misconfigurations fixes them one restart at a
   time. Nobody decided that; it fell out of `IHostedService`.

Issue #437's `SigningStartupSelfTestHostedService` — registered by `AddZeeKayDaAuthCore()` — already
established that **core takes a hosting dependency**, which removes the packaging obstacle that
would otherwise have forced this abstraction into `.AspNetCore` (where the `.AzureKeyVault`,
`.FileSystem`, and `.Windows` provider packages could not reach it).

---

## Current State

### 1. One hosted service, two collections

There is exactly **one** `IHostedService` for startup verification across the entire framework:
`StartupVerificationHostedService`, in `ZeeKayDa.Auth` (core), registered once by
`AddZeeKayDaAuthCore()` via
`services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, StartupVerificationHostedService>())`.

Its `StartAsync` runs two phases over two *separate* DI collections:

- **Phase 1 — gates.** `IEnumerable<IStartupVerificationGate>`. `IStartupVerificationGate` is
  **`internal`** to `ZeeKayDa.Auth`, exposed to first-party packages only via `InternalsVisibleTo`.
  Gates run sequentially in registration order; the first gate that reports a failure aborts
  startup immediately, with **no aggregation** and with **nothing having been logged**.
- **Phase 2 — verifiers.** `IEnumerable<IStartupVerifier>`. `IStartupVerifier` is **public**.
  Verifiers run sequentially in DI registration order; every one of them runs, warnings are logged
  as they are produced, and failures are aggregated into a single exception thrown after the loop.

Gates are a **collection** rather than a single optional singleton from day one. There is exactly
one today (the sanitizing-logger check), but making it a collection costs nothing structurally and
avoids a breaking internal reshape if a second gate-like need appears. Gate *order* is not a hazard
the way verifier order would be, because the collection is closed: only framework code can ever add
to it, so the framework always controls the order in full.

Because both phases happen inside a single `IHostedService.StartAsync`,
**`HostOptions.ServicesStartConcurrently` has no effect whatsoever on this subsystem's internal
ordering.** Whatever else the host chooses to start concurrently with us, gates still run before
verifiers, and verifiers still run one at a time in registration order. That is the structural
replacement for today's "registered first, and hosted services start in registration order"
convention.

### 2. `IStartupVerifier` — the public shape

```csharp
namespace ZeeKayDa.Auth;

/// <summary>Accumulates the failures and warnings produced by a single verifier invocation.</summary>
public sealed class StartupVerificationContext
{
    private readonly List<ZeeKayDaConfigurationFailure> _failures = [];
    private readonly List<StartupVerificationWarning> _warnings = [];

    public IReadOnlyList<ZeeKayDaConfigurationFailure> Failures => _failures;
    public IReadOnlyList<StartupVerificationWarning> Warnings => _warnings;

    /// <summary>Records a configuration failure. Startup will abort once all verifiers have run.</summary>
    public void AddFailure(string code, string message) => _failures.Add(new(code, message));

    /// <summary>Records a structured warning for the runner to log. Does not abort startup.
    /// <paramref name="messageTemplate"/> uses standard <see cref="ILogger"/> named-placeholder
    /// syntax (e.g. <c>"{StoreName}"</c>) — it is passed through to the sink unformatted, exactly
    /// like any other <c>LogWarning</c> call site, so structured backends can index the fields and
    /// <c>SecretSanitizingLogger</c>'s by-key redaction can act on them.</summary>
    public void AddWarning(string code, string messageTemplate, LogLevel level, params object?[] args)
        => _warnings.Add(new(code, messageTemplate, level, args));

    /// <summary>Overload defaulting to <see cref="LogLevel.Warning"/>.</summary>
    public void AddWarning(string code, string messageTemplate, params object?[] args)
        => AddWarning(code, messageTemplate, LogLevel.Warning, args);
}

public sealed record StartupVerificationWarning(string Code, string MessageTemplate, LogLevel Level, object?[] Args);

public interface IStartupVerifier
{
    /// <summary>Stable name used for log attribution and diagnostics only. NOT an ordering or
    /// priority hint — execution order is DI registration order, and nothing a verifier returns
    /// can influence it.</summary>
    string Name { get; }

    ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken);
}
```

`IStartupVerificationGate` is the same method signature, `internal`:

```csharp
internal interface IStartupVerificationGate
{
    string Name { get; }
    ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken);
}
```

Four properties of this shape are deliberate:

**(a) A mutable accumulator, not a returned result.** The rejected alternative was
`ValueTask<StartupVerificationResult>` with static `Ok()` / `Fail(...)` / `Warn(...)` factories —
the `IHealthCheck` → `HealthCheckResult` shape. The accumulator wins because an implementer never
has to learn how to *construct a correct return value*; they call `AddFailure` or `AddWarning` in
whichever branch they happen to be in, and a pass-through verifier has an empty method body. This is
the `ModelStateDictionary` / `ValidationContext` shape that .NET developers already know. It also
handles "warn **and** fail" and "warn twice" without a composite result type, which the result-record
shape needs an escape hatch for.

**(b) A fresh context per invocation.** The runner constructs a new `StartupVerificationContext` for
each verifier rather than passing one shared instance down the chain. That is what lets it attribute
every warning and every failure back to the producing verifier's `Name` in logs, and it means one
verifier cannot read, mutate, or clear another's findings.

**(c) `scopedServices` is a per-invocation `AsyncServiceScope`.** The runner creates a fresh scope
for every verifier invocation and passes its `ServiceProvider` in. This generalises the pattern
`ClientRepositoryStartupActivator`, `ScopePresenceStartupValidator`, and
`DistributedCacheStoreStartupValidator` each hand-roll today, and it makes the rule mechanical:
**constructor-inject only genuine singletons; resolve anything scoped from `scopedServices` inside
`VerifyAsync`.** The "captured scoped implementation as a root singleton" footgun stops being a
remark on two classes and becomes the shape of the interface. It also preserves the second reason
those classes resolve lazily: a `GetRequiredService` failure happens inside `VerifyAsync`, well after
`ValidateOnStart()`'s friendlier `IValidateOptions<T>` messages have already had their chance to win.

**(d) `ValueTask`, and one interface rather than several.** `ValueTask` because most verifiers
complete synchronously and allocating a `Task` per check at startup is pointless; async because
`ScopePresenceStartupValidator` genuinely needs awaitable repository I/O and the whole reason it is
not an `IValidateOptions<T>` is that `Validate` is synchronous. One interface rather than a
split by behaviour (validate / warn / activate) because real checks do not split that way:
`DistributedCacheStoreStartupValidator` and `InMemoryStoreWarningService` each fail *or* warn *or*
stay silent depending on a branch taken **after** a single resolution. Splitting the interface would
force them to resolve the same scoped dependency twice or stash state between two calls.

### 3. The runner owns all logging — through a logger scoped to the verifier's own type

A verifier never logs. It records warnings as data; the runner reads `context.Warnings` after
`VerifyAsync` returns and logs each one, but it does **not** log everything through its own
`ISanitizingLogger<StartupVerificationHostedService>`. Instead, for each verifier it resolves a
logger closed over that verifier's own runtime type, reusing the framework's existing open-generic
registration rather than introducing a new factory abstraction:

```csharp
var loggerType = typeof(ISanitizingLogger<>).MakeGenericType(verifier.GetType());
var verifierLogger = (ILogger)services.GetRequiredService(loggerType);
```

`AddZeeKayDaAuthCore()` already registers `ISanitizingLogger<>` as an **open generic**
(`TryAddSingleton(typeof(ISanitizingLogger<>), typeof(SecretSanitizingLogger<>))`), which is exactly
what lets the container close it over an arbitrary `Type` picked at runtime — the same mechanism
`ILogger<T>` itself relies on, just invoked reflectively instead of through a compile-time type
parameter. This costs nothing new: no `ISanitizingLoggerFactory`, no extra registration, no change to
how a verifier author consumes the type. The resulting log entries carry the verifier's own type as
their category — `MyPackage.InMemoryStoreVerifier`, not `StartupVerificationHostedService` — exactly
as if the verifier had constructor-injected `ISanitizingLogger<InMemoryStoreVerifier>` and logged
through it directly, except the verifier never holds the reference.

The runner logs each warning as `verifierLogger.Log(warning.Level, "[{Verifier}] {Code}: " +
warning.MessageTemplate, [verifier.Name, warning.Code, .. warning.Args])` — `{Verifier}` (the
instance `Name`, disambiguating same-type instances such as the two `InMemoryStoreVerifier`
registrations), `{Code}`, and every argument the verifier
supplied, passed through to the sink **unformatted**. This is full structured logging: a backend that
indexes structured fields sees `{Verifier}`, `{Code}`, and every
verifier-supplied placeholder as queryable fields, exactly as it would for any other `LogWarning`
call site in the framework — and because the arguments stay structured rather than being flattened
into a string before they reach the logger, `SecretSanitizingLogger`'s by-key redaction can act on
them the same way it already does for every other framework log call. This also turns
`InMemoryStoreWarningService`'s existing dev-vs-non-dev distinction into data — the same verifier
calls `AddWarning(..., LogLevel.Warning, ...)` in Development and `AddWarning(..., LogLevel.Critical,
...)` for the non-Development override — instead of branching over two logger calls.

Centralising *who calls `Log`* — not *which category it logs under* — is what preserves the security
property: a verifier still never holds a logger reference and cannot accidentally bypass redaction
or log before the gate has passed (§7), because the runner resolves the type-scoped logger on the
verifier's behalf, after the gate phase has already run. See Security Considerations 6 for the
residual limit this does **not** remove: an author who ignores the `{Placeholder}` convention and
interpolates a secret directly into the message-template string bypasses by-key redaction exactly as
they would with a raw `ILogger` call — structured logging makes correct usage the easy path, it does
not make incorrect usage impossible. The `Code` on `StartupVerificationWarning` remains the stable,
type-independent discriminator for log-based alerting.

### 4. Aggregation semantics

- **Phase 1 (gates): abort immediately.** The runner throws as soon as a gate reports a failure or
  throws. This is unchanged from today's behaviour and is the point of the phase existing.
- **Phase 2 (verifiers): run all, aggregate, throw once.** The runner appends each verifier's
  `context.Failures` to one running list *regardless of whether an earlier verifier already
  failed*, and after the loop throws `new ZeeKayDaConfigurationException([.. allFailures])` if the
  list is non-empty.

This is a **deliberate behaviour change** from today. Currently, a host with a missing `openid`
scope, a missing refresh-token store, and no `IDistributedCache` registered surfaces exactly one of
those per restart. After this change it surfaces all three in one `AggregatedFailures` list, in one
exception, in one restart. That is strictly better for the operator, and it is safe precisely
*because* the gate is split out: once the sanitizing-logger check is in phase 1, no phase-2 verifier
depends on any other phase-2 verifier having succeeded **for its own correctness**.
`TokenStorePresenceValidator`'s existing internal two-failure aggregation becomes a special case of
the general mechanism.

One documented ordering expectation does change, and it is a diagnostics one, not a safety one. ADR
0008 §5 states that the store presence validator "runs before the in-memory warning emitter … so a
half-registered configuration fails fast rather than emitting a misleading warning." Under phase-2
aggregation both run: the operator sees the `stores.*` presence failure *and* the in-memory store
warning in the same startup, and the host still refuses to start. Nothing is weakened — the failure
that aborts startup is identical — but the warning ADR 0008 wanted suppressed now appears alongside
it. That is the accepted cost of aggregation, and **ADR 0008 §5 must be amended in the
implementation PR** so the two ADRs do not disagree. Ordering the presence verifier before the
in-memory verifier (which DI registration order does anyway) keeps the failure first in the
operator's log.

### 5. Unexpected exceptions from a verifier

A verifier is expected to report through `context.AddFailure`. If it throws instead — a third-party
bug, or a `GetRequiredService` failure inside `VerifyAsync` — the runner catches it and rethrows as:

```csharp
throw new ZeeKayDaConfigurationException(
    new ZeeKayDaConfigurationFailure(
        "startup.verifier_failed",
        $"Verifier '{name}' threw {ex.GetType().FullName}. See the inner exception for the root cause."),
    ex);
```

The existing two-argument `ZeeKayDaConfigurationException(failure, innerException)` constructor
preserves the root cause. Startup still aborts — there is no silent swallow — but the operator gets
an attributed, legible failure naming the offending verifier rather than a bare stack trace from
inside the host's startup pipeline.

**The wrapper names the exception type, never `ex.Message`.** The message of an arbitrary
underlying exception is untrusted text: a repository connection failure, a Key Vault
`RequestFailedException` carrying a SAS-bearing URI, or a third-party verifier that interpolated a
secret into its own exception all end up there. `ZeeKayDaConfigurationFailure.Message` is a plain
string on public API surface that the framework itself encourages hosts to surface, and
`SecretSanitizingLogger` cannot redact it — that wrapper redacts structured log values *by key* and
exception messages via `RedactedExceptionWrapper`, and neither mechanism can reach credential text
already flattened into a failure message string. Copying `ex.Message` into a failure would therefore
launder it past both of the framework's redaction controls (ADR 0007 §7, ADR 0009). The root cause
remains fully available as `InnerException`, where `RedactedExceptionWrapper` *does* apply if it is
ever logged through `ISanitizingLogger<T>`. The same rule binds verifier authors: never interpolate
a caught exception's message into `AddFailure` / `AddWarning`.

A verifier that throws a `ZeeKayDaConfigurationException`
directly (the pattern every check uses today) is a special case: the runner **unwraps** it and
appends its `AggregatedFailures` to the running list rather than re-wrapping it as
`startup.verifier_failed`. Re-wrapping would replace a stable, published `Code` — for example
`signing.self_test_failed` (ADR 0015 §11) or `logging.sanitizing_logger_shadowed` — with the generic
`startup.verifier_failed`, silently breaking any operator alerting keyed on those codes and
contradicting §10's commitment that codes survive the migration verbatim. Unwrapping is also what
makes the migration of an existing check mechanical: a check can be moved to `IStartupVerifier`
before its `throw` is converted to an `AddFailure`, and its externally observable failure code does
not change at either step.

Unwrapping cannot degrade into a silent swallow, and that is a structural property rather than a
convention: **`ZeeKayDaConfigurationException.AggregatedFailures` is guaranteed non-empty by the
type itself.** Both public constructors populate it — the `params` one throws `ArgumentException`
on an empty array (`ComposeMessage`), the other takes a single failure — and the property is
get-only, so no subclass can produce an instance carrying zero failures. Absorbing therefore always
contributes at least one failure to `context.Failures`, which always aborts startup (immediately in
phase 1, after the loop in phase 2). There is no input for which the `catch` observes a
`ZeeKayDaConfigurationException` and the host still starts.

What absorbing gives up is the verifier attribution that the `startup.verifier_failed` wrapper
carries in its message. This is accepted: the codes and messages absorbed are the framework's own
published ones, which are self-identifying, and preserving them is the whole point of the
special case. It is not extended to any other exception type — a `ZeeKayDaConfigurationException` is
the only exception in the framework that carries a structured, published `Code`, so it is the only
one whose flattening would lose externally observable information.

**`OperationCanceledException` is rethrown, not wrapped.** If `cancellationToken` is signalled —
the host is shutting down while startup verification is still running — a verifier that honours the
token throws `OperationCanceledException`. Wrapping that as `startup.verifier_failed` would report a
*configuration* fault for what is an orderly shutdown, and would fire operator alerting keyed on
that code every time a deployment is cancelled mid-start. The runner therefore rethrows an
`OperationCanceledException` unchanged when `cancellationToken.IsCancellationRequested`, and only
then; a verifier that throws `OperationCanceledException` while the token is *not* signalled is a
verifier bug and is wrapped like any other unexpected exception. Either way the host does not start,
so fail-closed is unaffected — only the reported cause differs.

**No per-verifier timeout is introduced.** A verifier that hangs forever hangs startup. That is
accepted for now: every in-tree verifier is either microsecond-scale in-memory work or a call whose
transport already has its own timeout (the Key Vault SDK's, the repository's). `CancellationToken`
is already on `VerifyAsync`, so a runner-enforced timeout can be added later without a breaking
change to the interface.

### 6. Sequential, no parallelism

Verifiers run strictly sequentially, in DI registration order. There is no parallel mode and no
opt-in flag.

The rationale is that parallelism buys nothing here and costs the ordering guarantee: most verifiers
are pure in-memory checks costing microseconds, and the genuinely slow ones — the signing self-test
(#437, which performs a real sign operation), `ClientRepositoryStartupActivator` (which forces
PBKDF2 hashing of every client secret) — are exactly the **side-effecting** ones where concurrency is
least attractive. Failure composition under parallelism would also have to answer "all awaited then
aggregated, or first-wins" and "what happens to a verifier still running when another has already
decided the host is misconfigured," neither of which has a good answer for side-effecting checks.

`Name` is explicitly **not** an ordering hint, and there is no priority/order property. Execution
order is DI registration order and nothing a verifier declares can change it.

### 7. The gate: how the sanitizing-logger guarantee becomes structural

`SanitizingLoggerRegistrationStartupValidator` becomes `SanitizingLoggerRegistrationGate`, the sole
implementation of `IStartupVerificationGate`. **It moves to `ZeeKayDa.Auth` (core), together with
`SanitizingLoggerClosedOverrideScanner`, and is registered by `AddZeeKayDaAuthCore()` via
`TryAddEnumerable` — the same method that registers the runner.**

The gate must not stay in `.AspNetCore`. Nothing about it is AspNetCore-specific: the scanner
depends only on `IServiceCollection` (`Microsoft.Extensions.DependencyInjection.Abstractions`) and
`ISanitizingLogger<>`, both of which core already has — core defines `ISanitizingLogger<>`, registers
the open-generic `SecretSanitizingLogger<>`, and exposes `IServiceCollection` extension methods.
**The move adds no `PackageReference` to `ZeeKayDa.Auth`**: `DependencyInjection.Abstractions`,
`Logging.Abstractions` and `Hosting.Abstractions` (the last already required by #437's hosted
service) are all present today, and neither type touches `Microsoft.AspNetCore.*`. Both types are
`internal`, so relocating them from the `ZeeKayDa.Auth.AspNetCore` namespace into `ZeeKayDa.Auth` is
not a public-API change; their existing tests continue to compile under the
`InternalsVisibleTo("ZeeKayDa.Auth.AspNetCore.Tests")` core already declares, and should move to
`ZeeKayDa.Auth.Tests` alongside the types.
Leaving the gate behind in `.AspNetCore` while the runner ships from `AddZeeKayDaAuthCore()` opens a
real hole: `AddZeeKayDaAuthCore()` is public and is called directly by every provider package, and
`ZeeKayDaAuthBuilder` has a public constructor, so a host can reach a fully-wired signing
configuration without ever calling `AddZeeKayDaAuth()`. In that configuration the gate collection is
**empty**, phase 1 passes vacuously, and phase 2 begins resolving and logging through
`ISanitizingLogger<T>` instances that nothing has verified. Registering the
gate and the runner from the same call is what makes "there is always a gate" true by construction
rather than by which entry point the host happened to call. Its logic is otherwise unchanged.

It still aggregates `logging.sanitizing_logger_shadowed` and
`logging.sanitizing_logger_closed_override`, and both still abort startup. What changes is *why* it runs
first. Today: because it is registered first and hosted services start in registration order.
After this ADR: because it is in a **different collection**, which the single runner drains **to
completion, before it resolves `IEnumerable<IStartupVerifier>` at all**. There is no registration
order a host or third party can choose that puts an `IStartupVerifier` ahead of a gate, because they
are not in the same list.

Five supporting rules make the guarantee hold within the verification subsystem:

- **The runner logs nothing before the gate phase completes.** All logging happens inside the
  phase-2 loop, after the last gate has passed — including logging that goes through a
  per-verifier-type `ISanitizingLogger<T>` (§3), not just the runner's own. Every such `T` may itself
  be shadowed — that is exactly what the gate detects — and none is resolved or used until the gate
  has ruled that out.
- **A gate does not log.** It inspects (`_logger is not SecretSanitizingLogger<...>`) and reports
  through the context. Gate warnings are structurally possible but there are none today, and the
  runner defers logging any gate warning until after all gates have passed.
- **The runner does not *construct* a verifier before the gate phase completes.**
  `IEnumerable<IStartupVerifier>` is resolved inside `StartAsync`, after the gate loop — not
  constructor-injected (§9). Constructor injection would run every verifier's constructor, including
  a third party's, at runner-construction time, and a constructor can log: `ISanitizingLogger<T>` is
  deliberately public so that out-of-package providers can inject it (ADR 0011 Amendment 2(d)), so
  "log from a constructor through a shadowed sanitizer" is a reachable path, not a theoretical one.
  Gates are still constructor-injected; the gate collection is closed to framework types that
  provably do not log.
- **The gate ships from the same registration call as the runner** (`AddZeeKayDaAuthCore()`), so
  there is no supported configuration in which a runner exists without a gate.
- **Resolving `ISanitizingLogger<T>` for an arbitrary verifier type `T` after the gate has passed is
  safe precisely because the gate's scan is not per-`T`.**
  `SanitizingLoggerClosedOverrideScanner.FindClosedGenericOverrides()` scans the whole
  `IServiceCollection` for *any* closed-generic `ISanitizingLogger<>` override, of any `T`, not just
  the runner's own. If the gate passes, no closed-generic override exists for *any* type in the
  container — including every verifier's type — so `MakeGenericType(verifier.GetType())` cannot
  resolve a shadowed instance the gate would have missed. This is what makes the dynamic-type
  resolution in §3 a legitimate use of the gate's result, rather than a new gap the gate does not
  cover.

**Scope of the guarantee.** It covers the verification subsystem: no `IStartupVerifier`, and no
runner log call, can precede the gate. It does **not** extend to arbitrary host or third-party
`IHostedService` registrations, which the host may register before the runner and which
`HostOptions.ServicesStartConcurrently = true` may run concurrently with it. That limit is
unchanged from today's design and is out of scope here — but it is the reason the sign-off criterion
is read as "structurally guaranteed *for the framework's own startup checks*", which this design
does achieve and the registration-order convention did not.

`SanitizingLoggerRegistrationGate` is a **permanent, deliberate exception** to the migration below.
It is never an `IStartupVerifier`.

### 8. Worked examples

**(1) Validate and fail — migrated `ScopePresenceStartupValidator`:**

```csharp
internal sealed class ScopePresenceVerifier : IStartupVerifier
{
    public string Name => "ScopePresence";

    public async ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        var repository = scopedServices.GetRequiredService<IScopeRepository>();
        var scopes = await repository.GetScopesAsync(cancellationToken);

        if (!scopes.Any(s => string.Equals(s.Name, StandardScopes.OpenId.Name, StringComparison.Ordinal)))
        {
            context.AddFailure(
                "scopes.openid_missing",
                $"IScopeRepository must include the '{StandardScopes.OpenId.Name}' scope. " +
                $"Every OpenID Connect authorization request is required to include '{StandardScopes.OpenId.Name}'.");
        }
    }
}
```

The `IServiceScopeFactory` field, the `CreateAsyncScope()` call, the `StopAsync`, and the
remarks paragraph explaining why the repository is resolved from a scope all disappear — the scope is
the runner's job now. The failure code and message text are byte-identical, so existing tests that
assert on them keep passing.

**(2) Warn only — migrated `InsecureIssuerWarningService`:**

```csharp
internal sealed class InsecureIssuerVerifier(IOptions<AuthorizationServerOptions> options) : IStartupVerifier
{
    public string Name => "InsecureIssuer";

    public ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        if (options.Value.AllowInsecureIssuer)
        {
            context.AddWarning(
                "issuer.insecure_allowed",
                "AllowInsecureIssuer is enabled for issuer '{Issuer}'. This is a LOOPBACK " +
                "DEVELOPMENT-ONLY setting and must NEVER be used in production. Remove " +
                "AllowInsecureIssuer = true before deploying to any non-development environment.",
                options.Value.Issuer);
        }

        return ValueTask.CompletedTask;
    }
}
```

`IOptions<T>` is a singleton, so it stays constructor-injected; `ISanitizingLogger<T>` is gone from
the constructor because the runner logs — but the log entry this produces still carries the category
`InsecureIssuerVerifier` and a structured `{Issuer}` field, not a flattened string under the runner's
own category (§3). `ExceptionSanitizingDisabledWarningService` and
`AbsoluteFamilyLifetimeUnboundedWarningService` migrate identically.

**(3) Warns *and* fails depending on branch — migrated `DistributedCacheStoreStartupValidator`:**

```csharp
internal sealed class DistributedCacheStoreVerifier : IStartupVerifier
{
    public string Name => "DistributedCacheStore";

    public ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        var cache = scopedServices.GetService<IDistributedCache>();

        if (cache is null)
        {
            context.AddFailure(
                "stores.idistributedcache.missing",
                "The distributed-cache-backed token stores require an IDistributedCache registration. " +
                "Call AddDistributedMemoryCache() or register a distributed cache implementation.");
        }
        else if (cache is not MemoryDistributedCache)
        {
            context.AddWarning("stores.idistributedcache.non_atomic", WarningMessage);
        }
        // MemoryDistributedCache: single-node dev/test, silent.

        return ValueTask.CompletedTask;
    }
}
```

One resolution, three outcomes, one interface. This is the case that rules out splitting
`IStartupVerifier` by behaviour.

**(4) Per-instance captured state, registered N times — migrated `InMemoryStoreWarningService`:**

```csharp
internal sealed class InMemoryStoreVerifier(
    IHostEnvironment environment,
    string storeName,
    bool allowOutsideDevelopment) : IStartupVerifier
{
    public string Name => $"InMemoryStore({storeName})";

    public ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        if (environment.IsDevelopment())
        {
            context.AddWarning("stores.inmemory.active", WarningMessageFormat, storeName);
        }
        else if (!allowOutsideDevelopment)
        {
            context.AddFailure("stores.inmemory.non_development", NonDevelopmentFailureMessage);
        }
        else
        {
            context.AddWarning(
                "stores.inmemory.non_development_override",
                NonDevelopmentOverrideWarningMessageFormat,
                LogLevel.Critical,
                storeName);
        }

        return ValueTask.CompletedTask;
    }
}
```

Registered exactly as today — by factory, once per store, each capturing its own state:

```csharp
// in AddInMemoryAuthorizationCodeStore(...)
services.AddSingleton<IStartupVerifier>(sp => new InMemoryStoreVerifier(
    sp.GetRequiredService<IHostEnvironment>(),
    InMemoryStoreVerifier.AuthorizationCodeStoreName,
    allowOutsideDevelopment));
```

Note `AddSingleton<IStartupVerifier>` rather than `TryAddEnumerable` here: two registrations of the
*same implementation type* with different captured state is exactly the case `TryAddEnumerable`
deduplicates away, so this registration deliberately uses plain `AddSingleton`, as it does today.
Both the `Warning`-vs-`Critical` distinction and the per-store independence of the
`allowOutsideDevelopment` gate survive unchanged; the level is now data on the warning rather than a
second logging call site. `WarningMessageFormat` and `NonDevelopmentOverrideWarningMessageFormat`
change from `string.Format` composite-format strings (`"{0}"`) to `ILogger` named-placeholder
templates (`"{StoreName}"`) — the same rewording every migrated message needs, and the only one:
`storeName` now reaches the sink as a structured field instead of being flattened in before
`AddWarning` is even called. Note both verifier instances share the category `InMemoryStoreVerifier`
(the *type* is what a dynamically-resolved `ISanitizingLogger<T>` keys on, per §3) — the `{Verifier}`
field the runner prepends (this instance's `Name`, e.g. `InMemoryStore(AuthorizationCodeStore)`) is
what still lets an operator or log query tell the two registrations apart.

**(5) Side-effecting activation — migrated `ClientRepositoryStartupActivator`:**

```csharp
internal sealed class ClientRepositoryActivationVerifier : IStartupVerifier
{
    public string Name => "ClientRepositoryActivation";

    public ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        // Resolving triggers construction-time validation: duplicate detection, per-client checks,
        // PBKDF2 secret hashing. Any exception flows out to the runner and aborts startup; nothing
        // is caught here. A ZeeKayDaConfigurationException from the repository's constructor has its
        // AggregatedFailures absorbed with their codes intact; any other exception (a DI resolution
        // failure, say) is wrapped as startup.verifier_failed (§5).
        var repository = scopedServices.GetRequiredService<IClientRepository>();

        var inMemoryOptions = scopedServices.GetService<InMemoryClientRegistrationOptions>();
        if (inMemoryOptions is not null && repository is not InMemoryClientRepository)
        {
            context.AddWarning(
                "clients.inmemory_shadowed",
                $"AddInMemoryClients was called but the resolved IClientRepository is " +
                $"{repository.GetType().FullName}, not InMemoryClientRepository. The configured " +
                "in-memory clients are unreachable. Register a custom IClientRepository before " +
                "calling AddInMemoryClients, or remove AddInMemoryClients entirely.");
        }

        return ValueTask.CompletedTask;
    }
}
```

Being side-effecting does **not** disqualify a check from being an `IStartupVerifier` — the
per-verifier scope is precisely what makes forcing construction safe here, and letting the exception
flow rather than catching it is the correct behaviour under §5.

**(6) The gate — structurally identical, reached through the closed collection:**

```csharp
internal sealed class SanitizingLoggerRegistrationGate(
    ISanitizingLogger<SanitizingLoggerRegistrationGate> logger,
    SanitizingLoggerClosedOverrideScanner closedOverrideScanner) : IStartupVerificationGate
{
    public string Name => "SanitizingLoggerRegistration";

    public ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        if (logger is not SecretSanitizingLogger<SanitizingLoggerRegistrationGate>)
        {
            context.AddFailure("logging.sanitizing_logger_shadowed", /* unchanged message */ ...);
        }

        var closedOverrides = closedOverrideScanner.FindClosedGenericOverrides();
        if (closedOverrides.Count > 0)
        {
            context.AddFailure("logging.sanitizing_logger_closed_override", /* unchanged message */ ...);
        }

        return ValueTask.CompletedTask;
    }
}
```

Deliberately indistinguishable in shape from a regular verifier. The security property comes
entirely from *which collection it is in* and the fact that that collection is `internal`, not from
anything the type itself does. Note it still injects `ISanitizingLogger<T>` — to **inspect** the
resolved instance's type, never to log through it.

### 9. Runner pseudo-code

```csharp
internal sealed class StartupVerificationHostedService(
    IEnumerable<IStartupVerificationGate> gates,
    IServiceProvider rootServices,
    IServiceScopeFactory scopeFactory) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        // ---- Phase 1: gates. Sequential. Abort on the first failure. Nothing is logged yet. ----
        var pendingGateWarnings =
            new List<(object Source, string Name, StartupVerificationWarning Warning)>();

        foreach (var gate in gates)
        {
            await using var gateScope = scopeFactory.CreateAsyncScope();
            var gateContext = new StartupVerificationContext();

            await InvokeAsync(
                gate.Name,
                gateContext,
                ct => gate.VerifyAsync(gateContext, gateScope.ServiceProvider, ct),
                cancellationToken);

            if (gateContext.Failures.Count > 0)
                throw new ZeeKayDaConfigurationException([.. gateContext.Failures]);

            // Gate warnings (none today) are held until every gate has passed, because the
            // sanitizing logger is not yet known to be trustworthy.
            pendingGateWarnings.AddRange(
                gateContext.Warnings.Select(w => ((object)gate, gate.Name, w)));
        }

        foreach (var (source, name, warning) in pendingGateWarnings)
            LogWarning(source, name, warning);

        // ---- Phase 2: verifiers. Sequential. Run all, aggregate, throw once. ----
        // IEnumerable<IStartupVerifier> is resolved HERE rather than constructor-injected.
        // Resolving it runs every verifier's *constructor*, including third-party ones, and a
        // constructor is free to log. Deferring the resolution until after the gate phase is what
        // makes §7's "nothing logs before the gate has passed" true of verifier construction and
        // not merely of verifier execution.
        var verifiers = rootServices.GetServices<IStartupVerifier>();

        var failures = new List<ZeeKayDaConfigurationFailure>();

        foreach (var verifier in verifiers)
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var context = new StartupVerificationContext();

            await InvokeAsync(
                verifier.Name,
                context,
                ct => verifier.VerifyAsync(context, scope.ServiceProvider, ct),
                cancellationToken);

            foreach (var warning in context.Warnings)
                LogWarning(verifier, verifier.Name, warning);

            failures.AddRange(context.Failures);
        }

        if (failures.Count > 0)
            throw new ZeeKayDaConfigurationException([.. failures]);
    }

    // Resolves ISanitizingLogger<TSource> reflectively so the entry carries the producing check's
    // own category (§3), then forwards the verifier's template and args to the sink UNFORMATTED —
    // the args stay structured, so SecretSanitizingLogger's by-key redaction applies to them
    // exactly as it does at any other framework log call site. Only ever reached after the gate
    // phase has passed, for both phases.
    private void LogWarning(object source, string name, StartupVerificationWarning warning)
    {
        var sourceLogger = (ILogger)rootServices.GetRequiredService(
            typeof(ISanitizingLogger<>).MakeGenericType(source.GetType()));

        sourceLogger.Log(
            warning.Level,
            "[{Verifier}] {Code}: " + warning.MessageTemplate,
            [name, warning.Code, .. warning.Args]);
    }

    // Shared unexpected-exception handling for both phases (§5). Never swallows.
    private static async ValueTask InvokeAsync(
        string name,
        StartupVerificationContext context,
        Func<CancellationToken, ValueTask> invoke,
        CancellationToken cancellationToken)
    {
        try
        {
            await invoke(cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Orderly host shutdown during startup, not a misconfiguration. Reporting it as
            // startup.verifier_failed would fire configuration alerting on every cancelled
            // deployment. The host still does not start, so this is not a swallow.
            throw;
        }
        catch (ZeeKayDaConfigurationException ex)
        {
            // A check that throws the framework's own configuration exception already carries
            // stable, published Codes. Absorb them verbatim instead of flattening them into
            // startup.verifier_failed. AggregatedFailures is non-empty by construction (both
            // constructors of the exception guarantee it), so this always contributes at least one
            // failure. Phase 1 still aborts on the first gate to produce a failure; phase 2 still
            // aggregates. Fail-closed either way.
            foreach (var failure in ex.AggregatedFailures)
                context.AddFailure(failure.Code, failure.Message);
        }
        catch (Exception ex)
        {
            // The exception TYPE is named, never ex.Message. An arbitrary underlying exception
            // message may carry credential material (a connection string, a SAS-bearing vault URI,
            // a third-party verifier that interpolated a secret), and ZeeKayDaConfigurationFailure
            // .Message is a plain string on public API surface that SecretSanitizingLogger cannot
            // redact — it redacts structured values by key and exception messages via
            // RedactedExceptionWrapper, neither of which reaches text already flattened into a
            // failure message. The root cause stays available to operators as InnerException,
            // where the redaction wrapper does apply. See ADR 0007 §7 and ADR 0009.
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "startup.verifier_failed",
                    $"Verifier '{name}' threw {ex.GetType().FullName}. See the inner exception " +
                    "for the root cause."),
                ex);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
```

### 10. Migration scope — all of them

**Every remaining startup check migrates.** There is no "new checks only" phase and no long-lived
coexistence of two mechanisms. The single permanent exception is
`SanitizingLoggerRegistrationGate`, which is an `IStartupVerificationGate` by design and never an
`IStartupVerifier`.

Side-effecting checks are explicitly **in** scope. Being side-effecting was the candidate reason to
exempt the signing activators, and it is not a good one: the per-verifier DI scope is precisely the
mechanism that makes forcing construction and performing real I/O safe, and sequential execution
means no side effect races another.

Existing failure `Code` strings and message text are preserved verbatim through the migration.
They are part of the public API contract and existing tests assert on them; the migration changes
*where the check lives*, not *what it says*.

The work is split into follow-up implementation issues, filed after this ADR merges (they are **not**
part of the ADR PR):

1. **Core** — `IStartupVerifier`, `StartupVerificationContext`, `StartupVerificationWarning`,
   `IStartupVerificationGate`, `StartupVerificationHostedService`, its `AddZeeKayDaAuthCore()`
   registration, **the move of `SanitizingLoggerRegistrationGate` and
   `SanitizingLoggerClosedOverrideScanner` from `.AspNetCore` into core and their registration in
   the same `AddZeeKayDaAuthCore()` call**, and migrating `SigningStartupSelfTestHostedService`
   (#437) to a verifier.
2. **`ZeeKayDa.Auth.AspNetCore`** — the ~9 remaining checks, including the two
   `InMemoryStoreVerifier` factory registrations with captured state.
3. **`ZeeKayDa.Auth.AzureKeyVault`** — `AzureKeyVaultCachedSigningStartupService`'s memory-residency
   `Information` log line, if not already subsumed by (1)'s signing-self-test migration.

**Sequencing constraint (security-binding).** The gate must land in the *same* change as the
runner — issue (1) — and never later. `AddZeeKayDaAuth()` calls `AddZeeKayDaAuthCore()` near the top
of its body, well before it registers today's `AddHostedService<SanitizingLoggerRegistrationStartup
Validator>()`. If issue (1) shipped the runner and a first migrated verifier while the
sanitizing-logger check was still an old-style hosted service registered later in `AddZeeKayDaAuth()`,
the runner's phase-2 logging would execute **before** the shadow check for the whole duration of the
migration — reintroducing exactly the leak this ADR exists to close, in the window where nobody is
looking for it. Issues (2) and (3) may follow at any pace: once the gate is in phase 1, every
still-unmigrated old-style hosted service is registered after the runner and therefore still runs
after the gate.

Verifiers remain independently testable without a host, which was a hard constraint: a test
constructs the verifier, hands it a `new StartupVerificationContext()` and an
`IServiceProvider` (a `ServiceCollection().BuildServiceProvider()` or a stub), awaits `VerifyAsync`,
and asserts on `context.Failures` / `context.Warnings`. That is *easier* than today's
`StartAsync`-and-catch, because assertions run against data rather than against a thrown exception
or a captured log sink.

### 11. Forward compatibility

Every question the issue raises about future evolution is answerable without a semver-major break:

- **Warning levels, categories, extra metadata** — new optional parameters or new members on
  `StartupVerificationContext` / `StartupVerificationWarning`, both of which the framework owns and
  no third party implements.
- **A per-verifier timeout** — the runner enforces it around the existing `CancellationToken`
  parameter, no interface change.
- **Contributing a health-check entry, or re-running post-start** — a new optional interface a
  verifier may *also* implement (the `ISigningStartupSelfTest` precedent from ADR 0015 §11), never a
  new required member on `IStartupVerifier`.

The one thing that is genuinely fixed by this ADR is the `VerifyAsync` signature itself. It is one
method with three parameters, all of which are framework-owned types or BCL types, which is the
smallest surface that covers every check in the table.

### 12. The seven open questions, answered

| # | Question | Decision | Where |
| --- | --- | --- | --- |
| 1 | Public API shape of `IStartupVerifier` | Public interface, one `ValueTask VerifyAsync(StartupVerificationContext, IServiceProvider, CancellationToken)`; mutable accumulator context, not a returned result; runner-supplied per-invocation scope; `Name` for diagnostics only, no ordering hint; evolvable without a major break | §2, §11 |
| 2 | Error-aggregation semantics | Two phases. Gates abort immediately; verifiers all run and aggregate into one `ZeeKayDaConfigurationException` | §1, §4 |
| 3 | Warnings inside or outside | Inside. Warnings are a data kind on the same interface; the runner owns all logging through the sanitizing logger; level is declared per warning | §2, §3 |
| 4 | Ordering and parallelism | Strictly sequential, DI registration order, no parallelism, no priority field. Immune to `HostOptions.ServicesStartConcurrently` because everything happens inside one `StartAsync` | §1, §6 |
| 5 | Migration scope | All ~11 remaining checks, side-effecting ones included; three follow-up implementation issues; `SanitizingLoggerRegistrationGate` is the single permanent exception | §10 |
| 6 | Naming and package placement | `IStartupVerifier` / `StartupVerificationContext` / `StartupVerificationWarning` / `StartupVerificationHostedService` in `ZeeKayDa.Auth`; `IStartupVerificationGate` internal in core; the gate implementation and its scanner move into core too, registered by the same `AddZeeKayDaAuthCore()` call as the runner. Avoids collision with `Microsoft.Extensions.Options`' `IStartupValidator` | §1, §2, §7 |
| 7 | Extensibility posture | `IStartupVerifier` genuinely public; `IStartupVerificationGate` `internal` + `InternalsVisibleTo`. A misbehaving third-party verifier is handled by contract shape (it reports, it does not throw) plus a runtime guard (a thrown `ZeeKayDaConfigurationException` is absorbed with its codes intact, anything else is wrapped as `startup.verifier_failed` naming the exception type but never its message; never swallowed). Hangs are accepted for now, with a timeout addable later | §1, §5, §11 |

---

## Considered and Rejected Alternatives

### Do nothing — keep the per-service `IHostedService` pattern

**Rejected, but it is a genuine option and the honest accounting matters.** The boilerplate is
about ten lines per class, and the current model has *zero shared-failure-mode risk*: a bug in one
check cannot affect another, there is no runner to get wrong, and each class is trivially testable
by calling `StartAsync`. This ADR gives that up — one runner is now a single point of failure for
twelve checks.

It is rejected because the two things the current model cannot give are the two things that matter
most. First, the sanitizing-logger ordering guarantee remains a comment next to an `AddHostedService`
call, silently broken by a host setting `HostOptions.ServicesStartConcurrently = true` or by a
future contributor reordering registrations. Second, the scope-resolution discipline stays tribal
knowledge encoded in remarks on two classes, so each new check rediscovers it — or does not. Both
are exactly the "invariant a naive implementation can violate while still compiling and passing a
happy-path test" that this project's design principles say must be fixed structurally. The
aggregating failure semantics and the single logging chokepoint are real but secondary benefits.

### A `Priority` / `Order` property on `IStartupVerifier`

**Rejected — it fails to make the ordering guarantee structural, which is the whole point.** If
ordering is a number a verifier declares, then any verifier — including a third party's — can
declare the same or a higher priority than the sanitizing-logger check and run before it. The
invariant would go from "documented convention" to "documented convention with a number attached,"
which is not an improvement. Two disjoint collections, one of which third parties structurally
cannot register into, is the version of this that cannot be gamed. It also avoids inventing an
ordering vocabulary (what does priority 100 mean relative to 50?) that would need documenting and
would drift.

### Separate interfaces per behaviour (`IStartupValidator` / `IStartupWarner` / `IStartupActivator`)

**Rejected — it does not fit the checks that actually exist.**
`DistributedCacheStoreStartupValidator` fails when `IDistributedCache` is absent, warns when it is
present but not `MemoryDistributedCache`, and is silent otherwise — three outcomes from **one**
resolution. `InMemoryStoreWarningService` warns in Development, fails outside it, and warns at
`Critical` when overridden. Splitting the interface would force these to either resolve the same
scoped dependency twice (two scopes, two resolutions, potentially two different instances) or stash
state between two interface calls, which is worse than the thing it was trying to clean up. It would
also collide with `Microsoft.Extensions.Options.IStartupValidator`.

### A returned `StartupVerificationResult` with static `Ok()` / `Fail()` / `Warn()` factories

**Rejected in favour of the mutable accumulator.** This is the `IHealthCheck` →
`HealthCheckResult` shape, and it was the strongest alternative. It has a genuine advantage: a
verifier is a pure function, which is marginally easier to reason about. It loses on the thing that
matters more, which is what a first-time implementer has to learn. A returned result requires
knowing how to *construct* the right value — which factory, how to represent "one failure and one
warning," what `Ok()` means versus returning a result with an empty failure list. `AddFailure` /
`AddWarning` requires knowing nothing: call the one that matches the branch you are in, or call
nothing at all. The accumulator is also the shape .NET developers have already met in
`ModelStateDictionary` and `ValidationContext`, and it handles multi-outcome checks (§3's example)
without a composite result type. The pit of success is deeper with the accumulator.

### Verifier-owned logging (each verifier injects its own `ISanitizingLogger<T>`)

**Rejected — the design achieves its category-preserving advantage without its downside.** The
obvious appeal of letting each verifier hold its own `ISanitizingLogger<T>` is per-type log
categories; the chosen design gets that too, by having the runner resolve `ISanitizingLogger<T>`
reflectively over the verifier's own runtime type (§3) rather than giving up categorization for
centralization. What verifier-owned logging still loses to the chosen design: a declarative warning
level as data rather than a branch over two logger call sites (`InMemoryStoreWarningService`'s
`Warning`-vs-`Critical` today); consistent message-template conventions enforced in one place instead
of per-class discipline; and — the security point — a single chokepoint through which every startup
warning provably passes, and which resolves each logger only *after* the gate phase (§7). A verifier
that holds no logger reference cannot log before that point even if its own constructor runs early;
a verifier that held its own `ISanitizingLogger<T>` via constructor injection could not be stopped
that way. `StartupVerificationWarning.Code` remains the stable, type-independent discriminator for
alerting that a bare log category never provided.

### Fail-fast aggregation for phase 2

**Rejected — worse for operators, with no compensating safety benefit.** Fail-fast is what happens
today only because it is what `IHostedService` does, not because anyone chose it. Once the
sanitizing-logger gate is split into its own phase, the "is it safe to run verifier N after verifier
N−1 failed?" concern evaporates for the remaining checks: none of them depends on another's success,
and their failures are independent misconfigurations. An operator standing up a new deployment
should be told about all of them at once, not made to discover them one restart at a time. The
genuine fail-fast case — the credential-redaction shadow, where continuing risks *logging secrets in
the clear* — is served by phase 1, which is fail-fast by construction.

### Per-verifier timeout enforcement in the runner

**Rejected for now, explicitly addable later.** No in-tree verifier is at risk: they are either
in-memory work, or calls whose transport already imposes a timeout (the Key Vault SDK's retry and
timeout policy, per ADR 0015 §11's "apply resilience at the transport layer" position). Adding a
timeout would mean choosing a default that is either too short for a slow cold-start repository or
too long to be useful, and getting that wrong turns a working deployment into a failing one. Because
`CancellationToken` is already a parameter on `VerifyAsync`, the runner can start enforcing a
deadline later without touching the interface — a non-breaking change whenever a real case appears.

### Making startup verification a `Microsoft.Extensions.Diagnostics.HealthChecks` health check

**Rejected — wrong lifecycle.** `IHealthCheck` answers "is this instance healthy *right now*,
repeatedly, at runtime," and its natural response to a problem is to report `Unhealthy` so an
orchestrator routes traffic elsewhere. Startup verification answers "is this instance configured
correctly *at all*," and its correct response is to refuse to start. A misconfigured issuer or a
shadowed sanitizing logger must abort the host before Kestrel accepts a single connection, not
degrade a health endpoint while the process serves requests. Health checks also run repeatedly,
which is actively wrong for side-effecting checks (forcing client-secret hashing, performing a real
Key Vault sign operation). `HealthCheckResult` was evaluated seriously as a *model* for the result
shape — see the accumulator entry above — but the two mechanisms answer different questions and
should stay separate. A future verifier that also wants to contribute a health-check entry can do so
via an additional opt-in interface (§11).

---

## Consequences

### Positive

- **The sanitizing-logger ordering guarantee becomes structural.** Two disjoint collections, one
  `internal`, drained in a fixed order inside a single `StartAsync`. No registration order, no
  priority number, and no `HostOptions` setting can subvert it.
- **The scope footgun disappears.** "Constructor-inject singletons, resolve scoped things from
  `scopedServices`" is now the shape of the interface rather than a remark on two classes.
- **Operators fix N misconfigurations per restart instead of one.**
- **One logging chokepoint**, through the sanitizing logger, for every startup warning in the
  framework — with the level declared as data and the log category still the producing verifier's
  own type, resolved dynamically rather than sacrificed for centralization (§3).
- **Verifiers get easier to test**, not harder: assert on `context.Failures` / `context.Warnings`
  instead of catching an exception or capturing a log sink.
- **Twelve hosted services become one**, and a new check becomes a class with one method rather than
  a class with a lifecycle.

### Negative / Trade-offs

- **A new public extensibility surface** (`IStartupVerifier`, `StartupVerificationContext`,
  `StartupVerificationWarning`) is a SemVer commitment, and third parties will register into it.
  Mitigated by keeping it to one method and by §11's evolution paths.
- **A shared failure mode.** A bug in the runner now affects all twelve checks, where today a bug in
  one check affects one check. This is the honest cost of the "do nothing" alternative being
  rejected.
- **A verifier's warning template and args are only as safe as its author makes them.** Structured
  placeholders survive to the sink, so by-key redaction still applies — but an author who
  interpolates a secret into the template string itself bypasses it, exactly as they would with a
  raw `ILogger` call (Security Considerations 6).
- **A misconfigured host performs every side effect on every restart** rather than short-circuiting
  at the first failure — PBKDF2 over all client secrets and a live Key Vault sign operation, once
  per restart of a crash-looping deployment (Security Considerations 7).
- **A hanging verifier hangs startup**, with no timeout guard today.
- **Migration churn across ~11 tested classes** whose tests assert on specific messages and codes.
  Mitigated by preserving every code and message string verbatim.
- **Two mechanisms exist transiently** during the phased migration. Accepted because the migration
  commits to completing; a permanent two-mechanism state is explicitly not the outcome.

---

## Security Considerations

1. **The credential-redaction abort-before-anything-logs guarantee is preserved, and strengthened
   from convention to structure.** Today it rests on `AddHostedService<SanitizingLoggerRegistration
   StartupValidator>()` being the first such call plus the host not enabling
   `ServicesStartConcurrently`. After this ADR it rests on `IStartupVerificationGate` being a
   different collection from `IStartupVerifier`, drained to completion first, inside a single
   `StartAsync` that the host's concurrency setting cannot reach into. Four supporting rules close
   the remaining gaps (§7): the runner emits **no** log output at all before the last gate has passed,
   and holds no logger of its own to emit it with — every `ISanitizingLogger<T>` it uses is resolved
   on demand *after* the gate phase, because any of them might be the shadowed instance under test;
   gate warnings are buffered rather than logged inline for the same reason;
   verifiers are **resolved** after the gate phase rather than constructor-injected, so a verifier's
   constructor cannot log first either; and the gate is registered by the same
   `AddZeeKayDaAuthCore()` call as the runner, so no entry point yields a runner with an empty gate
   collection. The guarantee is scoped to the verification subsystem — an unrelated host
   `IHostedService` registered ahead of the runner, or started concurrently with it, is outside it,
   as it is today.

2. **`internal` + `InternalsVisibleTo` closes the priority-gaming risk a public ordering knob would
   leave open.** If ordering were expressible — a `Priority` property, an `Order` int, an
   `[RunsFirst]` attribute — then a third-party package, or an out-of-tree signing provider, could
   claim a position ahead of the sanitizing-logger check and log through a shadowed, non-redacting
   logger before the shadow is detected. Making the gate collection unreachable outside the framework
   means the wrong thing cannot be expressed at all, rather than being expressible and discouraged.
   This is the tier-1 fix from the "docs are not a mitigation" ladder: reshape the extension point so
   the violation is unrepresentable, rather than documenting an ordering rule and hoping.

   The residual limit is worth recording: these assemblies are not strong-named, so
   `InternalsVisibleTo` matches on simple assembly name alone. An assembly that names itself
   `ZeeKayDa.Auth.AspNetCore` would receive gate access. That requires an attacker who can already
   place an assembly in the host's load path — at which point the host is compromised regardless —
   so it is not a reason to adopt strong naming, but it is why `internal` is treated here as a
   correctness boundary against accidental misuse and API-surface creep, not as a security boundary
   against a hostile assembly.

3. **No silent swallow, and no laundering of an untrusted exception message.** A verifier that
   throws instead of reporting still aborts startup: a `ZeeKayDaConfigurationException` has its
   `AggregatedFailures` absorbed verbatim, and anything else becomes `startup.verifier_failed` with
   the original exception preserved as `InnerException`. There is deliberately no `catch`-and-continue
   path and no "log the exception and carry on" mode: a check that could not complete is
   indistinguishable from a check that failed, and both must fail closed. This matters most for the
   side-effecting verifiers — a signing self-test or a client-repository activation that throws must
   never be interpreted as "passed." It follows ADR 0015 §11's precedent, where a self-test that
   cannot complete aborts the handoff exactly as a definitive mismatch does.

   Two details of that wrapping are security-relevant. First, the wrapper embeds `ex.GetType()
   .FullName`, **never `ex.Message`** (§5): an arbitrary exception message is untrusted text that may
   carry credential material, and `ZeeKayDaConfigurationFailure.Message` is a plain public-API string
   that neither `SecretSanitizingLogger`'s key-based redaction nor `RedactedExceptionWrapper` can
   reach, while the host's own unhandled-startup-exception logger is not a sanitizing logger at all.
   Copying the message in would route credential material around both controls (ADR 0007 §7, ADR
   0009). Second, absorbing a `ZeeKayDaConfigurationException`'s failures rather than re-wrapping
   them preserves stable published `Code` values such as `signing.self_test_failed` and
   `logging.sanitizing_logger_shadowed`; flattening every throw to `startup.verifier_failed` would
   silently break operator alerting keyed on the code of a security control.

4. **Aggregation does not weaken any individual check.** Phase 2 aggregation changes *when* the
   exception is thrown, never *whether* it is. Every failure that aborts startup today still aborts
   startup, with the same `Code` and message; the operator simply sees all of them at once in
   `AggregatedFailures`. No verifier gains the ability to downgrade its own failure to a warning —
   `AddFailure` and `AddWarning` are distinct calls and only the framework's own checks choose
   between them for framework invariants.

5. **A third-party verifier still runs inside the host's startup with full DI access.** This is not
   new — anything registered in DI already has that — but it is worth stating that
   `IStartupVerifier` is not a sandbox. What the design guarantees is that a third-party verifier
   cannot run before the credential-redaction gate, cannot suppress or observe another verifier's
   findings (fresh context per invocation), cannot influence execution order, and cannot fail
   silently. It can still hang startup (§5, accepted) and it can still do anything a DI-resolved
   singleton can do.

6. **The logging chokepoint preserves by-key redaction, but cannot save an author who defeats it.**
   `SecretSanitizingLogger` redacts structured log values **by key** (`client_secret`,
   `code_verifier`, `access_token`, …) and replaces exception messages with
   `RedactedExceptionWrapper`. Because `AddWarning` takes a **message template plus args** (§2, §3)
   rather than a pre-formatted string, both mechanisms still apply end to end: the args reach the
   sink structured and keyed, so a value recorded under a sensitive placeholder name is redacted
   exactly as it would be at any other framework log call site. An earlier draft of this ADR
   flattened the message at the `AddWarning` call, which would have stripped the keys that redaction
   keys on and quietly downgraded the guarantee — that is why the structured shape is load-bearing
   and not a stylistic preference.

   The residual limits are worth naming, because the chokepoint guarantees *routing*, not
   *content*: (a) an author who interpolates a secret directly into the template string bypasses
   by-key redaction exactly as they would with a raw `ILogger` call — so the binding rule for
   verifier authors, first- and third-party, is that secret material and a caught exception's
   `Message` (§5) belong in neither the template nor a non-sensitive-keyed arg; (b) the same applies
   to `AddFailure`, which has no template/args form at all because its message lands in a
   `ZeeKayDaConfigurationFailure` on public API surface rather than in a log record; (c) a
   third-party verifier's template is author-controlled and is logged as-is, newlines included, so
   log forging via a verifier message is available to anyone who can already register a verifier — a
   low bar, and one more entry on §5's "not a sandbox" list. The implementation issue should carry
   an explicit XML-doc warning on `AddWarning` / `AddFailure` to that effect, extend the CI
   log-hygiene grep to cover those call sites and not only `ILogger` ones, and — since the runner now
   passes a template through `ILogger.Log` — confirm the `ZEEKAYDA0001` interpolated-string analyzer
   still fires on an interpolated `AddWarning` template.

7. **Aggregation makes a doomed host pay for every side effect on every restart.** Today the first
   throwing check aborts and later checks never run. Under phase-2 aggregation, a host that is
   already known to be misconfigured still executes `ClientRepositoryActivationVerifier` (PBKDF2 over
   every configured client secret — cost linear in client count and deliberately expensive per
   secret) and the signing self-test (a real Key Vault sign operation, plus key reads). In a
   restart-loop deployment — a Kubernetes `CrashLoopBackOff` is the ordinary shape of a misconfigured
   rollout — that is repeated indefinitely: sustained CPU burn and sustained request volume against a
   vault that enforces per-vault throttling limits. It is self-inflicted rather than attacker-driven,
   and bounded by the host's own restart backoff, which is why it is accepted rather than mitigated
   with a "skip side effects once failures exist" rule (that rule would reintroduce exactly the
   inter-verifier dependency §4 removes). Two things keep it small and should be treated as binding:
   side-effecting verifiers are registered **last**, after the cheap configuration checks, so a
   configuration failure is discovered before the expensive work in the common case; and no verifier
   retries internally. The sequential, no-timeout decision (§5, §6) does not add a DoS surface of its
   own — a hanging verifier hangs a host that is not yet serving traffic, which fails closed.

8. **Warning levels as data do not permit downgrading a mandatory warning.** ADR 0008 §5's
   in-memory-store warning text and ADR 0015 §6's within-window-vanish `Warning` are emitted by
   framework-owned verifiers that pass their own level; the `level` parameter is a per-call-site
   choice by the check's author, not a runtime knob an operator or third party can turn down. The
   runner logs each warning at the level it was recorded with and has no suppression path.

---

## Changelog

- **2026-08-16 — PR #443 — issue #441** — Initial ADR. Replaces ~12 hand-rolled startup-check
  `IHostedService` classes with one `StartupVerificationHostedService` running two disjoint
  collections: an `internal` `IStartupVerificationGate` phase (fail-fast, nothing logged) and a
  public `IStartupVerifier` phase (sequential, all run, failures aggregated into one
  `ZeeKayDaConfigurationException`). Verifiers report through a mutable
  `StartupVerificationContext` (`AddFailure` / `AddWarning`) and receive a runner-created per-
  invocation DI scope; the runner owns all logging. Makes the
  `SanitizingLoggerRegistrationStartupValidator` ordering guarantee structural rather than
  registration-order convention.
- **2026-08-16 — PR #443 — issue #441** — Security review amendments before merge: verifiers are
  resolved after the gate phase instead of being constructor-injected, so no verifier *constructor*
  can log first (§7, §9); the gate and its scanner move into core and register from the same
  `AddZeeKayDaAuthCore()` call as the runner, closing the empty-gate-collection gap for hosts that
  never call `AddZeeKayDaAuth()` (§7, §10); the exception wrapper names the exception type instead of
  embedding `ex.Message` in a public failure message, and absorbs a thrown
  `ZeeKayDaConfigurationException`'s failures rather than flattening its stable `Code`s to
  `startup.verifier_failed` (§5, §9); the gate is made a same-change requirement of the runner's
  implementation issue rather than a later step (§10); §4 acknowledges the ADR 0008 §5 ordering
  statement that aggregation changes; and Security Considerations gain the message-redaction limit of
  the logging chokepoint and the restart-loop side-effect cost of aggregation.
- **2026-08-16 — PR #443 — issue #441** — Architect confirmation of both security amendments, with
  three follow-on corrections: the gate move is recorded as adding no `PackageReference` to core and
  as a namespace-only relocation of two `internal` types (§7); the unwrap rule gains the structural
  argument that `AggregatedFailures` is non-empty by construction, so absorbing can never become a
  silent swallow, plus an `OperationCanceledException` rethrow so an orderly host shutdown is not
  reported as `startup.verifier_failed` (§5, §9); and §8's `ClientRepositoryActivationVerifier`
  comment, which still described a `ZeeKayDaConfigurationException` from the repository constructor
  being flattened, is corrected to match §5.

---

## References

- **Issue #441** — this design.
- **ADR 0007 §7** — credential redaction (the guarantee the sanitizing-logger gate protects).
- **ADR 0009** — exception-message sanitization in `SecretSanitizingLogger` (`RedactedExceptionWrapper`);
  the reason `ex.Message` is never copied into a `ZeeKayDaConfigurationFailure` (§5).
- **ADR 0008 §5 / §8** — in-memory store warning text; non-atomic distributed-cache stores.
- **ADR 0011 / 0015** — signing provider tiers; **ADR 0015 §11** — the `SigningStartupSelfTest
  HostedService` that established core's hosting dependency, and the "a check that cannot complete
  fails closed" precedent.
- **ADR 0014 §5** — unbounded absolute family lifetime (the escape-hatch warning).
- **Issue #437** — signing startup self-test; independent of this ADR, a natural migration target.
- **Prior art** — OpenIddict's options-validation approach; Duende IdentityServer's
  `IValidateOptions<T>` + `IHostedService` startup checks;
  `Microsoft.Extensions.Diagnostics.HealthChecks` (`IHealthCheck` → `HealthCheckResult`), evaluated
  as a result-shape model and as a hosting mechanism, and rejected as the latter.
