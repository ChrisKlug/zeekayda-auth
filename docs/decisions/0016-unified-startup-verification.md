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

    /// <summary>Records a warning for the runner to log. Does not abort startup.</summary>
    public void AddWarning(string code, string message, LogLevel level = LogLevel.Warning)
        => _warnings.Add(new(code, message, level));
}

public sealed record StartupVerificationWarning(string Code, string Message, LogLevel Level);

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

### 3. The runner owns all logging

A verifier never logs. It records warnings as data; the runner reads `context.Warnings` after
`VerifyAsync` returns and logs each one through a single shared
`ISanitizingLogger<StartupVerificationHostedService>`, at the warning's own `Level`, tagged with the
producing verifier's `Name`.

This turns `InMemoryStoreWarningService`'s existing dev-vs-non-dev distinction into data — the same
verifier calls `AddWarning(..., LogLevel.Warning)` in Development and `AddWarning(...,
LogLevel.Critical)` for the non-Development override — instead of branching over two logger calls.
Centralising it also means every startup warning in the framework goes through the sanitizing logger
by construction; a verifier cannot accidentally bypass redaction because it never holds a logger.

The trade-off is real and accepted: **per-verifier logger categorisation is lost** (every startup
warning is logged under the runner's category, not the check's own type), and warnings carry a
pre-formatted message string rather than structured logging placeholders. The `Code` on
`StartupVerificationWarning` is the structured discriminator that replaces both — it is a stable
string in the same family as `ZeeKayDaConfigurationFailure.Code`, and it is what log-based alerting
should match on.

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
depends on any other phase-2 verifier having succeeded. `TokenStorePresenceValidator`'s existing
internal two-failure aggregation becomes a special case of the general mechanism.

### 5. Unexpected exceptions from a verifier

A verifier is expected to report through `context.AddFailure`. If it throws instead — a third-party
bug, or a `GetRequiredService` failure inside `VerifyAsync` — the runner catches it and rethrows as:

```csharp
throw new ZeeKayDaConfigurationException(
    new ZeeKayDaConfigurationFailure(
        "startup.verifier_failed",
        $"Verifier '{name}' threw: {ex.Message}"),
    ex);
```

The existing two-argument `ZeeKayDaConfigurationException(failure, innerException)` constructor
preserves the root cause. Startup still aborts — there is no silent swallow — but the operator gets
an attributed, legible failure naming the offending verifier rather than a bare stack trace from
inside the host's startup pipeline. A verifier that throws a `ZeeKayDaConfigurationException`
directly (the pattern every check uses today) still works and is still wrapped the same way, which
means the migration of an existing check can be mechanical even before its throw is converted to an
`AddFailure`.

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
implementation of `IStartupVerificationGate`. It stays in `ZeeKayDa.Auth.AspNetCore`, because it
depends on `SanitizingLoggerClosedOverrideScanner` — an `IServiceCollection`-scanning type that is
AspNetCore-specific — and is registered by `AddZeeKayDaAuth()` via `TryAddEnumerable`.

Its logic is unchanged: it aggregates `logging.sanitizing_logger_shadowed` and
`logging.sanitizing_logger_closed_override` and both abort startup. What changes is *why* it runs
first. Today: because it is registered first and hosted services start in registration order.
After this ADR: because it is in a **different collection**, which the single runner drains **to
completion, before it resolves `IEnumerable<IStartupVerifier>` at all**. There is no registration
order a host or third party can choose that puts an `IStartupVerifier` ahead of a gate, because they
are not in the same list.

Two supporting rules make the guarantee airtight:

- **The runner logs nothing before the gate phase completes.** All logging happens inside the
  phase-2 loop, after the last gate has passed. The runner's own
  `ISanitizingLogger<StartupVerificationHostedService>` may itself be a shadowed instance — that is
  exactly what the gate detects — and it is never used until the gate has ruled that out.
- **A gate does not log.** It inspects (`_logger is not SecretSanitizingLogger<...>`) and reports
  through the context. Gate warnings are structurally possible but there are none today, and the
  runner defers logging any gate warning until after all gates have passed.

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
                $"AllowInsecureIssuer is enabled for issuer '{options.Value.Issuer}'. " +
                "This is a LOOPBACK DEVELOPMENT-ONLY setting and must NEVER be used in production. " +
                "Remove AllowInsecureIssuer = true before deploying to any non-development environment.");
        }

        return ValueTask.CompletedTask;
    }
}
```

`IOptions<T>` is a singleton, so it stays constructor-injected; `ISanitizingLogger<T>` is gone
because the runner logs. `ExceptionSanitizingDisabledWarningService` and
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
            context.AddWarning(
                "stores.inmemory.active",
                string.Format(CultureInfo.InvariantCulture, WarningMessageFormat, storeName));
        }
        else if (!allowOutsideDevelopment)
        {
            context.AddFailure("stores.inmemory.non_development", NonDevelopmentFailureMessage);
        }
        else
        {
            context.AddWarning(
                "stores.inmemory.non_development_override",
                string.Format(CultureInfo.InvariantCulture, NonDevelopmentOverrideWarningMessageFormat, storeName),
                LogLevel.Critical);
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
second logging call site.

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
        // PBKDF2 secret hashing. Any exception — including a ZeeKayDaConfigurationException from the
        // repository's constructor, or a DI resolution failure — flows out to the runner, which
        // wraps it as startup.verifier_failed and aborts. Nothing is caught here.
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
    IEnumerable<IStartupVerifier> verifiers,
    IServiceScopeFactory scopeFactory,
    ISanitizingLogger<StartupVerificationHostedService> logger) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        // ---- Phase 1: gates. Sequential. Abort on the first failure. Nothing is logged yet. ----
        foreach (var gate in gates)
        {
            await using var gateScope = scopeFactory.CreateAsyncScope();
            var gateContext = new StartupVerificationContext();

            await InvokeAsync(
                gate.Name,
                ct => gate.VerifyAsync(gateContext, gateScope.ServiceProvider, ct),
                cancellationToken);

            if (gateContext.Failures.Count > 0)
                throw new ZeeKayDaConfigurationException([.. gateContext.Failures]);

            // Gate warnings (none today) are held until every gate has passed, because the
            // sanitizing logger is not yet known to be trustworthy.
            pendingGateWarnings.AddRange(gateContext.Warnings.Select(w => (gate.Name, w)));
        }

        foreach (var (name, warning) in pendingGateWarnings)
            logger.Log(warning.Level, "[{Verifier}] {Code}: {Message}", name, warning.Code, warning.Message);

        // ---- Phase 2: verifiers. Sequential. Run all, aggregate, throw once. ----
        var failures = new List<ZeeKayDaConfigurationFailure>();

        foreach (var verifier in verifiers)
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var context = new StartupVerificationContext();

            await InvokeAsync(
                verifier.Name,
                ct => verifier.VerifyAsync(context, scope.ServiceProvider, ct),
                cancellationToken);

            foreach (var warning in context.Warnings)
                logger.Log(warning.Level, "[{Verifier}] {Code}: {Message}", verifier.Name, warning.Code, warning.Message);

            failures.AddRange(context.Failures);
        }

        if (failures.Count > 0)
            throw new ZeeKayDaConfigurationException([.. failures]);
    }

    // Shared unexpected-exception wrapping for both phases (§5). Never swallows.
    private static async ValueTask InvokeAsync(
        string name, Func<CancellationToken, ValueTask> invoke, CancellationToken cancellationToken)
    {
        try
        {
            await invoke(cancellationToken);
        }
        catch (Exception ex)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "startup.verifier_failed",
                    $"Verifier '{name}' threw: {ex.Message}"),
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
   registration, and migrating `SigningStartupSelfTestHostedService` (#437) to a verifier.
2. **`ZeeKayDa.Auth.AspNetCore`** — the gate plus the ~9 remaining checks, including the two
   `InMemoryStoreVerifier` factory registrations with captured state.
3. **`ZeeKayDa.Auth.AzureKeyVault`** — `AzureKeyVaultCachedSigningStartupService`'s memory-residency
   `Information` log line, if not already subsumed by (1)'s signing-self-test migration.

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
| 6 | Naming and package placement | `IStartupVerifier` / `StartupVerificationContext` / `StartupVerificationWarning` / `StartupVerificationHostedService` in `ZeeKayDa.Auth`; `IStartupVerificationGate` internal in core; the gate implementation in `.AspNetCore`. Avoids collision with `Microsoft.Extensions.Options`' `IStartupValidator` | §1, §2, §7 |
| 7 | Extensibility posture | `IStartupVerifier` genuinely public; `IStartupVerificationGate` `internal` + `InternalsVisibleTo`. A misbehaving third-party verifier is handled by contract shape (it reports, it does not throw) plus a runtime guard (unexpected exceptions wrapped as `startup.verifier_failed`, never swallowed). Hangs are accepted for now, with a timeout addable later | §1, §5, §11 |

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

**Rejected.** It preserves per-type log categories, which is a real loss in the chosen design, but
it costs three things worth more: consistent message formatting and verifier attribution across
every startup warning in the framework; a declarative warning level as data rather than a branch
over two logger call sites; and — the security point — a single chokepoint through which every
startup warning provably passes the sanitizing logger. A verifier that holds no logger cannot
accidentally log through a raw `ILogger<T>` and bypass redaction. The `Code` on
`StartupVerificationWarning` recovers most of the diagnostic value that the per-type category
provided, as a stable string rather than a type name.

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
  framework — with the level declared as data.
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
- **Per-verifier log categories are lost.** Every startup warning is logged under
  `StartupVerificationHostedService`. `StartupVerificationWarning.Code` is the replacement
  discriminator; any log-based alerting keyed on the old per-type categories must be re-keyed.
- **Structured-logging placeholders collapse to a pre-formatted message string** at the
  `AddWarning` call. The `Code` carries the machine-readable part instead.
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
   `StartAsync` that the host's concurrency setting cannot reach into. Two supporting rules close the
   remaining gaps: the runner emits **no** log output at all before the last gate has passed (its own
   `ISanitizingLogger<StartupVerificationHostedService>` might itself be the shadowed instance under
   test), and gate warnings are buffered rather than logged inline for the same reason.

2. **`internal` + `InternalsVisibleTo` closes the priority-gaming risk a public ordering knob would
   leave open.** If ordering were expressible — a `Priority` property, an `Order` int, an
   `[RunsFirst]` attribute — then a third-party package, or an out-of-tree signing provider, could
   claim a position ahead of the sanitizing-logger check and log through a shadowed, non-redacting
   logger before the shadow is detected. Making the gate collection unreachable outside the framework
   means the wrong thing cannot be expressed at all, rather than being expressible and discouraged.
   This is the tier-1 fix from the "docs are not a mitigation" ladder: reshape the extension point so
   the violation is unrepresentable, rather than documenting an ordering rule and hoping.

3. **No silent swallow of a verifier's failure.** A verifier that throws instead of reporting is
   wrapped as `startup.verifier_failed` with the original exception preserved as `InnerException`,
   and startup still aborts. There is deliberately no `catch`-and-continue path and no "log the
   exception and carry on" mode: a check that could not complete is indistinguishable from a check
   that failed, and both must fail closed. This matters most for the side-effecting verifiers — a
   signing self-test or a client-repository activation that throws must never be interpreted as
   "passed." It follows ADR 0015 §11's precedent, where a self-test that cannot complete aborts the
   handoff exactly as a definitive mismatch does.

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

6. **Warning levels as data do not permit downgrading a mandatory warning.** ADR 0008 §5's
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

---

## References

- **Issue #441** — this design.
- **ADR 0007 §7** — credential redaction (the guarantee the sanitizing-logger gate protects).
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
