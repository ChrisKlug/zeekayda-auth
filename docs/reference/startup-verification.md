---
title: "Startup verification"
description: "Reference for IStartupVerifier, IStartupActivator, StartupVerificationContext, and how to add framework- or provider-owned startup checks to ZeeKayDa.Auth."
parent: "Reference"
nav_order: 7
---

*Added in Unreleased.*

ZeeKayDa.Auth runs every startup check — its own internal checks and any you add — through a single `IHostedService`, once, before the host finishes starting. Most configuration mistakes are already caught earlier by [`IValidateOptions<T>`](https://learn.microsoft.com/dotnet/core/extensions/options-validation) validation on `AuthorizationServerOptions`, which is synchronous. These seams exist for the checks that structurally cannot be: anything that needs async I/O, a scoped DI dependency, or a genuine side effect (forcing construction of a repository, performing a real cryptographic sign operation to prove a signing key is reachable).

There are two of them, and **which one you implement decides when your check runs**:

| Interface | Phase | For a check that |
|---|---|---|
| `IStartupVerifier` | second | only reads options or inspects the container |
| `IStartupActivator` | third | calls into a caller-supplied extension point — a repository, a signing key source, a scope store |

Both derive from `IStartupCheck`, which carries the two members. **The activator phase does not run at all if any verifier reported a failure**, so an application whose issuer is misconfigured never opens a connection to a key vault before being told about the issuer. Resolving a service whose construction runs someone else's code counts as calling into it: if resolving it can do work, your check is an activator.

## `IStartupCheck`, `IStartupVerifier`, and `IStartupActivator`

```csharp
public interface IStartupCheck
{
    string Name { get; }

    ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken);
}

public interface IStartupVerifier : IStartupCheck;   // phase 2 — cheap
public interface IStartupActivator : IStartupCheck;  // phase 3 — does real work
```

| Member | Contract |
|---|---|
| `Name` | A stable name used for log attribution and diagnostics only. It is **not** an ordering or priority hint — execution order within a phase is DI registration order, and nothing a check returns can influence it. |
| `VerifyAsync` | Runs the check. Report outcomes by calling `context.AddFailure(...)` and `context.AddWarning(...)` — never throw except for a genuinely unexpected failure (a DI resolution error, a third-party bug). |

Register an implementation the same way you register any other service:

```csharp
builder.Services.AddSingleton<IStartupVerifier, MyCustomVerifier>();      // cheap
builder.Services.AddSingleton<IStartupActivator, MyRepositoryActivator>(); // does real work
```

### Rules for implementing a verifier

- **Never log directly.** The runner logs every warning on your behalf, under a log category matching your own implementation type, after the internal gate phase has completed (see [How verifiers run](#how-verifiers-run)). A verifier that constructor-injects `ILogger<T>` or `ISanitizingLogger<T>` and calls it directly bypasses this and may log before it is safe to do so.
- **Resolve only genuine singletons from the constructor.** Resolve anything scoped from the `IServiceProvider` passed to `VerifyAsync` — the runner creates a fresh `AsyncServiceScope` for every invocation. Constructor-injecting a scoped service as if it were a singleton is exactly the footgun this design exists to prevent.
- **Report through the context; don't throw for expected outcomes.** Call `context.AddFailure` for a configuration problem you detected. Only let an exception propagate for something genuinely unexpected — the runner treats a thrown `ZeeKayDaConfigurationException` as if its `AggregatedFailures` had already been added to the context, and wraps any other exception as an unexpected verifier failure (see [Unexpected exceptions](#unexpected-exceptions)).
- **Being side-effecting is fine — register it as an `IStartupActivator`.** A check that forces construction of a repository, or performs a real sign operation to prove a key is reachable, is a legitimate use of the per-check scope. Putting it in the activator phase is what stops it running for a host that is already known to be misconfigured.
- **Do not depend on running after another check.** Order within a phase is registration order and is not a guarantee. If your check needs another's work done first, ask for it — that is why `ISigningKeyRing.EnsureInitializedAsync` is idempotent, so the check that validates client registrations against the advertised algorithms can call it rather than assume it runs second.

## `StartupVerificationContext`

Accumulates the failures and warnings produced by a single verifier invocation. The runner constructs a fresh instance for every invocation, so nothing on it needs to be reset between checks, and one verifier can never read, mutate, or clear another's findings.

```csharp
public sealed class StartupVerificationContext
{
    public void AddFailure(string code, string message);

    public void AddWarning(string code, string messageTemplate, LogLevel level, params object?[] args);

    public void AddWarning(string code, string messageTemplate, params object?[] args); // LogLevel.Warning

    public IReadOnlyList<ZeeKayDaConfigurationFailure> Failures { get; }

    public IReadOnlyList<StartupVerificationWarning> Warnings { get; }
}
```

| Member | Contract |
|---|---|
| `AddFailure(code, message)` | Records a configuration failure. Does not throw or abort immediately — the runner aborts startup once the current phase has finished running. `code` should be a stable, versioned string identifier (e.g. `"stores.idistributedcache.missing"`); `ZeeKayDaConfigurationFailure.Code` is part of the public API contract and must not change without a semver-major bump. |
| `AddWarning(code, messageTemplate, level, args)` | Records a structured warning for the runner to log at the given `LogLevel`. Does not abort startup. |
| `AddWarning(code, messageTemplate, args)` | Same, logged at `LogLevel.Warning`. |

`messageTemplate` uses standard `ILogger` named-placeholder syntax (e.g. `"{StoreName}"`), not string interpolation. It is passed through to the sink unformatted, exactly like any other `LogWarning` call site, so structured logging backends can index the fields and the framework's redaction layer can act on them by key.

> ⚠️ **Warning:** Interpolating a value directly into `messageTemplate` instead of passing it as a named-placeholder argument bypasses by-key redaction — the same way it would at any other framework log call site. If the interpolated value could ever be a secret, this is a real disclosure risk, not a style nit. `messageTemplate` must be a compile-time constant; this is enforced by the [`ZEEKAYDA0002`](analyzer-rules.md#zeekayda0002--non-constant-string-in-log-call) analyzer everywhere in the codebase that logs, including here.

## How verifiers run

Startup verification runs in three phases, all inside the same hosted service's startup call:

1. **Internal gates run first**, sequentially, and abort startup immediately on the first failure — with nothing logged yet. These exist only inside the framework itself (for example, the check that the redaction-layer logger has not been shadowed by a competing DI registration) and are not an extension point; there is no public interface for adding one.
2. **Your `IStartupVerifier` instances run second**, once every gate has passed. Every registered verifier runs — a failure in one does not skip the rest — and every failure across the phase is aggregated into a single `ZeeKayDaConfigurationException` thrown once, after the loop. Warnings are logged as they are produced.
3. **Your `IStartupActivator` instances run third**, and **only if the verifier phase produced no failure at all**. The phase aggregates the same way.

Three consequences of this shape matter to you as an implementer:

- **You see every problem in one restart**, not one problem per restart. A host missing both the `openid` scope and an `IDistributedCache` registration gets both failures in one `AggregatedFailures` list.
- **Your check cannot run before the internal gates have passed**, and nothing you register can reorder that. This is what guarantees the redaction layer is already trustworthy by the time your warnings are logged.
- **An activator sees a configuration that already passed every cheap check.** If your check is expensive, or reaches out over a network, that is where it belongs.

## Unexpected exceptions

If `VerifyAsync` throws instead of reporting through the context, the runner distinguishes two cases:

- **A thrown `ZeeKayDaConfigurationException`** is absorbed verbatim — its `AggregatedFailures` are added to the running failure list, preserving their original stable codes.
- **Any other exception** is recorded as a failure and the phase continues:

  ```csharp
  context.AddFailure(
      "startup.verifier_failed",
      $"Verifier '{name}' threw {ex.GetType().FullName}. See the inner exception for the root cause.");
  ```

  The exception itself travels as the phase aggregate's `InnerException` — an `AggregateException` when more than one check threw. One check with a bug therefore no longer hides the genuine, fixable configuration errors reported beside it.

> ⚠️ **Warning:** The wrapper names the exception's **type**, never `ex.Message`. An arbitrary underlying exception's message is untrusted text — a database connection string, a cloud SDK exception carrying a SAS-bearing URI, anything a lower layer decided to put in `Message`. `ZeeKayDaConfigurationFailure.Message` is a plain string on public API surface that the redaction layer cannot act on, so it must never carry raw exception text. The original exception is preserved as `InnerException`, where it stays available to an operator through their logging or crash-dump pipeline, redacted the same way any other logged exception is if it is ever logged through the framework's sanitizing logger. Apply the same rule in your own verifiers: if you must describe a caught exception in a failure or warning, name its type, not its message.

Startup still aborts either way — there is no silent swallow — but the operator gets an attributed, legible failure naming the offending check, alongside every other failure in that phase, rather than a bare stack trace from inside the host's startup pipeline.

## Worked examples

The following patterns cover every shape a real verifier takes.

**Validate and fail:**

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

        if (!scopes.Any(s => string.Equals(s.Name, "openid", StringComparison.Ordinal)))
        {
            context.AddFailure(
                "scopes.openid_missing",
                "IScopeRepository must include the 'openid' scope. Every OpenID Connect " +
                "authorization request is required to include 'openid'.");
        }
    }
}
```

**Warn only:**

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

`IOptions<T>` is a singleton, so it stays constructor-injected — only scoped dependencies need to move to `scopedServices` inside `VerifyAsync`.

**Warn or fail depending on a branch, from one resolution:**

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
                "The distributed-cache-backed token stores require an IDistributedCache " +
                "registration. Call AddDistributedMemoryCache() or register a distributed " +
                "cache implementation.");
        }
        else if (cache is not MemoryDistributedCache)
        {
            context.AddWarning(
                "stores.idistributedcache.non_atomic",
                "A distributed cache other than MemoryDistributedCache is registered. Review " +
                "the atomicity trade-offs of the distributed-cache-backed token stores before " +
                "relying on this in production.");
        }
        // MemoryDistributedCache: single-node dev/test, silent.

        return ValueTask.CompletedTask;
    }
}
```

One resolution, three outcomes, one method — this is the case that rules out separate interfaces for validation, warning, and side-effecting checks.

**Per-instance captured state, registered more than once:**

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
                "In-memory store '{StoreName}' is active. Tokens will be lost on restart.",
                storeName);
        }
        else if (!allowOutsideDevelopment)
        {
            context.AddFailure(
                "stores.inmemory.non_development",
                "In-memory stores are not permitted outside a Development environment.");
        }
        else
        {
            context.AddWarning(
                "stores.inmemory.non_development_override",
                "In-memory store '{StoreName}' is active outside Development because " +
                "allowOutsideDevelopment was set to true.",
                LogLevel.Critical,
                storeName);
        }

        return ValueTask.CompletedTask;
    }
}
```

Register it by factory, once per store, each capturing its own state:

```csharp
services.AddSingleton<IStartupVerifier>(sp => new InMemoryStoreVerifier(
    sp.GetRequiredService<IHostEnvironment>(),
    "AuthorizationCodeStore",
    allowOutsideDevelopment));
```

Two registrations of the *same implementation type* with different captured state both need to run — use `AddSingleton`, not `TryAddEnumerable`, which would deduplicate them away.

**Side-effecting activation:**

```csharp
internal sealed class ClientRepositoryActivationVerifier : IStartupVerifier
{
    public string Name => "ClientRepositoryActivation";

    public ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        // Resolving triggers construction-time validation: duplicate detection, per-client
        // checks, secret hashing. Any exception flows out to the runner and aborts startup;
        // nothing is caught here.
        var repository = scopedServices.GetRequiredService<IClientRepository>();

        var inMemoryOptions = scopedServices.GetService<InMemoryClientRegistrationOptions>();
        if (inMemoryOptions is not null && repository is not InMemoryClientRepository)
        {
            context.AddWarning(
                "clients.inmemory_shadowed",
                "AddInMemoryClients was called but the resolved IClientRepository is " +
                "{RepositoryType}, not InMemoryClientRepository. The configured in-memory " +
                "clients are unreachable.",
                repository.GetType().FullName);
        }

        return ValueTask.CompletedTask;
    }
}
```

Being side-effecting does not disqualify a check from being an `IStartupVerifier` — the per-verifier scope is precisely what makes forcing construction safe here, and letting an unexpected exception propagate rather than catching it is the correct behaviour.

## Related pages

- [Analyzer rules](analyzer-rules.md) — including `ZEEKAYDA0002`, which governs the `messageTemplate` argument to `AddWarning`
- [Token stores](token-stores.md) — the store-presence and distributed-cache startup checks referenced above
- [AuthorizationServerOptions reference](configuration.md) — options validated earlier, via `IValidateOptions<T>`
