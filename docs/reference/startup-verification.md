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
| `IStartupVerifier` | first (early) | resolves and calls only what the framework itself registered — options, `IServiceProviderIsService` |
| `IStartupActivator` | second (late) | resolves or calls anything the framework did **not** register — an `IClientRepository`, an `ISigningKeySource`, an `IDistributedCache` |

Both declare the same two members. **The activator phase does not run at all if any verifier reported a failure**, so an application whose issuer is misconfigured never opens a connection to a key vault before being told about the issuer.

The rule is about *whose code runs*, not about how slow you expect it to be: resolving a service counts, because a constructor is code. If your check touches a type the host registered, it is an activator, even when the implementation you have in mind does nothing expensive.

## `IStartupVerifier` and `IStartupActivator`

Every type on this page lives in the `ZeeKayDa.Auth.StartupVerification` namespace.

```csharp
public interface IStartupVerifier   // phase 1 — cheap
{
    string Name { get; }

    Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken);
}

public interface IStartupActivator  // phase 2 — does real work
{
    string Name { get; }

    Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken);
}
```

| Member | Contract |
|---|---|
| `Name` | A stable name used for log attribution and diagnostics only. It is **not** an ordering or priority hint — execution order within a phase is DI registration order, and nothing a check returns can influence it. |
| `VerifyAsync` | Runs the check. Report outcomes by calling `context.AddFailure(...)` and `context.AddWarning(...)` — never throw except for a genuinely unexpected failure (a DI resolution error, a third-party bug). |

Register an implementation as scoped, and constructor-inject what it needs — scoped services included. Any other lifetime fails startup with `startup.check_not_scoped`:

```csharp
builder.Services.AddScoped<IStartupVerifier, MyCustomVerifier>();      // cheap
builder.Services.AddScoped<IStartupActivator, MyRepositoryActivator>(); // does real work
```

The runner creates one `AsyncServiceScope` per phase and resolves every check in that phase from it, so **the checks in a phase share a scope**. A check that leaves a scoped dependency in a broken state (an EF `DbContext` after a failed save, say) can cause a misleading second failure in a later check of the same phase.

### Rules for implementing a verifier

- **Never log directly.** The runner logs every warning on your behalf, under a log category matching your own implementation type (see [How verifiers run](#how-verifiers-run)).
- **Keep the constructor cheap.** A constructor that throws fails the resolution of its whole phase, so the other checks in that phase do not run. The runner still reports it, but it can name only the phase, not your check.
- **Report through the context; don't throw for expected outcomes.** Call `context.AddFailure` for a configuration problem you detected. Only let an exception propagate for something genuinely unexpected — the runner treats a thrown `ZeeKayDaConfigurationException` as if its `AggregatedFailures` had already been added to the context, and wraps any other exception as an unexpected verifier failure (see [Unexpected exceptions](#unexpected-exceptions)).
- **Being side-effecting is fine — register it as an `IStartupActivator`.** A check that forces construction of a repository, or performs a real sign operation to prove a key is reachable, is a legitimate use of the phase's scope. Putting it in the activator phase is what stops it running for a host that is already known to be misconfigured.
- **Do not depend on running after another check.** Order within a phase is registration order and is not a guarantee. If your check needs another's work done first, ask for it — that is why `SigningKeyRing.EnsureInitializedAsync` is idempotent, so the check that validates client registrations against the advertised algorithms can call it rather than assume it runs second.

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

Startup verification runs inside the same hosted service's startup call:

1. **Every options type registered with `AddZeeKayDaOptions` is validated first.** No check runs against options that do not validate.
2. **Your `IStartupVerifier` instances run next.** Every registered verifier runs — a failure in one does not skip the rest. The phase collects every failure and warning, logs the warnings, then throws every failure in a single `ZeeKayDaConfigurationException`.
3. **Your `IStartupActivator` instances run last**, and **only if the verifier phase produced no failure at all** — they are not even constructed otherwise. The phase aggregates the same way.

Three consequences of this shape matter to you as an implementer:

- **You see every problem in a phase in one restart**, not one problem per restart. A host with two invalid client registrations gets both failures in one `AggregatedFailures` list. The guarantee is per phase, not across phases: a cheap failure and an activator failure surface in separate restarts, because the activator never ran. Within a phase, two checks reporting a failure with the **same code and the same message** are collapsed into one — they describe one broken configuration, not two problems — so make your failure message name its subject if your check can be registered more than once.
- **Warnings are logged under your check's own category, through the framework's sanitizing logger**, so by-key redaction applies to their arguments exactly as at any framework log call site.
- **An activator sees a configuration that already passed every cheap check.** If your check is expensive, or reaches out over a network, that is where it belongs.

## Unexpected exceptions

If `VerifyAsync` — or a check's constructor — throws instead of reporting through the context, the runner distinguishes two cases:

- **A thrown `ZeeKayDaConfigurationException`** is absorbed verbatim — its `AggregatedFailures` are added to the running failure list, preserving their original stable codes. Verbatim means verbatim: the runner does not inspect, reword, or redact your failure messages, so each one reaches the operator exactly as you wrote it. That is why the warning below binds you and not only the framework.
- **Any other exception** is recorded as a failure and the phase continues:

  ```csharp
  context.AddFailure(
      "startup.verifier_failed",
      $"Check '{name}' threw {ex.GetType().FullName}. See the inner exception for the root cause.");
  ```

  A constructor that throws is reported the same way, naming the phase (`Constructing the startup activators threw …`) rather than the check. The exception itself travels as the phase aggregate's `InnerException` — an `AggregateException` when more than one check threw — and so does the inner exception of an absorbed `ZeeKayDaConfigurationException`. One check with a bug therefore does not hide the genuine, fixable configuration errors reported beside it.

> ⚠️ **Warning:** The wrapper names the exception's **type**, never `ex.Message`. An arbitrary underlying exception's message is untrusted text — a database connection string, a cloud SDK exception carrying a SAS-bearing URI, anything a lower layer decided to put in `Message`. `ZeeKayDaConfigurationFailure.Message` is a plain string on public API surface that the redaction layer cannot act on, so it must never carry raw exception text. The original exception is preserved as `InnerException`, where it stays available to an operator through their logging or crash-dump pipeline, redacted the same way any other logged exception is if it is ever logged through the framework's sanitizing logger. Apply the same rule in your own verifiers: if you must describe a caught exception in a failure or warning, name its type, not its message.

Startup still aborts either way — there is no silent swallow — but the operator gets an attributed, legible failure naming the offending check, alongside every other failure in that phase, rather than a bare stack trace from inside the host's startup pipeline.

## Worked examples

The following patterns cover every shape a real verifier takes.

**Validate and fail:**

```csharp
internal sealed class ScopePresenceActivator(IScopeRepository repository) : IStartupActivator
{
    public string Name => "ScopePresence";

    public async Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
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

**Warn only:** a host-authored check, to keep the example about the API rather than about any
framework check whose own behaviour may change.

```csharp
internal sealed class SeedDataVerifier(IOptions<MyHostOptions> options) : IStartupVerifier
{
    public string Name => "SeedData";

    public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
        if (options.Value.SeedDemoUsers)
        {
            context.AddWarning(
                "myhost.seed_users_enabled",
                "Demo users are seeded for '{Tenant}'. They have well-known passwords and must " +
                "never be enabled outside local development.",
                options.Value.Tenant);
        }

        return Task.CompletedTask;
    }
}
```

**Warn or fail depending on a branch, from one resolution:**

```csharp
internal sealed class SharedCacheActivator(IDistributedCache? cache = null) : IStartupActivator
{
    public string Name => "SharedCache";

    public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
        if (cache is null)
        {
            context.AddFailure(
                "myapp.cache.missing",
                "This host needs an IDistributedCache registration. Call " +
                "AddDistributedMemoryCache() or register a shared cache.");
        }
        else if (cache is MemoryDistributedCache)
        {
            context.AddWarning(
                "myapp.cache.per_process",
                "IDistributedCache is the per-process MemoryDistributedCache. It is shared " +
                "with nothing, so instances do not see each other's entries.");
        }

        return Task.CompletedTask;
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

    public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
        if (environment.IsDevelopment())
        {
            context.AddWarning(
                "stores.inmemory.active",
                "In-memory store '{StoreName}' is active. Tokens will be lost on restart.",
                LogLevel.Information,
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

        return Task.CompletedTask;
    }
}
```

Register it by factory, once per store, each capturing its own state:

```csharp
services.AddScoped<IStartupVerifier>(sp => new InMemoryStoreVerifier(
    sp.GetRequiredService<IHostEnvironment>(),
    "AuthorizationCodeStore",
    allowOutsideDevelopment));
```

Two registrations of the *same implementation type* with different captured state both need to run — use `AddScoped`, not `TryAddEnumerable`, which would deduplicate them away.

**Side-effecting activation:**

```csharp
internal sealed class ClientRepositoryActivator(
    IClientRepository repository,
    InMemoryClientRegistrationOptions? inMemoryOptions = null) : IStartupActivator
{
    public string Name => "ClientRepositoryActivation";

    public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
        // Injecting the repository already forced its construction-time validation: duplicate
        // detection, per-client checks, secret hashing.
        if (inMemoryOptions is not null && repository is not InMemoryClientRepository)
        {
            context.AddWarning(
                "clients.inmemory_shadowed",
                "AddInMemoryClients was called but the resolved IClientRepository is " +
                "{RepositoryType}, not InMemoryClientRepository. The configured in-memory " +
                "clients are unreachable.",
                repository.GetType().FullName);
        }

        return Task.CompletedTask;
    }
}
```

It is an `IStartupActivator` because it resolves `IClientRepository`, which the host registers — the framework's own `ClientRepositoryActivator` is one for the same reason. Letting an unexpected exception propagate rather than catching it is the correct behaviour. (The framework's own version resolves the repository inside `VerifyAsync` from an injected `IServiceProvider` instead, because it must first wait for the signing key ring to read its keys — an awaited step a constructor cannot take.)

## Related pages

- [Analyzer rules](analyzer-rules.md) — including `ZEEKAYDA0002`, which governs the `messageTemplate` argument to `AddWarning`
- [Token stores](token-stores.md) — the store-presence and distributed-cache interaction-store startup checks
- [AuthorizationServerOptions reference](configuration.md) — options validated earlier, via `IValidateOptions<T>`
