using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Verifies at startup that a distributed-cache-backed token store has an
/// <see cref="IDistributedCache"/> to run on, and that outside Development it is not the
/// per-process <see cref="MemoryDistributedCache"/>.
/// </summary>
/// <remarks>
/// <para>
/// Despite its name, <see cref="MemoryDistributedCache"/> is shared with nothing. Behind a load
/// balancer an authorization code issued by one instance cannot be redeemed at another, and a
/// refresh token rotated on one is unknown to the rest — single-use enforcement and reuse
/// detection hold only per process. In Development, where the per-process cache is the expected
/// choice, that is recorded rather than warned about. Which of the three answers the host gets is
/// <see cref="EnvironmentGate"/>'s decision, shared with every other development-only resource;
/// what lives here is the wording for this one.
/// </para>
/// <para>
/// One instance is registered per store registration, each capturing its own <c>storeName</c> and
/// <c>allowMemoryCacheOutsideDevelopment</c>, and they are added with plain
/// <c>AddSingleton&lt;IStartupActivator&gt;</c> rather than <c>TryAddEnumerable</c> — which
/// deduplicates by implementation type, so a host registering the code store and the refresh token
/// store with different opt-out values would have the second silently dropped.
/// </para>
/// <para>
/// The non-atomicity warning is a separate concern and is raised whatever the environment: a real
/// shared cache still cannot make check-and-set atomic, so a multi-instance deployment is exposed
/// to double redemption regardless of which cache is behind it.
/// </para>
/// </remarks>
internal sealed class DistributedCacheStoreStartupValidator : IStartupActivator
{
    /// <summary>The store name passed for the authorization code store registration.</summary>
    internal const string AuthorizationCodeStoreName = "authorization code store";

    /// <summary>The store name passed for the refresh token store registration.</summary>
    internal const string RefreshTokenStoreName = "refresh token store";

    internal const string WarningMessage =
        "ZeeKayDa.Auth: IDistributedCache resolves to a non-MemoryDistributedCache implementation. " +
        "The distributed-cache-backed token stores are non-atomic; multi-instance deployments are " +
        "exposed to TOCTOU double-redemption/double-consumption. Replace these stores with an " +
        "atomic implementation before going to production. See docs/reference/token-stores.md for guidance.";

    internal const string MissingCacheMessage =
        "IDistributedCache is not registered. Call services.AddDistributedMemoryCache() " +
        "(dev/test) or register a production-grade distributed cache before adding " +
        "distributed-cache-backed stores.";

    /// <summary>Named-placeholder template for the Development message.</summary>
    internal const string PerProcessCacheActiveMessageFormat =
        "ZeeKayDa.Auth: the distributed-cache {StoreName} is running on the per-process " +
        "MemoryDistributedCache. Despite its name, that cache is shared with nothing: an " +
        "authorization code issued by one instance cannot be redeemed at another, and single-use " +
        "enforcement and reuse detection hold only within one process. Register a shared " +
        "IDistributedCache before deploying to more than one instance.";

    /// <summary>Named-placeholder template for the non-Development override warning.</summary>
    internal const string PerProcessCacheOverrideWarningMessageFormat =
        "ZeeKayDa.Auth: the distributed-cache {StoreName} is running on the per-process " +
        "MemoryDistributedCache outside a Development environment. " +
        "allowMemoryCacheOutsideDevelopment has been set to true for this registration — ensure " +
        "this is intentional (e.g. an integration test host). Single-use enforcement and reuse " +
        "detection do not span instances.";

    private readonly IHostEnvironment _environment;
    private readonly string _storeName;
    private readonly bool _allowMemoryCacheOutsideDevelopment;

    public DistributedCacheStoreStartupValidator(
        IHostEnvironment environment,
        string storeName,
        bool allowMemoryCacheOutsideDevelopment)
    {
        ArgumentNullException.ThrowIfNull(environment);
        ArgumentException.ThrowIfNullOrWhiteSpace(storeName);

        _environment = environment;
        _storeName = storeName;
        _allowMemoryCacheOutsideDevelopment = allowMemoryCacheOutsideDevelopment;
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Every instance shares this category, so the instance <see cref="Name"/> (e.g.
    /// <c>DistributedCacheStore(refresh token store)</c>) is what lets an operator tell two
    /// registrations apart.
    /// </remarks>
    public string Name => $"DistributedCacheStore({_storeName})";

    /// <inheritdoc/>
    public ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        var cache = scopedServices.GetService<IDistributedCache>();

        if (cache is null)
        {
            context.AddFailure("stores.idistributedcache.missing", MissingCacheMessage);
            return ValueTask.CompletedTask;
        }

        if (cache is not MemoryDistributedCache)
        {
            context.AddWarning("stores.idistributedcache.non_atomic", WarningMessage);
            return ValueTask.CompletedTask;
        }

        switch (EnvironmentGate.Evaluate(_environment, _allowMemoryCacheOutsideDevelopment))
        {
            case EnvironmentGate.Verdict.ExpectedInDevelopment:
                context.AddWarning(
                    "stores.token.per_process_cache_active",
                    PerProcessCacheActiveMessageFormat,
                    LogLevel.Information,
                    _storeName);
                break;

            case EnvironmentGate.Verdict.AllowedByOptOut:
                context.AddWarning(
                    "stores.token.per_process_cache_override",
                    PerProcessCacheOverrideWarningMessageFormat,
                    LogLevel.Critical,
                    _storeName);
                break;

            default:
                // Names its own store, for the reason InMemoryStoreVerifier does: the runner
                // collapses failures identical in code and message, so a message naming no store
                // would report one of two broken registrations and send the operator round the
                // restart cycle for the other.
                context.AddFailure(
                    "stores.token.per_process_cache",
                    $"The distributed-cache {_storeName} resolves IDistributedCache to MemoryDistributedCache " +
                    "outside a Development environment. Despite its name, that cache is shared with nothing: " +
                    "an authorization code issued by one instance cannot be redeemed at another, and " +
                    "single-use enforcement and reuse detection hold only within one process. Register a " +
                    "shared IDistributedCache (Redis, SQL Server, ...) or pass " +
                    "allowMemoryCacheOutsideDevelopment: true if this host is an intentional " +
                    "non-Development test host.");
                break;
        }

        return ValueTask.CompletedTask;
    }
}
