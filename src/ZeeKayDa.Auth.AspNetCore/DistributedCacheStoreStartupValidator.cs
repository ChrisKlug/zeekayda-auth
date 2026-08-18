using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Verifies that <see cref="IDistributedCache"/> is registered at application startup and emits
/// a warning when a non-<see cref="MemoryDistributedCache"/> implementation is detected.
/// </summary>
/// <remarks>
/// An absent <see cref="IDistributedCache"/> is always a configuration error and fails startup.
/// <see cref="MemoryDistributedCache"/> (the dev/test default) is expected and emits no warning;
/// any other implementation is assumed to be a shared distributed cache, and a warning reminds
/// operators that the built-in stores are non-atomic and must be replaced before production.
/// </remarks>
internal sealed class DistributedCacheStoreStartupValidator : IStartupVerifier
{
    internal const string WarningMessage =
        "ZeeKayDa.Auth: IDistributedCache resolves to a non-MemoryDistributedCache implementation. " +
        "The distributed-cache-backed token stores are non-atomic; multi-instance deployments are " +
        "exposed to TOCTOU double-redemption/double-consumption. Replace these stores with an " +
        "atomic implementation before going to production. See ADR 0008 §8.";

    /// <inheritdoc/>
    public string Name => "DistributedCacheStore";

    /// <inheritdoc/>
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
                "IDistributedCache is not registered. Call services.AddDistributedMemoryCache() " +
                "(dev/test) or register a production-grade distributed cache before adding " +
                "distributed-cache-backed stores.");
        }
        else if (cache is not MemoryDistributedCache)
        {
            context.AddWarning("stores.idistributedcache.non_atomic", WarningMessage);
        }

        return ValueTask.CompletedTask;
    }
}
