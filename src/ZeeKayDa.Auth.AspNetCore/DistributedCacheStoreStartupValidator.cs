using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Verifies that <see cref="IDistributedCache"/> is registered at application startup and emits
/// a warning when a non-<see cref="MemoryDistributedCache"/> implementation is detected.
/// </summary>
/// <remarks>
/// <para>
/// When no <see cref="IDistributedCache"/> is registered at all, the framework fails closed by
/// throwing a <see cref="ZeeKayDaConfigurationException"/> — an absent cache is always a
/// configuration error.
/// </para>
/// <para>
/// When the resolved implementation is <see cref="MemoryDistributedCache"/> (the default
/// in-process cache added by <c>AddDistributedMemoryCache()</c>), no warning is emitted
/// because a single-node dev/test setup is the expected use-case for that type.
/// </para>
/// <para>
/// Any other implementation is assumed to be a shared distributed cache. In that case a warning
/// is emitted reminding operators that the built-in stores are non-atomic and must be replaced
/// with an atomic implementation before going to production.
/// </para>
/// </remarks>
internal sealed class DistributedCacheStoreStartupValidator : IHostedService
{
    internal const string WarningMessage =
        "ZeeKayDa.Auth: IDistributedCache resolves to a non-MemoryDistributedCache implementation. " +
        "The distributed-cache-backed token stores are non-atomic; multi-instance deployments are " +
        "exposed to TOCTOU double-redemption/double-consumption. Replace these stores with an " +
        "atomic implementation before going to production. See ADR 0008 §8.";

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ISanitizingLogger<DistributedCacheStoreStartupValidator> _logger;

    public DistributedCacheStoreStartupValidator(
        IServiceScopeFactory scopeFactory,
        ISanitizingLogger<DistributedCacheStoreStartupValidator> logger)
    {
        ArgumentNullException.ThrowIfNull(scopeFactory);
        ArgumentNullException.ThrowIfNull(logger);

        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    /// <inheritdoc/>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        using var scope = _scopeFactory.CreateScope();
        var cache = scope.ServiceProvider.GetService<IDistributedCache>();

        if (cache is null)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "stores.idistributedcache.missing",
                    "IDistributedCache is not registered. Call services.AddDistributedMemoryCache() " +
                    "(dev/test) or register a production-grade distributed cache before adding " +
                    "distributed-cache-backed stores."));
        }

        if (cache is not MemoryDistributedCache)
        {
            _logger.Log(LogLevel.Warning, WarningMessage);
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
