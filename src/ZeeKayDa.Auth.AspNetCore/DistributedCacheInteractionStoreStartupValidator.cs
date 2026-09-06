using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Verifies at startup that the distributed-cache interaction store has an
/// <see cref="IDistributedCache"/> to run on, and that outside Development it is not the
/// per-process <see cref="MemoryDistributedCache"/>.
/// </summary>
/// <remarks>
/// Despite its name, <see cref="MemoryDistributedCache"/> is shared with nothing. Behind a load
/// balancer an authorization request started on one instance cannot be completed by another, and
/// the failure looks like an intermittent bug in the host's login page. Startup is the only place
/// to catch it; the host opts out for an intentional non-Development test host, and is reminded
/// on every start.
/// </remarks>
internal sealed class DistributedCacheInteractionStoreStartupValidator : IStartupActivator
{
    internal const string PerProcessCacheOverrideWarningMessage =
        "ZeeKayDa.Auth: the distributed-cache interaction store is running on the per-process " +
        "MemoryDistributedCache outside a Development environment. allowMemoryCacheOutsideDevelopment " +
        "has been set to true — ensure this is intentional (e.g. an integration test host). An " +
        "authorization request started on one instance cannot be completed by another.";

    private readonly IHostEnvironment _environment;
    private readonly bool _allowMemoryCacheOutsideDevelopment;

    public DistributedCacheInteractionStoreStartupValidator(IHostEnvironment environment, bool allowMemoryCacheOutsideDevelopment)
    {
        ArgumentNullException.ThrowIfNull(environment);

        _environment = environment;
        _allowMemoryCacheOutsideDevelopment = allowMemoryCacheOutsideDevelopment;
    }

    /// <inheritdoc/>
    public string Name => "DistributedCacheInteractionStore";

    /// <inheritdoc/>
    public ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        var cache = scopedServices.GetService<IDistributedCache>();

        if (cache is null)
        {
            context.AddFailure("stores.idistributedcache.missing", DistributedCacheStoreStartupValidator.MissingCacheMessage);
            return ValueTask.CompletedTask;
        }

        if (!IsPerProcessCacheOutsideDevelopment(cache))
            return ValueTask.CompletedTask;

        if (_allowMemoryCacheOutsideDevelopment)
        {
            context.AddWarning(
                "stores.interaction.per_process_cache_override",
                PerProcessCacheOverrideWarningMessage,
                LogLevel.Critical);
            return ValueTask.CompletedTask;
        }

        context.AddFailure(
            "stores.interaction.per_process_cache",
            "The distributed-cache interaction store resolves IDistributedCache to MemoryDistributedCache " +
            "outside a Development environment. Despite its name, that cache is shared with nothing: an " +
            "authorization request started on one instance cannot be completed by another. Register a " +
            "shared IDistributedCache (Redis, SQL Server, ...) or pass allowMemoryCacheOutsideDevelopment: " +
            "true if this host is an intentional non-Development test host.");

        return ValueTask.CompletedTask;
    }

    private bool IsPerProcessCacheOutsideDevelopment(IDistributedCache cache) =>
        cache is MemoryDistributedCache && !_environment.IsDevelopment();
}
