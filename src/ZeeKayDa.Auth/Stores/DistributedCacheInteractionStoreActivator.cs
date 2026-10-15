using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Configuration;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// Checks at startup that the distributed-cache interaction store has a cache, and that outside Development
/// it is not the per-process <see cref="MemoryDistributedCache"/>, which shares nothing between instances.
/// </summary>
internal sealed class DistributedCacheInteractionStoreActivator(
    IHostEnvironment environment,
    bool allowMemoryCacheOutsideDevelopment,
    IDistributedCache? cache) : IStartupActivator
{
    internal const string MissingCacheMessage =
        "IDistributedCache is not registered. Call services.AddDistributedMemoryCache() " +
        "(development) or register a shared distributed cache before adding the " +
        "distributed-cache interaction store.";

    internal const string PerProcessCacheActiveMessage =
        "ZeeKayDa.Auth: the distributed-cache interaction store is running on the per-process " +
        "MemoryDistributedCache. Despite its name, that cache is shared with nothing: an " +
        "authorization request started on one instance cannot be completed by another. Register a " +
        "shared IDistributedCache before deploying to more than one instance.";

    internal const string PerProcessCacheOverrideWarningMessage =
        "ZeeKayDa.Auth: the distributed-cache interaction store is running on the per-process " +
        "MemoryDistributedCache outside a Development environment. allowMemoryCacheOutsideDevelopment " +
        "has been set to true — ensure this is intentional (e.g. an integration test host). An " +
        "authorization request started on one instance cannot be completed by another.";

    /// <inheritdoc/>
    public string Name => "DistributedCacheInteractionStore";

    /// <inheritdoc/>
    public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
        if (cache is null)
        {
            context.AddFailure("stores.idistributedcache.missing", MissingCacheMessage);
            return Task.CompletedTask;
        }

        if (cache is not MemoryDistributedCache)
            return Task.CompletedTask;

        switch (EnvironmentGate.Evaluate(environment, allowMemoryCacheOutsideDevelopment))
        {
            case EnvironmentGate.Verdict.ExpectedInDevelopment:
                context.AddWarning(
                    "stores.interaction.per_process_cache_active",
                    PerProcessCacheActiveMessage,
                    LogLevel.Information);
                break;

            case EnvironmentGate.Verdict.AllowedByOptOut:
                context.AddWarning(
                    "stores.interaction.per_process_cache_override",
                    PerProcessCacheOverrideWarningMessage,
                    LogLevel.Critical);
                break;

            default:
                context.AddFailure(
                    "stores.interaction.per_process_cache",
                    "The distributed-cache interaction store resolves IDistributedCache to MemoryDistributedCache " +
                    "outside a Development environment. Despite its name, that cache is shared with nothing: an " +
                    "authorization request started on one instance cannot be completed by another. Register a " +
                    "shared IDistributedCache (Redis, SQL Server, ...) or pass allowMemoryCacheOutsideDevelopment: " +
                    "true if this host is an intentional non-Development test host.");
                break;
        }

        return Task.CompletedTask;
    }
}
