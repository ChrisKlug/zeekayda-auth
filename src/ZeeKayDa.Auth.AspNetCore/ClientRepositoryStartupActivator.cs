using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Forces the registered <see cref="IClientRepository"/> to be resolved during host startup.
/// </summary>
/// <remarks>
/// <see cref="InMemoryClientRepository"/> performs duplicate detection, per-client validation, and
/// secret hashing in its constructor; since it's a singleton, nothing else forces construction
/// before the first request needing it. The repository is resolved from a short-lived scope in
/// <see cref="StartAsync"/> rather than constructor-injected: this lets the friendlier
/// <c>ClientRepositoryPresenceValidator</c> message surface first when none is registered, and
/// avoids capturing a scoped repository implementation as a root-scope singleton.
/// </remarks>
internal sealed class ClientRepositoryStartupActivator : IHostedService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ISanitizingLogger<ClientRepositoryStartupActivator> _logger;

    public ClientRepositoryStartupActivator(
        IServiceScopeFactory scopeFactory,
        ISanitizingLogger<ClientRepositoryStartupActivator> logger)
    {
        ArgumentNullException.ThrowIfNull(scopeFactory);
        ArgumentNullException.ThrowIfNull(logger);
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    /// <inheritdoc/>
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await using var scope = _scopeFactory.CreateAsyncScope();

        // Any ZeeKayDaConfigurationException from construction-time validation aborts startup
        // before Kestrel accepts connections.
        var repository = scope.ServiceProvider.GetRequiredService<IClientRepository>();

        // Warn if a custom IClientRepository has shadowed AddInMemoryClients' registration.
        var inMemoryOptions = scope.ServiceProvider.GetService<InMemoryClientRegistrationOptions>();
        if (inMemoryOptions is not null && repository is not InMemoryClientRepository)
        {
            _logger.LogWarning(
                "AddInMemoryClients was called but the resolved IClientRepository is {RepositoryType}, " +
                "not InMemoryClientRepository. The configured in-memory clients are unreachable. " +
                "Register a custom IClientRepository before calling AddInMemoryClients, or remove AddInMemoryClients entirely.",
                repository.GetType().FullName);
        }
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
