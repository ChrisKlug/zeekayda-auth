using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Forces the registered <see cref="IClientRepository"/> to be resolved during host startup.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="InMemoryClientRepository"/> performs duplicate detection, per-client validation, and
/// PBKDF2 secret hashing in its constructor. Because it is registered as a singleton, nothing
/// otherwise forces it to be constructed until the first request that needs it — which would turn
/// a configuration error into a first-request failure rather than a startup failure.
/// </para>
/// <para>
/// The repository is resolved inside <see cref="StartAsync"/> from a short-lived scope rather than
/// being constructor-injected. This avoids two problems. First, constructor injection of
/// <see cref="IClientRepository"/> means that, when none is registered, the host fails with a raw
/// DI "unable to resolve service" error instead of the friendly
/// <c>ClientRepositoryPresenceValidator</c> message. Resolving lazily here lets the options
/// <c>ValidateOnStart()</c> validator (an <c>IStartupValidator</c>, run before hosted services)
/// surface that friendly message first. Second, constructor injection would capture a scoped
/// repository implementation (e.g. an EF-backed one) as a root-scope singleton; a dedicated scope
/// resolves it correctly.
/// </para>
/// </remarks>
internal sealed class ClientRepositoryStartupActivator : IHostedService
{
    private readonly IServiceScopeFactory _scopeFactory;

    public ClientRepositoryStartupActivator(IServiceScopeFactory scopeFactory)
    {
        ArgumentNullException.ThrowIfNull(scopeFactory);
        _scopeFactory = scopeFactory;
    }

    /// <inheritdoc/>
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await using var scope = _scopeFactory.CreateAsyncScope();

        // Resolving triggers construction-time validation (duplicate detection, per-client checks,
        // secret hashing). Any ZeeKayDaConfigurationException propagates and aborts startup before
        // Kestrel accepts connections.
        _ = scope.ServiceProvider.GetRequiredService<IClientRepository>();
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
