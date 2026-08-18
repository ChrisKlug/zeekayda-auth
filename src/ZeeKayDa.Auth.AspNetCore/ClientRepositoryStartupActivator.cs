using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Forces the registered <see cref="IClientRepository"/> to be resolved during host startup.
/// </summary>
/// <remarks>
/// <see cref="InMemoryClientRepository"/> performs duplicate detection, per-client validation, and
/// secret hashing in its constructor; since it's a singleton, nothing else forces construction
/// before the first request needing it. Nothing here catches exceptions thrown while resolving
/// <see cref="IClientRepository"/>; when none is registered at all, the friendlier
/// <c>ClientRepositoryPresenceValidator</c> options-validation message aborts startup before this
/// verifier ever runs, otherwise the exception propagates unhandled from this method.
/// </remarks>
internal sealed class ClientRepositoryStartupActivator : IStartupVerifier
{
    /// <inheritdoc/>
    public string Name => "ClientRepositoryActivation";

    /// <inheritdoc/>
    public ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        // Resolving triggers construction-time validation: duplicate detection, per-client checks,
        // secret hashing. Any exception flows out to the runner and aborts startup; nothing is
        // caught here.
        var repository = scopedServices.GetRequiredService<IClientRepository>();

        // Warn if a custom IClientRepository has shadowed AddInMemoryClients' registration.
        var inMemoryOptions = scopedServices.GetService<InMemoryClientRegistrationOptions>();
        if (inMemoryOptions is not null && repository is not InMemoryClientRepository)
        {
            context.AddWarning(
                "clients.inmemory_shadowed",
                "AddInMemoryClients was called but the resolved IClientRepository is " +
                "{RepositoryType}, not InMemoryClientRepository. The configured in-memory clients " +
                "are unreachable. Register a custom IClientRepository before calling " +
                "AddInMemoryClients, or remove AddInMemoryClients entirely.",
                repository.GetType().FullName);
        }

        return ValueTask.CompletedTask;
    }
}
