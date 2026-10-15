using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Fails startup when no <see cref="IClientRepository"/> is registered, asking
/// <see cref="IServiceProviderIsService"/> rather than building it where the container offers that.
/// </summary>
internal sealed class ClientRepositoryPresenceVerifier(IServiceProvider services) : IStartupVerifier
{
    /// <inheritdoc/>
    public string Name => "ClientRepositoryPresence";

    /// <inheritdoc/>
    public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
        if (!IsClientRepositoryRegistered())
            context.AddFailure(
                "client.repository.missing",
                "No IClientRepository has been registered. " +
                "Call builder.AddInMemoryClients(...) or register a custom IClientRepository implementation.");

        return Task.CompletedTask;
    }

    private bool IsClientRepositoryRegistered()
    {
        if (services.GetService<IServiceProviderIsService>() is { } isService)
            return isService.IsService(typeof(IClientRepository));

        try
        {
            return services.GetService<IClientRepository>() is not null;
        }
        catch (ZeeKayDaConfigurationException)
        {
            // Registered and broken: ClientRepositoryActivator reports that.
            return true;
        }
    }
}
