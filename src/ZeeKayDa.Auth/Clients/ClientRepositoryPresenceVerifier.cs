using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Verifies at application startup that an <see cref="IClientRepository"/> has been registered in
/// the dependency injection container.
/// </summary>
/// <remarks>
/// Asks <see cref="IServiceProviderIsService"/> rather than resolving the repository, because
/// resolving it constructs the caller's repository. A container that does not provide
/// <see cref="IServiceProviderIsService"/> (a third party replacing the default provider) falls back
/// to resolving, as <c>SigningKeyRingPresenceVerifier</c> does, so the check reports rather than
/// skipping itself.
/// </remarks>
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
            // Registered and broken, a different answer from "absent": ClientRepositoryActivator
            // reports that failure in the next phase.
            return true;
        }
    }
}
