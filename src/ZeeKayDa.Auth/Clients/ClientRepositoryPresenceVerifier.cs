using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Clients;
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
internal sealed class ClientRepositoryPresenceVerifier : IStartupVerifier
{
    /// <inheritdoc/>
    public string Name => "ClientRepositoryPresence";

    /// <inheritdoc/>
    public Task VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        if (!IsClientRepositoryRegistered(scopedServices))
            context.AddFailure(
                "client.repository.missing",
                "No IClientRepository has been registered. " +
                "Call builder.AddInMemoryClients(...) or register a custom IClientRepository implementation.");

        return Task.CompletedTask;
    }

    private static bool IsClientRepositoryRegistered(IServiceProvider scopedServices)
    {
        if (scopedServices.GetService<IServiceProviderIsService>() is { } isService)
            return isService.IsService(typeof(IClientRepository));

        try
        {
            return scopedServices.GetService<IClientRepository>() is not null;
        }
        catch (ZeeKayDaConfigurationException)
        {
            // Registered and broken, a different answer from "absent": ClientRepositoryActivator
            // reports that failure in the next phase.
            return true;
        }
    }
}
