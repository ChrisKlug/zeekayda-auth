using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// Verifies at application startup that an <see cref="IClientRepository"/> has been registered in
/// the dependency injection container.
/// </summary>
/// <remarks>
/// Asks <see cref="IServiceProviderIsService"/> rather than resolving the repository, because
/// resolving it constructs the caller's repository. A container that does not provide
/// <see cref="IServiceProviderIsService"/> (a third party replacing the default provider) skips the
/// check rather than failing with a confusing resolution error, as the other presence checks do.
/// </remarks>
internal sealed class ClientRepositoryPresenceValidator : IStartupVerifier
{
    /// <inheritdoc/>
    public string Name => "ClientRepositoryPresence";

    /// <inheritdoc/>
    public ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        var isService = scopedServices.GetService<IServiceProviderIsService>();
        if (isService is null)
            return ValueTask.CompletedTask;

        if (!isService.IsService(typeof(IClientRepository)))
            context.AddFailure(
                "client.repository.missing",
                "No IClientRepository has been registered. " +
                "Call builder.AddInMemoryClients(...) or register a custom IClientRepository implementation.");

        return ValueTask.CompletedTask;
    }
}
