using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Builds the hasher registry at startup, so every timing decoy is made, and a hasher that cannot make one
/// fails the host, before the first request.
/// </summary>
internal sealed class ClientSecretHasherActivator(IServiceProvider services) : IStartupActivator
{
    /// <inheritdoc/>
    public string Name => "ClientSecretHasherActivation";

    /// <inheritdoc/>
    public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
        services.GetRequiredService<ClientSecretHasherRegistry>();
        return Task.CompletedTask;
    }
}
