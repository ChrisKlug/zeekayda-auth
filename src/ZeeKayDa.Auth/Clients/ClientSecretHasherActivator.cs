using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Builds <see cref="CompositeClientSecretHasher"/> at startup, so every registered hasher's timing
/// decoy is made, and a hasher that cannot make one fails the host, before the first request.
/// </summary>
/// <remarks>
/// The composite is a lazy singleton, and only the in-memory client store needs it while it is
/// built; a host with its own <see cref="IClientRepository"/> would otherwise build it on its first
/// token request. An activator because it runs every registered hasher's <c>Create</c>.
/// </remarks>
internal sealed class ClientSecretHasherActivator : IStartupActivator
{
    /// <inheritdoc/>
    public string Name => "ClientSecretHasherActivation";

    /// <inheritdoc/>
    public Task VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        scopedServices.GetRequiredService<CompositeClientSecretHasher>();
        return Task.CompletedTask;
    }
}
