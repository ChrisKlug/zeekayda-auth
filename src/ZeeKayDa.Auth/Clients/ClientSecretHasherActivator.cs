using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Builds <see cref="ClientSecretHasherRegistry"/> at startup, so every registered hasher's timing
/// decoy is made, and a hasher that cannot make one fails the host, before the first request.
/// </summary>
/// <remarks>
/// The registry is a lazy singleton, and only the in-memory client store needs it while it is
/// built; a host with its own <see cref="IClientRepository"/> would otherwise build it on its first
/// token request. An activator because it runs every registered hasher's <c>Create</c>.
/// <para>
/// The registry is resolved in <see cref="VerifyAsync"/>, not injected: building it is the check,
/// and a hasher that throws from the constructor would fail the whole phase's resolution rather
/// than this one check.
/// </para>
/// </remarks>
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
