using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Tokens;

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
internal sealed class ClientRepositoryStartupActivator : IStartupActivator
{
    /// <inheritdoc/>
    public string Name => "ClientRepositoryActivation";

    /// <inheritdoc/>
    public async ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        // Client registrations are validated against the algorithms the server advertises, which do
        // not exist until the signing key ring has read its source. Asking for that here, rather
        // than assuming this runs after the ring's own activator, is what keeps the check correct
        // whatever order the activator phase happens to run in. EnsureInitializedAsync is
        // idempotent, so whichever activator asks first does the work and the other observes it.
        await EnsureSigningKeysReadAsync(scopedServices, cancellationToken).ConfigureAwait(false);

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

    }

    /// <summary>
    /// Initializes the signing key ring if one is registered, swallowing a configuration failure.
    /// </summary>
    /// <remarks>
    /// The ring's own activator reports that failure — recording it here as well would put the same
    /// code in the aggregate twice for one broken configuration. All this cares about is whether the
    /// advertised algorithms exist by the time client registrations are validated; if they cannot,
    /// the validator logs that it could not run the subset check and the startup still fails on the
    /// ring's own report.
    /// </remarks>
    private static async ValueTask EnsureSigningKeysReadAsync(
        IServiceProvider scopedServices, CancellationToken cancellationToken)
    {
        if (scopedServices.GetService<ISigningKeyRing>() is not { } ring)
            return;

        try
        {
            await ring.EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (ZeeKayDaConfigurationException)
        {
        }
    }
}
