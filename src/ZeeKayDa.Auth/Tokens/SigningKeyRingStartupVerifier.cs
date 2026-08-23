using Microsoft.Extensions.DependencyInjection;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Framework-owned <see cref="IStartupVerifier"/> that initializes whatever <see cref="ISigningKeyRing"/>
/// is registered, once per host startup — so a misconfigured signing key fails the host rather than
/// the first request.
/// </summary>
/// <remarks>
/// A silent no-op when no <see cref="ISigningKeyRing"/> is registered at all: <c>AddZeeKayDaSigningKeys()</c>
/// (the health check registration) deliberately never registers a ring, so a host that adds only the
/// health check must still start.
/// </remarks>
internal sealed class SigningKeyRingStartupVerifier : IStartupVerifier
{
    /// <inheritdoc/>
    public string Name => "SigningKeyRing";

    /// <inheritdoc/>
    /// <remarks>
    /// Delegates to the internal <c>ISigningKeyRing.InitializeAsync</c> and lets any thrown
    /// <see cref="ZeeKayDaConfigurationException"/> propagate — the runner treats it as if its
    /// <see cref="ZeeKayDaConfigurationException.AggregatedFailures"/> had already been added to
    /// <paramref name="context"/>.
    /// </remarks>
    public async ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        var ring = scopedServices.GetService<ISigningKeyRing>();
        if (ring is null)
            return;

        await ring.InitializeAsync(cancellationToken).ConfigureAwait(false);
    }
}
