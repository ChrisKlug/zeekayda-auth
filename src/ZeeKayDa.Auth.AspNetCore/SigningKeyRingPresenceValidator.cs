using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Verifies at application startup that a signing key source — and therefore an
/// <see cref="ISigningKeyRing"/> — has been registered.
/// </summary>
/// <remarks>
/// An authorization server cannot issue an ID token without one, and cannot publish
/// <c>id_token_signing_alg_values_supported</c>, which OpenID Connect Discovery 1.0 §3 requires:
/// the advertised algorithms are derived from the ring's key set. Failing here is what keeps that
/// dependency from surfacing as a dependency-injection error on the first discovery request.
/// <para>
/// Asks <see cref="IServiceProviderIsService"/> rather than resolving the ring, because resolving it
/// constructs the caller's signing key source — real work, and this is a verifier, running in the
/// phase that exists so a host with no signing source learns about it before any work is done. The
/// ring's own activator runs in the <em>next</em> phase, so nothing has initialized the ring by the
/// time this runs.
/// </para>
/// <para>
/// A container that does not provide <see cref="IServiceProviderIsService"/> — a third party
/// replacing the default provider — falls back to resolving, so the check reports rather than
/// skipping itself; those hosts pay the construction here. On that path a ring factory that throws
/// answers "registered, and broken", which is not what this check asks about: the ring's activator
/// reports that failure in the next phase, and Microsoft.Extensions.DependencyInjection does not
/// cache a failed factory invocation, so re-throwing it here would report it twice.
/// </para>
/// </remarks>
internal sealed class SigningKeyRingPresenceValidator : IStartupVerifier
{
    /// <inheritdoc/>
    public string Name => "SigningKeyRingPresence";

    /// <inheritdoc/>
    public ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        if (!IsSigningKeyRingRegistered(scopedServices))
            context.AddFailure(
                "signing.key_ring.missing",
                "No signing key source has been registered, so no token can be signed and " +
                "id_token_signing_alg_values_supported cannot be published. Call " +
                "builder.AddInMemoryDevelopmentJwtSigningKeys() or " +
                "builder.AddPersistedDevelopmentJwtSigningKeys() for local development, one of the " +
                "provider packages' registrations (builder.AddPemFileSigning(), " +
                "builder.AddPfxFileSigning(), builder.AddAzureKeyVaultRemoteSigning(), " +
                "builder.AddAzureKeyVaultCachedSigning(), builder.AddWindowsCertificateStoreSigning()), " +
                "or services.AddZeeKayDaSigningKeySource<TSource>() for a custom ISigningKeySource.");

        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// Whether an <see cref="ISigningKeyRing"/> is registered — which is not the same question as
    /// whether one can be built.
    /// </summary>
    /// <remarks>
    /// A ring factory that throws answers "yes, and it is broken": the registration exists, and
    /// <c>SigningKeyRingStartupVerifier</c> has already run and recorded that failure. Letting the
    /// exception escape here would report the same configuration failure a second time, because
    /// <c>Microsoft.Extensions.DependencyInjection</c> does not cache a failed factory invocation.
    /// Only a <see cref="ZeeKayDaConfigurationException"/> is treated this way — that is the
    /// framework's own "this composition is wrong" signal, already aggregated by the runner. Any
    /// other exception is a genuine surprise and still aborts startup here.
    /// </remarks>
    private static bool IsSigningKeyRingRegistered(IServiceProvider scopedServices)
    {
        if (scopedServices.GetService<IServiceProviderIsService>() is { } isService)
            return isService.IsService(typeof(ISigningKeyRing));

        try
        {
            return scopedServices.GetService<ISigningKeyRing>() is not null;
        }
        catch (ZeeKayDaConfigurationException)
        {
            // The registration exists and is broken, which is a different answer from "absent" —
            // the ring's own activator, in the next phase, reports that failure.
            return true;
        }
    }
}
