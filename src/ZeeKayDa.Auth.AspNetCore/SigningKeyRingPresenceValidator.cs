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
/// Resolves the ring rather than asking <see cref="IServiceProviderIsService"/> about it, so the
/// check works on any container rather than skipping itself on a third-party one. Resolution is free
/// here in the ordinary case: <c>SigningKeyRingStartupVerifier</c> is registered from
/// <c>AddZeeKayDaAuthCore()</c>, which runs before this verifier, so the ring has normally already
/// been constructed and initialized by the time this runs.
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
        try
        {
            return scopedServices.GetService<ISigningKeyRing>() is not null;
        }
        catch (ZeeKayDaConfigurationException)
        {
            return true;
        }
    }
}
