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
/// here: <c>SigningKeyRingStartupVerifier</c> is registered from <c>AddZeeKayDaAuthCore()</c>, which
/// runs before this verifier, so by the time this runs the ring has already been constructed and
/// initialized — this cannot be the call that builds a signing key source.
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
        if (scopedServices.GetService<ISigningKeyRing>() is null)
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
}
