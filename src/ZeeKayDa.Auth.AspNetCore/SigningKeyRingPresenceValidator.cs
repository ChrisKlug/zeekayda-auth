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
/// Uses <see cref="IServiceProviderIsService"/> to inspect the container without resolving the ring
/// — resolving it constructs the signing key source. If <see cref="IServiceProviderIsService"/> is
/// absent (a third-party DI container replacing the default provider), the check is skipped rather
/// than failing with a confusing resolution error.
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
        var isService = scopedServices.GetService<IServiceProviderIsService>();
        if (isService is null)
            return ValueTask.CompletedTask;

        if (!isService.IsService(typeof(ISigningKeyRing)))
            context.AddFailure(
                "signing.key_ring.missing",
                "No signing key source has been registered, so no token can be signed and " +
                "id_token_signing_alg_values_supported cannot be published. Call " +
                "builder.AddInMemoryDevelopmentJwtSigningKeys() for local development, one of the " +
                "provider packages' registrations (builder.AddPemFileSigning(), " +
                "builder.AddPfxFileSigning(), builder.AddAzureKeyVaultRemoteSigning(), " +
                "builder.AddAzureKeyVaultCachedSigning(), builder.AddWindowsCertificateStoreSigning()), " +
                "or services.AddZeeKayDaSigningKeySource<TSource>() for a custom ISigningKeySource.");

        return ValueTask.CompletedTask;
    }
}
