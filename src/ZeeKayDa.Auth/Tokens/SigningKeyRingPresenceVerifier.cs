using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.StartupVerification;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>Fails startup when no signing key source is registered, rather than on the first discovery request.</summary>
/// <remarks>
/// Asks <see cref="IServiceProviderIsService"/> rather than resolving the ring, which would construct the
/// source in a phase meant to run before any work; a container without it falls back to resolving.
/// </remarks>
internal sealed class SigningKeyRingPresenceVerifier(IServiceProvider services) : IStartupVerifier
{
    /// <inheritdoc/>
    public string Name => "SigningKeyRingPresence";

    /// <inheritdoc/>
    public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
        if (!IsSigningKeyRingRegistered())
            context.AddFailure(
                "signing.key_ring.missing",
                "No signing key source has been registered, so no token can be signed and " +
                "id_token_signing_alg_values_supported cannot be published. Call " +
                "builder.AddInMemoryDevelopmentSigning() or " +
                "builder.AddPersistedDevelopmentSigning() for local development, one of the " +
                "provider packages' registrations (builder.AddPemFileSigning(), " +
                "builder.AddPfxFileSigning(), builder.AddAzureKeyVaultRemoteSigning(), " +
                "builder.AddAzureKeyVaultCachedSigning(), builder.AddWindowsCertificateStoreSigning()), " +
                "or builder.AddSigningKeySource<TSource>() for a custom ISigningKeySource.");

        return Task.CompletedTask;
    }

    /// <summary>
    /// Whether a ring is registered, not whether one can be built: a factory throwing a configuration
    /// failure counts as registered, since the ring's activator reports that failure itself.
    /// </summary>
    private bool IsSigningKeyRingRegistered()
    {
        if (services.GetService<IServiceProviderIsService>() is { } isService)
            return isService.IsService(typeof(SigningKeyRing));

        try
        {
            return services.GetService<SigningKeyRing>() is not null;
        }
        catch (ZeeKayDaConfigurationException)
        {
            return true;
        }
    }
}
