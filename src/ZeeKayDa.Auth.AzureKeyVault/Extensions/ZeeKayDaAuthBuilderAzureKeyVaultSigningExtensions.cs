using Azure.Core;
using Azure.Security.KeyVault.Keys;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AzureKeyVault;
using ZeeKayDa.Auth.Extensions;
using ZeeKayDa.Auth.Tokens;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for registering Azure Key Vault as a remote JWT signing key provider with
/// <see cref="ZeeKayDaAuthBuilder"/>.
/// </summary>
public static class ZeeKayDaAuthBuilderAzureKeyVaultSigningExtensions
{
    /// <summary>
    /// Registers Azure Key Vault as the JWT signing key provider. Every signature is produced by a
    /// live call to Key Vault; the provider automatically discovers and rotates through the
    /// key's versions.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Signing is performed remotely inside Azure Key Vault. The private key never leaves the
    /// vault and is never held in process memory. Use <c>AddAzureKeyVaultCachedSigning</c> if Key
    /// Vault latency or throttling limits are a concern.
    /// </para>
    /// <para>
    /// Rotation bootstrap behavior: the very first key version this deployment ever uses activates
    /// immediately (there is no prior published JWKS state any relying party could have cached).
    /// Every subsequent rotation requires the new Key Vault key version to exist for at least
    /// <see cref="JwtSigningServiceOptions.RefreshInterval"/> before it is expected to sign
    /// anything — a relying party could plausibly have cached a JWKS containing only the previous
    /// version. Operators should create rotated-in key versions with that much lead time before
    /// they need to become active.
    /// </para>
    /// <para>
    /// <see cref="JwtSigningServiceOptions.RefreshInterval"/> doubles as this publish-then-activate
    /// delay, so it must exceed your relying parties' actual JWKS cache TTL — the library rejects
    /// values below a one-minute floor as an almost-certain misconfiguration, but cannot verify a
    /// value above that floor is actually long enough for your specific relying parties.
    /// </para>
    /// <para>
    /// If the sole (or most recently active) key version reaches its Key Vault <c>ExpiresOn</c>
    /// with no enabled successor version, key loading fails closed with a configuration error
    /// rather than silently continuing to sign with an expired key or with none at all. This is
    /// expected behavior, not a defect — rotate in a new key version before the active one expires.
    /// </para>
    /// </remarks>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="keyIdentifier">The Key Vault (or Managed HSM) key to sign with.</param>
    /// <param name="credential">The credential used to authenticate to Key Vault.</param>
    /// <param name="configure">
    /// An optional callback to further configure <see cref="AzureKeyVaultRemoteSigningOptions"/>
    /// (for example, <see cref="JwtSigningServiceOptions.RefreshInterval"/> or
    /// <see cref="AzureKeyVaultRemoteSigningOptions.Algorithm"/>).
    /// </param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> or <paramref name="credential"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when an <see cref="IJwtSigningService"/> has already been registered. Only one
    /// signing key provider is allowed.
    /// </exception>
    public static ZeeKayDaAuthBuilder AddAzureKeyVaultRemoteSigning(
        this ZeeKayDaAuthBuilder builder,
        KeyVaultKeyIdentifier keyIdentifier,
        TokenCredential credential,
        Action<AzureKeyVaultRemoteSigningOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(credential);

        // Defensive/idempotent: guarantees ISigningKeyRetirementWindowProvider and
        // IOptions<AuthorizationServerOptions> are resolvable even when this package is used
        // standalone, without ZeeKayDa.Auth.AspNetCore's AddZeeKayDaAuth().
        builder.Services.AddZeeKayDaAuthCore();

        builder.ThrowIfAlreadyRegistered(typeof(IJwtSigningService));

        builder.Services.AddOptions<AzureKeyVaultRemoteSigningOptions>()
            .Configure(options =>
            {
                options.KeyIdentifier = keyIdentifier;
                options.Credential = credential;
            })
            .Configure(configure ?? (_ => { }))
            .ValidateOnStart();

        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IValidateOptions<AzureKeyVaultRemoteSigningOptions>,
                AzureKeyVaultRemoteSigningOptionsValidator>());

        builder.Services.TryAddSingleton<TimeProvider>(TimeProvider.System);
        builder.Services.TryAddSingleton<IKeyVaultKeyReader, KeyVaultKeyReader>();
        builder.Services.TryAddSingleton<IKeyVaultSigner, KeyVaultSigner>();
        builder.Services.AddSingleton<IJwtSigningService, AzureKeyVaultRemoteSigningJwtSigningService>();
        builder.Services.AddHostedService<AzureKeyVaultSigningStartupActivator>();

        return builder;
    }
}
