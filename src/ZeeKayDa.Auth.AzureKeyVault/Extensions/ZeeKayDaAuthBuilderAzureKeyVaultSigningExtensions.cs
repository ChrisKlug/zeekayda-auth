using Azure.Core;
using Azure.Security.KeyVault.Certificates;
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
/// Extension methods for registering Azure Key Vault as a JWT signing key provider with
/// <see cref="ZeeKayDaAuthBuilder"/>: either <see cref="AddAzureKeyVaultRemoteSigning"/> (signing
/// stays inside Key Vault) or <see cref="AddAzureKeyVaultCachedSigning"/> (the private key is
/// downloaded once and cached in process memory for local signing).
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
    /// vault and is never held in process memory. Use <c>AddAzureKeyVaultCachedSigning</c>
    /// if Key Vault latency or throttling limits are a concern.
    /// </para>
    /// <para>
    /// The first key version a deployment ever uses activates immediately. Every subsequent
    /// rotation requires the new version to have existed for at least
    /// <see cref="ZeeKayDa.Auth.Tokens.KeySourceOptions.PublicationLead"/> before it signs anything,
    /// so relying parties have had a chance to see it in a published JWKS — create rotated-in
    /// versions with that much lead time. <c>PublicationLead</c> must exceed your relying parties'
    /// actual JWKS cache TTL.
    /// </para>
    /// <para>
    /// If the active key version reaches its Key Vault <c>ExpiresOn</c> with no enabled successor,
    /// key loading fails closed with a configuration error rather than signing with an expired or
    /// absent key — rotate in a new version before the active one expires.
    /// </para>
    /// </remarks>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="keyIdentifier">The Key Vault (or Managed HSM) key to sign with.</param>
    /// <param name="algorithm">The JWS algorithm to sign with.</param>
    /// <param name="credential">The credential used to authenticate to Key Vault.</param>
    /// <param name="configure">
    /// An optional callback to further configure <see cref="AzureKeyVaultRemoteSigningOptions"/>
    /// (for example, <see cref="ZeeKayDa.Auth.Tokens.KeySourceOptions.RefreshInterval"/>).
    /// </param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> or <paramref name="credential"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when an <see cref="IJwtSigningService"/> has already been registered. Only one
    /// signing key provider is allowed.
    /// </exception>
    /// <seealso cref="AddAzureKeyVaultCachedSigning"/>
    public static ZeeKayDaAuthBuilder AddAzureKeyVaultRemoteSigning(
        this ZeeKayDaAuthBuilder builder,
        KeyVaultKeyIdentifier keyIdentifier,
        SigningAlgorithm algorithm,
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
                options.Algorithm = algorithm;
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

        return builder;
    }

    /// <summary>
    /// Registers Azure Key Vault as the JWT signing key provider, downloading the private key
    /// once and caching it in process memory for local signing. The provider automatically
    /// discovers and rotates through the certificate's versions.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The private key is downloaded from Azure Key Vault at startup and cached in process
    /// memory. Signing is performed locally. An attacker who achieves process memory read gets
    /// a permanent copy of the signing key. Use <c>AddAzureKeyVaultRemoteSigning</c> if the
    /// private key must never leave the vault.
    /// </para>
    /// <para>
    /// <paramref name="certificateIdentifier"/> must name a Key Vault <b>certificate</b> created
    /// with an exportable key policy. Key-only <c>KeyClient.GetKeyAsync</c> never returns private
    /// key material, so this provider downloads the certificate's linked secret instead, which
    /// only carries the full PFX when the key policy is exportable. A non-exportable certificate
    /// fails startup with a <see cref="ZeeKayDaConfigurationException"/> pointing at
    /// <see cref="AddAzureKeyVaultRemoteSigning"/> as the alternative.
    /// </para>
    /// <para>
    /// Rotation bootstrap, the publish-then-activate delay, and fail-closed behavior on expiry are
    /// identical to <see cref="AddAzureKeyVaultRemoteSigning"/> — see its remarks. Because this
    /// provider re-downloads private key material on every
    /// <see cref="ZeeKayDa.Auth.Tokens.KeySourceOptions.RefreshInterval"/>, that traffic is more
    /// sensitive than the remote-signing provider's public-key-only refresh.
    /// </para>
    /// </remarks>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="certificateIdentifier">
    /// The Key Vault certificate to sign with. Must have been created with an exportable key
    /// policy.
    /// </param>
    /// <param name="algorithm">The JWS algorithm to sign with.</param>
    /// <param name="credential">The credential used to authenticate to Key Vault.</param>
    /// <param name="configure">
    /// An optional callback to further configure <see cref="AzureKeyVaultCachedSigningOptions"/>
    /// (for example, <see cref="ZeeKayDa.Auth.Tokens.KeySourceOptions.RefreshInterval"/>).
    /// </param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> or <paramref name="credential"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when an <see cref="IJwtSigningService"/> has already been registered. Only one
    /// signing key provider is allowed.
    /// </exception>
    /// <seealso cref="AddAzureKeyVaultRemoteSigning"/>
    public static ZeeKayDaAuthBuilder AddAzureKeyVaultCachedSigning(
        this ZeeKayDaAuthBuilder builder,
        KeyVaultCertificateIdentifier certificateIdentifier,
        SigningAlgorithm algorithm,
        TokenCredential credential,
        Action<AzureKeyVaultCachedSigningOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(credential);

        // Defensive/idempotent: guarantees ISigningKeyRetirementWindowProvider and
        // IOptions<AuthorizationServerOptions> are resolvable even when this package is used
        // standalone, without ZeeKayDa.Auth.AspNetCore's AddZeeKayDaAuth().
        builder.Services.AddZeeKayDaAuthCore();

        builder.ThrowIfAlreadyRegistered(typeof(IJwtSigningService));

        builder.Services.AddOptions<AzureKeyVaultCachedSigningOptions>()
            .Configure(options =>
            {
                options.CertificateIdentifier = certificateIdentifier;
                options.Algorithm = algorithm;
                options.Credential = credential;
            })
            .Configure(configure ?? (_ => { }))
            .ValidateOnStart();

        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                IValidateOptions<AzureKeyVaultCachedSigningOptions>,
                AzureKeyVaultCachedSigningOptionsValidator>());

        builder.Services.TryAddSingleton<TimeProvider>(TimeProvider.System);
        builder.Services.TryAddSingleton<IKeyVaultCertificateReader, KeyVaultCertificateReader>();
        builder.Services.AddSingleton<IJwtSigningService, AzureKeyVaultCachedSigningJwtSigningService>();
        builder.Services.AddHostedService<AzureKeyVaultCachedSigningStartupService>();

        return builder;
    }
}
