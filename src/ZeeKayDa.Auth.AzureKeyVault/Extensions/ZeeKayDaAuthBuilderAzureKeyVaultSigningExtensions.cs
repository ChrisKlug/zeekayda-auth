using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys;
using Microsoft.Extensions.DependencyInjection.Extensions;
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
    /// live call to Key Vault; the provider discovers the key's versions itself and derives which
    /// one signs from the vault's own per-version metadata.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Signing is performed remotely inside Azure Key Vault. The private key never leaves the
    /// vault and is never held in process memory. Use <c>AddAzureKeyVaultCachedSigning</c>
    /// if Key Vault latency or throttling limits are a concern.
    /// </para>
    /// <para>
    /// The vault is read exactly once, at startup — rotation is picked up by restarting the host.
    /// Rotate by creating a new version of the key (Key Vault's automatic rotation policy does
    /// exactly that): the new version is published as staged until it has existed for
    /// <see cref="AzureKeyVaultRemoteSigningOptions.PreActivationDelay"/>, so relying parties see
    /// its public half in the JWKS before it ever signs, and a restart after that promotes it to
    /// the signing key. Versions it succeeds stay published per
    /// <see cref="AzureKeyVaultRemoteSigningOptions.PreviousVersionsToPublish"/>; disabling a
    /// version in the vault removes it from publication unconditionally.
    /// </para>
    /// <para>
    /// If no enabled version is eligible to sign — every one expired, not yet valid, or younger
    /// than the pre-activation delay (the key's chronologically-first version ever is exempt from
    /// the delay) — startup fails closed with a configuration error rather than signing with an
    /// ineligible key.
    /// </para>
    /// </remarks>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="keyIdentifier">The Key Vault (or Managed HSM) key to sign with.</param>
    /// <param name="algorithm">The JWS algorithm to sign with.</param>
    /// <param name="credential">The credential used to authenticate to Key Vault.</param>
    /// <param name="configure">
    /// An optional callback to further configure <see cref="AzureKeyVaultRemoteSigningOptions"/>
    /// (for example, <see cref="AzureKeyVaultRemoteSigningOptions.PreActivationDelay"/>).
    /// </param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> or <paramref name="credential"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when a signing key provider has already been registered. Only one is allowed.
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

        // Transitional, removed with IJwtSigningService itself in #511. No first-party provider
        // registers an IJwtSigningService any more; this rejects a composition where the
        // application still carries a third-party provider on the old contract, which
        // AddZeeKayDaSigningKeySource below cannot see.
        builder.ThrowIfAlreadyRegistered(typeof(IJwtSigningService));

        // Registered first so a second signing key source is rejected before this method applies any
        // of its own configuration — a caller that catches the rejection must not be left with this
        // call's options callbacks applied to the surviving registration.
        builder.Services.AddZeeKayDaSigningKeySource<AzureKeyVaultRemoteSigningKeySource>();

        // Defensive/idempotent: guarantees the core services are resolvable even when this package is
        // used standalone, without ZeeKayDa.Auth.AspNetCore's AddZeeKayDaAuth().
        builder.Services.AddZeeKayDaAuthCore();

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
    /// The vault is read exactly once, at startup — rotation is picked up by restarting the host.
    /// Rotate by creating a new version of the certificate: it is published as staged until it has
    /// existed for <see cref="AzureKeyVaultCachedSigningOptions.PreActivationDelay"/>, so relying
    /// parties see its public half in the JWKS before it ever signs, and a restart after that
    /// promotes it to the signing key. Versions it succeeds stay published per
    /// <see cref="AzureKeyVaultCachedSigningOptions.PreviousVersionsToPublish"/>; disabling a
    /// version in the vault removes it from publication unconditionally. If no enabled version is
    /// eligible to sign, startup fails closed with a configuration error.
    /// </para>
    /// <para>
    /// Private key material is downloaded for exactly one version — the signing one. Every other
    /// published version is read as public <c>Cer</c> material only, so <c>secrets/get</c> is
    /// needed for one version and a published-only version's private key never enters the process.
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

        // Transitional, removed with IJwtSigningService itself in #511. No first-party provider
        // registers an IJwtSigningService any more; this rejects a composition where the
        // application still carries a third-party provider on the old contract, which
        // AddZeeKayDaSigningKeySource below cannot see.
        builder.ThrowIfAlreadyRegistered(typeof(IJwtSigningService));

        // Registered first so a second signing key source is rejected before this method applies any
        // of its own configuration — a caller that catches the rejection must not be left with this
        // call's options callbacks applied to the surviving registration.
        builder.Services.AddZeeKayDaSigningKeySource<AzureKeyVaultCachedSigningKeySource>();

        // Defensive/idempotent: guarantees the core services are resolvable even when this package is
        // used standalone, without ZeeKayDa.Auth.AspNetCore's AddZeeKayDaAuth().
        builder.Services.AddZeeKayDaAuthCore();

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

        return builder;
    }
}
