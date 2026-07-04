using System.Security.Cryptography;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Reads certificate-version metadata from, and downloads private key material out of, Azure Key
/// Vault. A seam over <see cref="Azure.Security.KeyVault.Certificates.CertificateClient"/> and
/// <see cref="Azure.Security.KeyVault.Secrets.SecretClient"/> so that rotation logic can be
/// exercised against a fake with no network access.
/// </summary>
internal interface IKeyVaultCertificateReader
{
    /// <summary>
    /// Enumerates every version Key Vault has ever recorded for the configured certificate,
    /// including disabled and expired ones — the rotation algorithm needs the full history to
    /// durably derive which version was created first.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    IAsyncEnumerable<KeyVaultCertificateVersionInfo> GetCertificateVersionsAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Downloads the private key material for a specific certificate version, via the Key Vault
    /// secret linked to that certificate version.
    /// </summary>
    /// <param name="version">The Key Vault certificate version identifier.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>
    /// The extracted private key — real private key material, unlike the remote-signing reader's
    /// public-only result — and its <see cref="SigningKeyType"/>. The caller takes ownership of
    /// the returned <see cref="AsymmetricAlgorithm"/> and is responsible for disposing it.
    /// </returns>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown when the certificate version does not exist, the credential lacks the required
    /// permissions, or the certificate's key policy is non-exportable so no private key material
    /// is present in the downloaded secret.
    /// </exception>
    ValueTask<(AsymmetricAlgorithm PrivateKey, SigningKeyType KeyType)> GetPrivateKeyMaterialAsync(
        string version, CancellationToken cancellationToken);

    /// <summary>
    /// Fetches only the public key for a specific certificate version, without ever downloading
    /// the linked secret (and so without ever requiring the <c>secrets/get</c> permission or
    /// extracting real private key material). Called for every included version, including the
    /// active signing key — its <see cref="SigningKeyDescriptor"/> is always built from this
    /// public-only source, never from <see cref="GetPrivateKeyMaterialAsync"/>'s result — see
    /// <c>AzureKeyVaultCachedSigningJwtSigningService.LoadKeysAsync</c>'s remarks for the full
    /// rationale and for why only the active version's actual <c>SigningKeyPair.PrivateKey</c>
    /// additionally comes from <see cref="GetPrivateKeyMaterialAsync"/>.
    /// </summary>
    /// <param name="version">The Key Vault certificate version identifier.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>
    /// A public-only key — an <see cref="AsymmetricAlgorithm"/> holding no private key material —
    /// and its <see cref="SigningKeyType"/>. The caller takes ownership of the returned instance
    /// and is responsible for disposing it.
    /// </returns>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown when the certificate version does not exist or the credential lacks the required
    /// permissions.
    /// </exception>
    ValueTask<(AsymmetricAlgorithm PublicKey, SigningKeyType KeyType)> GetPublicKeyMaterialAsync(
        string version, CancellationToken cancellationToken);
}

/// <summary>
/// A single Key Vault certificate version's rotation-relevant metadata.
/// </summary>
/// <param name="Id">The full versioned certificate identifier URI.</param>
/// <param name="Version">The certificate version segment.</param>
/// <param name="Enabled">
/// Whether the version is currently enabled. An operator disabling a version is an immediate,
/// unconditional exclusion from the trusted key set, bypassing the retirement window.
/// </param>
/// <param name="CreatedOn">
/// The durable creation timestamp Key Vault stamped on this version. Identical across every
/// replica and process restart — the basis for the entire stateless rotation derivation.
/// </param>
/// <param name="NotBefore">The version's configured not-before time, if any.</param>
/// <param name="ExpiresOn">The version's configured expiry time, if any.</param>
internal readonly record struct KeyVaultCertificateVersionInfo(
    Uri Id,
    string Version,
    bool Enabled,
    DateTimeOffset CreatedOn,
    DateTimeOffset? NotBefore,
    DateTimeOffset? ExpiresOn);
