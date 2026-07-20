using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Configuration options for <c>AddAzureKeyVaultCachedSigning</c>.
/// </summary>
/// <remarks>
/// <see cref="RotatingKeySourceOptions.KeyRotationCheckInterval"/> is inherited from the base class
/// and defaults to 5 minutes. It is the interval on which certificate versions are rediscovered
/// and their private key material re-downloaded from Key Vault — see
/// <c>AzureKeyVaultCachedSigningJwtSigningService</c>. <see cref="SigningKeyActivationDelay"/> is
/// the separate publish-then-activate delay applied to every rotated-in certificate version.
/// </remarks>
public sealed class AzureKeyVaultCachedSigningOptions : RotatingKeySourceOptions
{
    /// <summary>
    /// Gets or sets the publish-then-activate lead time a newly rotated-in certificate version
    /// must be visible before it may become the active signer (ADR 0011 §3.5). When unset (the
    /// default), defaults to <see cref="RotatingKeySourceOptions.KeyRotationCheckInterval"/>. Must
    /// be greater than or equal to <see cref="RotatingKeySourceOptions.KeyRotationCheckInterval"/> —
    /// enforced both by <c>AzureKeyVaultCachedSigningOptionsValidator</c> and independently inside
    /// <c>KeyVaultSigningKeyRotation.BuildActivationTimeline</c>.
    /// </summary>
    public TimeSpan? SigningKeyActivationDelay { get; set; }

    /// <summary>
    /// Gets or sets the Key Vault certificate to sign with. The certificate must have been created
    /// with an exportable key policy — see <c>AddAzureKeyVaultCachedSigning</c>'s remarks. The
    /// <see cref="KeyVaultCertificateIdentifier.Version"/> component, if present, is ignored — the
    /// provider always discovers and downloads every live certificate version itself in order to
    /// support rotation.
    /// </summary>
    public KeyVaultCertificateIdentifier CertificateIdentifier { get; set; }

    /// <summary>
    /// Gets or sets the credential used to authenticate to Key Vault for both listing certificate
    /// versions and downloading each version's private key material via its linked secret.
    /// </summary>
    public TokenCredential? Credential { get; set; }

    /// <summary>
    /// Gets or sets the JWS algorithm to use when signing. A Key Vault certificate's key does not
    /// itself declare RS256 vs PS256 — that choice is made here and must match the certificate
    /// key's type (RSA algorithms for RSA certificates, EC algorithms for EC certificates).
    /// </summary>
    public SigningAlgorithm Algorithm { get; set; }
}
