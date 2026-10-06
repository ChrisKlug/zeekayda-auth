using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Configuration options for <c>AddAzureKeyVaultCachedSigning</c>.
/// </summary>
/// <remarks>
/// Key Vault owns the certificate's version history, and the provider lists every enabled version, dated
/// from the vault's own per-version metadata — there are no <c>Previous</c>/<c>Current</c>/<c>Next</c>
/// properties to configure here. The vault is read exactly once, at startup: rotation is picked up
/// by restarting the host. Rotate by creating a new certificate version; the framework decides from the
/// versions' dates when it takes over.
/// </remarks>
public sealed class AzureKeyVaultCachedSigningOptions
{
    /// <summary>
    /// Gets or sets the Key Vault certificate to sign with. The certificate must have been created
    /// with an exportable key policy — see <c>AddAzureKeyVaultCachedSigning</c>'s remarks. The
    /// <see cref="KeyVaultCertificateIdentifier.Version"/> component, if present, is ignored — the
    /// provider always discovers the certificate's versions itself and selects among them in order
    /// to support rotation.
    /// </summary>
    public KeyVaultCertificateIdentifier CertificateIdentifier { get; set; }

    /// <summary>
    /// Gets or sets the credential used to authenticate to Key Vault, both for listing/reading
    /// certificate versions (public material only) and for downloading the signing version's
    /// private key via its linked secret. Required — startup validation fails when it is unset;
    /// there is deliberately no fallback to <c>DefaultAzureCredential</c>, so the credential an
    /// application signs with is always visible at its call site.
    /// </summary>
    public TokenCredential? Credential { get; set; }

    /// <summary>
    /// Gets or sets the JWS algorithm to use when signing. A Key Vault certificate's key does not
    /// itself declare RS256 vs PS256 — that choice is made here and must match the certificate
    /// key's type (RSA algorithms for RSA certificates, EC algorithms for EC certificates).
    /// </summary>
    public SigningAlgorithm Algorithm { get; set; }
}
