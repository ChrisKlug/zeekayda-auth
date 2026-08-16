using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Configuration options for <c>AddAzureKeyVaultCachedSigning</c>.
/// </summary>
/// <remarks>
/// Key Vault owns the certificate's version history: the provider re-asks Key Vault for the
/// current version list once per <see cref="KeySourceOptions.RefreshInterval"/>.
/// <see cref="KeySourceOptions.PublicationLead"/> is not merely advisory here — every rotated-in
/// version's <c>ActivateAt</c> is derived as <c>CreatedOn + PublicationLead</c>, so it is the
/// actual publish-then-activate delay a version must wait out before becoming the active signer.
/// </remarks>
public sealed class AzureKeyVaultCachedSigningOptions : KeySourceOptions
{
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
