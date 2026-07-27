using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Configuration options for <c>AddAzureKeyVaultCachedSigning</c>.
/// </summary>
/// <remarks>
/// <para>
/// ADR 0015 Tier B (<see cref="KeySourceOptions"/>, issue #425): Key Vault owns the certificate's
/// version history, so <c>AzureKeyVaultCachedSigningJwtSigningService.ListKeysAsync</c> re-asks Key
/// Vault for the current version list once per <see cref="KeySourceOptions.RefreshInterval"/>.
/// </para>
/// <para>
/// <see cref="KeySourceOptions.PublicationLead"/> is inherited from <see cref="KeySourceOptions"/>
/// and, unlike Tier A, is not merely advisory here: every rotated-in certificate version's
/// <c>ActivateAt</c> is derived as <c>CreatedOn + PublicationLead</c> (never from when this process
/// first observed the version), so <see cref="KeySourceOptions.PublicationLead"/> is the actual
/// publish-then-activate delay a newly rotated-in version must wait out before it may become the
/// active signer.
/// </para>
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
