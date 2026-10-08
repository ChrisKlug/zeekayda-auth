using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Configuration options for <c>AddAzureKeyVaultCachedSigning</c>.
/// </summary>
/// <remarks>
/// Key Vault owns the certificate's version history, and the provider lists its enabled versions, dated from
/// the vault's own per-version metadata. The vault is read at startup and every
/// <see cref="SigningKeyOptions.RefreshInterval"/>, so a new certificate version is published within one
/// interval of its creation, and the framework decides from the versions' dates when it takes over.
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

    /// <summary>
    /// Gets or sets how many of the newest enabled versions to list, or <see langword="null"/> (the
    /// default) to list every enabled version. Must be at least 3 when set.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every listed version costs one public-key request at startup, and a certificate on a rotation policy
    /// keeps every old version, so this caps that cost. The newest versions are found from the vault's
    /// version metadata, which is one paged request whatever the count.
    /// </para>
    /// <para>
    /// A normal rotation has three versions live at once: the new one, published but not yet signing;
    /// the one signing; and the one before it, kept until the tokens it signed have expired. Add one
    /// for every further rotation that can happen within the signing-key lead time plus the
    /// retention — an emergency rotation, or two rotations close together. A value too high only costs
    /// startup requests; a value too low drops a version whose tokens are still in use, and those
    /// tokens then fail verification. When unsure, choose the higher number.
    /// </para>
    /// </remarks>
    public int? MaxVersions { get; set; }
}
