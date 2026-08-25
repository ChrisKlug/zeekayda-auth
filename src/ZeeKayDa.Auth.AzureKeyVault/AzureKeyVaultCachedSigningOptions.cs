using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Configuration options for <c>AddAzureKeyVaultCachedSigning</c>.
/// </summary>
/// <remarks>
/// Key Vault owns the certificate's version history, and the provider derives which versions to
/// publish and which one signs entirely from the vault's own per-version metadata — there are no
/// <c>Previous</c>/<c>Current</c>/<c>Next</c> properties to configure here. The vault is read
/// exactly once, at startup: rotation is picked up by restarting the host. Rotate by creating a new
/// certificate version (Key Vault's automatic rotation does exactly that); it is published as
/// staged until it has existed for <see cref="PreActivationDelay"/>, and a restart after that
/// promotes it to the signing key.
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
    /// Gets or sets how many enabled certificate versions older than the signing version stay
    /// published, so relying parties can still verify tokens those versions signed. Must be zero or
    /// greater. Only the older side is capped: every enabled version newer than the signing one is
    /// always published, so a host restarting after one of them ripens signs with a key this host
    /// already served. Published-only versions are read as public material only — their private
    /// keys are never downloaded.
    /// </summary>
    /// <remarks>
    /// Disabling a version in the vault always removes it from publication regardless of this
    /// count — that is the operator's revocation lever, and because the vault is read once at
    /// startup, it takes effect when the host next starts. An expired-but-enabled older version
    /// still publishes within the count: tokens it signed before expiry are still within their own
    /// lifetime.
    /// </remarks>
    public int PreviousVersionsToPublish { get; set; } = 1;

    /// <summary>
    /// Gets or sets how long a certificate version must have existed before it is eligible to sign.
    /// Must be zero or greater; <see cref="TimeSpan.Zero"/> disables the delay entirely.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A version younger than this is published as staged but does not sign — and its private key
    /// is not downloaded — so relying parties have had at least this long to pick its public half
    /// up from a published JWKS before the first token signed with it arrives. Set it comfortably
    /// above your relying parties' actual JWKS cache TTL. The chronologically-first version the
    /// certificate has ever had is exempt — there was no earlier key whose relying parties need
    /// protecting, and a brand-new deployment must be able to start.
    /// </para>
    /// <para>
    /// Derived from Key Vault's durable per-version <c>CreatedOn</c>, never from when this process
    /// first observed the version, so every replica and every restart computes the same answer.
    /// </para>
    /// </remarks>
    public TimeSpan PreActivationDelay { get; set; } = TimeSpan.FromDays(1);
}
