using Azure.Core;
using Azure.Security.KeyVault.Keys;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Configuration options for <c>AddAzureKeyVaultRemoteSigning</c>.
/// </summary>
/// <remarks>
/// Key Vault owns the key's version history, and the provider derives which versions to publish and
/// which one signs entirely from the vault's own per-version metadata — there are no
/// <c>Previous</c>/<c>Current</c>/<c>Next</c> properties to configure here. The vault is read
/// exactly once, at startup: rotation is picked up by restarting the host. Rotate by creating a new
/// key version (Key Vault's automatic rotation policy does exactly that); it is published as staged
/// until it has existed for <see cref="PreActivationDelay"/>, and a restart after that promotes it
/// to the signing key.
/// </remarks>
public sealed class AzureKeyVaultRemoteSigningOptions
{
    /// <summary>
    /// Gets or sets the Key Vault (or Managed HSM) key to sign with. The <see cref="KeyVaultKeyIdentifier.Version"/>
    /// component, if present, is ignored — the provider always discovers the key's versions itself
    /// and selects among them in order to support rotation.
    /// </summary>
    public KeyVaultKeyIdentifier KeyIdentifier { get; set; }

    /// <summary>
    /// Gets or sets the credential used to authenticate to Key Vault for both listing/reading key
    /// versions and performing sign operations. Required — startup validation fails when it is
    /// unset; there is deliberately no fallback to <c>DefaultAzureCredential</c>, so the credential
    /// an application signs with is always visible at its call site.
    /// </summary>
    public TokenCredential? Credential { get; set; }

    /// <summary>
    /// Gets or sets the JWS algorithm to use when signing. A Key Vault RSA key does not itself
    /// declare RS256 vs PS256 — that choice is made here and must match the key's type (RSA
    /// algorithms for RSA/RSA-HSM keys, EC algorithms for EC/EC-HSM keys).
    /// </summary>
    public SigningAlgorithm Algorithm { get; set; }

    /// <summary>
    /// Gets or sets how many enabled key versions older than the signing version stay published, so
    /// relying parties can still verify tokens those versions signed. Must be zero or greater.
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
    /// Gets or sets how long a key version must have existed before it is eligible to sign. Must be
    /// zero or greater; <see cref="TimeSpan.Zero"/> disables the delay entirely.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A version younger than this is published as staged but does not sign, so relying parties
    /// have had at least this long to pick its public half up from a published JWKS before the
    /// first token signed with it arrives. Set it comfortably above your relying parties' actual
    /// JWKS cache TTL. The chronologically-first version the key has ever had is exempt — there was
    /// no earlier key whose relying parties need protecting, and a brand-new deployment must be
    /// able to start.
    /// </para>
    /// <para>
    /// Derived from Key Vault's durable per-version <c>CreatedOn</c>, never from when this process
    /// first observed the version, so every replica and every restart computes the same answer.
    /// </para>
    /// </remarks>
    public TimeSpan PreActivationDelay { get; set; } = TimeSpan.FromDays(1);
}
