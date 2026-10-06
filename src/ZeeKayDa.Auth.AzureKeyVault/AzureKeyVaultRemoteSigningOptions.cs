using Azure.Core;
using Azure.Security.KeyVault.Keys;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Configuration options for <c>AddAzureKeyVaultRemoteSigning</c>.
/// </summary>
/// <remarks>
/// Key Vault owns the key's version history, and the provider lists its enabled versions, dated from
/// the vault's own per-version metadata. The vault is read once, at startup: rotation is picked up by
/// restarting the host. Rotate by creating a new key version; the framework decides from the
/// versions' dates when it takes over.
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
    /// Gets or sets how many of the newest enabled versions to list, or <see langword="null"/> (the
    /// default) to list every enabled version. Must be at least 3 when set.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every listed version costs one public-key request at startup, and a key on a rotation policy
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
