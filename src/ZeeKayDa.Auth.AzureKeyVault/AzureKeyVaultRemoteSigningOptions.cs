using Azure.Core;
using Azure.Security.KeyVault.Keys;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Configuration options for <c>AddAzureKeyVaultRemoteSigning</c>.
/// </summary>
/// <remarks>
/// Key Vault owns the key's version history, and the provider lists every enabled version, dated
/// from the vault's own per-version metadata — there are no <c>Previous</c>/<c>Current</c>/<c>Next</c>
/// properties to configure here. The vault is read exactly once, at startup: rotation is picked up
/// by restarting the host. Rotate by creating a new key version; the framework decides from the
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
}
