using Azure.Core;
using Azure.Security.KeyVault.Keys;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Configuration options for <c>AddAzureKeyVaultRemoteSigning</c>.
/// </summary>
/// <remarks>
/// <see cref="JwtSigningServiceOptions.RefreshInterval"/> is inherited from the base class and
/// defaults to 5 minutes. Unlike the local-development provider, this value must remain finite —
/// real key-version rotation polling requires the base class to periodically re-invoke
/// <c>LoadKeysAsync</c>, and it is also the publish-then-activate delay applied to every rotated-in
/// key version (see <c>AzureKeyVaultRemoteSigningJwtSigningService</c>).
/// </remarks>
public sealed class AzureKeyVaultRemoteSigningOptions : JwtSigningServiceOptions
{
    /// <summary>
    /// Gets or sets the Key Vault (or Managed HSM) key to sign with. The <see cref="KeyVaultKeyIdentifier.Version"/>
    /// component, if present, is ignored — the provider always discovers and signs with every
    /// live key version itself in order to support rotation.
    /// </summary>
    public KeyVaultKeyIdentifier KeyIdentifier { get; set; }

    /// <summary>
    /// Gets or sets the credential used to authenticate to Key Vault for both listing/reading key
    /// versions and performing sign operations.
    /// </summary>
    public TokenCredential? Credential { get; set; }

    /// <summary>
    /// Gets or sets the JWS algorithm to use when signing. A Key Vault RSA key does not itself
    /// declare RS256 vs PS256 — that choice is made here and must match the key's type (RSA
    /// algorithms for RSA/RSA-HSM keys, EC algorithms for EC/EC-HSM keys).
    /// </summary>
    public SigningAlgorithm Algorithm { get; set; }
}
