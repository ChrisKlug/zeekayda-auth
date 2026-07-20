using Azure.Core;
using Azure.Security.KeyVault.Keys;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Configuration options for <c>AddAzureKeyVaultRemoteSigning</c>.
/// </summary>
/// <remarks>
/// <see cref="RotatingKeySourceOptions.KeyRotationCheckInterval"/> is inherited from the base class
/// and defaults to 5 minutes: real key-version rotation polling requires the base class to
/// periodically re-invoke <c>LoadKeysAsync</c> (see <c>AzureKeyVaultRemoteSigningJwtSigningService</c>).
/// <see cref="SigningKeyActivationDelay"/> is the separate publish-then-activate delay applied to
/// every rotated-in key version.
/// </remarks>
public sealed class AzureKeyVaultRemoteSigningOptions : RotatingKeySourceOptions
{
    /// <summary>
    /// Gets or sets the publish-then-activate lead time a newly rotated-in key version must be
    /// visible before it may become the active signer (ADR 0011 §3.5). When unset (the default),
    /// defaults to <see cref="RotatingKeySourceOptions.KeyRotationCheckInterval"/>. Must be greater
    /// than or equal to <see cref="RotatingKeySourceOptions.KeyRotationCheckInterval"/> — enforced
    /// both by <c>AzureKeyVaultRemoteSigningOptionsValidator</c> and independently inside
    /// <c>KeyVaultSigningKeyRotation.BuildActivationTimeline</c>.
    /// </summary>
    public TimeSpan? SigningKeyActivationDelay { get; set; }

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
