using Azure.Core;
using Azure.Security.KeyVault.Keys;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Configuration options for <c>AddAzureKeyVaultRemoteSigning</c>.
/// </summary>
/// <remarks>
/// <para>
/// ADR 0015 Tier B (<see cref="KeySourceOptions"/>, issue #425): Key Vault owns the key's version
/// history, so <c>AzureKeyVaultRemoteSigningJwtSigningService.ListKeysAsync</c> re-asks Key Vault
/// for the current version list once per <see cref="KeySourceOptions.RefreshInterval"/>.
/// </para>
/// <para>
/// <see cref="KeySourceOptions.PublicationLead"/> is inherited from <see cref="KeySourceOptions"/>
/// and, unlike Tier A, is not merely advisory here: every rotated-in key version's <c>ActivateAt</c>
/// is derived as <c>CreatedOn + PublicationLead</c> (never from when this process first observed the
/// version), so <see cref="KeySourceOptions.PublicationLead"/> is the actual publish-then-activate
/// delay a newly rotated-in version must wait out before it may become the active signer.
/// </para>
/// </remarks>
public sealed class AzureKeyVaultRemoteSigningOptions : KeySourceOptions
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
