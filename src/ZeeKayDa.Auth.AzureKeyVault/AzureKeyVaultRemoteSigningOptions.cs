using Azure.Core;
using Azure.Security.KeyVault.Keys;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Configuration options for <c>AddAzureKeyVaultRemoteSigning</c>.
/// </summary>
/// <remarks>
/// Key Vault owns the key's version history: the provider re-asks Key Vault for the current
/// version list once per <see cref="KeySourceOptions.RefreshInterval"/>.
/// <see cref="KeySourceOptions.PublicationLead"/> is not merely advisory here — every rotated-in
/// version's <c>ActivateAt</c> is derived as <c>CreatedOn + PublicationLead</c>, so it is the
/// actual publish-then-activate delay a version must wait out before becoming the active signer.
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
