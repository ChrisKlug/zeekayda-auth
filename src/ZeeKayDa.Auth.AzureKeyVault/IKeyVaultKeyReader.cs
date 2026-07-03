using System.Security.Cryptography;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Reads key-version metadata and public key material from Azure Key Vault (or Managed HSM).
/// A seam over <see cref="Azure.Security.KeyVault.Keys.KeyClient"/> so that rotation logic can be
/// exercised against a fake with no network access.
/// </summary>
internal interface IKeyVaultKeyReader
{
    /// <summary>
    /// Enumerates every version Key Vault has ever recorded for the configured key, including
    /// disabled and expired ones — the rotation algorithm needs the full history to durably
    /// derive which version was created first.
    /// </summary>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    IAsyncEnumerable<KeyVaultKeyVersionInfo> GetKeyVersionsAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Fetches the public key material and key type for a specific key version.
    /// </summary>
    /// <param name="version">The Key Vault key version identifier.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>
    /// The public-only key (no private key material — obtained via <c>ToRSA(false)</c> /
    /// <c>ToECDsa(false)</c>) and its <see cref="SigningKeyType"/>.
    /// </returns>
    ValueTask<(AsymmetricAlgorithm PublicKey, SigningKeyType KeyType)> GetKeyMaterialAsync(
        string version, CancellationToken cancellationToken);
}

/// <summary>
/// A single Key Vault key version's rotation-relevant metadata.
/// </summary>
/// <param name="Id">The full versioned key identifier URI, used to construct a version-pinned <c>CryptographyClient</c>.</param>
/// <param name="Version">The key version segment.</param>
/// <param name="Enabled">
/// Whether the version is currently enabled. An operator disabling a version is an immediate,
/// unconditional exclusion from the trusted key set, bypassing the retirement window.
/// </param>
/// <param name="CreatedOn">
/// The durable creation timestamp Key Vault stamped on this version. Identical across every
/// replica and process restart — the basis for the entire stateless rotation derivation.
/// </param>
/// <param name="NotBefore">The version's configured not-before time, if any.</param>
/// <param name="ExpiresOn">The version's configured expiry time, if any.</param>
internal readonly record struct KeyVaultKeyVersionInfo(
    Uri Id,
    string Version,
    bool Enabled,
    DateTimeOffset CreatedOn,
    DateTimeOffset? NotBefore,
    DateTimeOffset? ExpiresOn);
