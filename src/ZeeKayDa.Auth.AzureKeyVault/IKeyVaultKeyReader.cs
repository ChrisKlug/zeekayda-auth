using System.Security.Cryptography;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>Reads key versions and their public keys from Key Vault (or Managed HSM); faked in tests.</summary>
internal interface IKeyVaultKeyReader
{
    /// <summary>Every version of the key, disabled and expired ones included.</summary>
    IAsyncEnumerable<KeyVaultKeyVersionInfo> GetKeyVersionsAsync(CancellationToken cancellationToken);

    /// <summary>A version's public key and key type; the caller disposes it.</summary>
    ValueTask<(AsymmetricAlgorithm PublicKey, SigningKeyType KeyType)> GetKeyMaterialAsync(
        string version, CancellationToken cancellationToken);
}

/// <summary>One Key Vault key version's listing metadata.</summary>
internal readonly record struct KeyVaultKeyVersionInfo(
    Uri Id,
    string Version,
    bool Enabled,
    DateTimeOffset CreatedOn,
    DateTimeOffset? NotBefore,
    DateTimeOffset? ExpiresOn) : IKeyVaultVersionInfo;
