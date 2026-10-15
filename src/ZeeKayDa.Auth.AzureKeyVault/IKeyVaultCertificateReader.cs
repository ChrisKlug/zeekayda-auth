using System.Security.Cryptography;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>Reads certificate versions and their key material from Key Vault; faked in tests.</summary>
internal interface IKeyVaultCertificateReader
{
    /// <summary>Every version of the certificate, disabled and expired ones included.</summary>
    IAsyncEnumerable<KeyVaultCertificateVersionInfo> GetCertificateVersionsAsync(CancellationToken cancellationToken);

    /// <summary>Downloads a version's private key through its linked secret; the caller disposes it.</summary>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown when the certificate version does not exist, the credential lacks the required
    /// permissions, or the certificate's key policy is non-exportable so no private key material
    /// is present in the downloaded secret.
    /// </exception>
    ValueTask<(AsymmetricAlgorithm PrivateKey, SigningKeyType KeyType)> GetPrivateKeyMaterialAsync(
        string version, CancellationToken cancellationToken);

    /// <summary>A version's public key, without the linked secret or <c>secrets/get</c>; the caller disposes it.</summary>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown when the certificate version does not exist or the credential lacks the required
    /// permissions.
    /// </exception>
    ValueTask<(AsymmetricAlgorithm PublicKey, SigningKeyType KeyType)> GetPublicKeyMaterialAsync(
        string version, CancellationToken cancellationToken);
}

/// <summary>One Key Vault certificate version's listing metadata.</summary>
internal readonly record struct KeyVaultCertificateVersionInfo(
    Uri Id,
    string Version,
    bool Enabled,
    DateTimeOffset CreatedOn,
    DateTimeOffset? NotBefore,
    DateTimeOffset? ExpiresOn) : IKeyVaultVersionInfo;
