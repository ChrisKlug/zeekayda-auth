using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>Signs inside Key Vault (or Managed HSM); faked in tests.</summary>
internal interface IKeyVaultSigner
{
    /// <summary>
    /// Signs <paramref name="signingInput"/>, undigested, with the version at <paramref name="keyVersionUri"/>.
    /// <paramref name="keyLabel"/> names the key in exceptions and must not carry the vault or key name.
    /// </summary>
    Task<ReadOnlyMemory<byte>> SignAsync(
        Uri keyVersionUri, string keyLabel, SigningAlgorithm algorithm, byte[] signingInput, CancellationToken cancellationToken);
}
