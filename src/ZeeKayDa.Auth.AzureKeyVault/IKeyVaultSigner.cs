using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Performs a JWS signature entirely inside Azure Key Vault (or Managed HSM) — the private key
/// never leaves the vault. A seam over
/// <see cref="Azure.Security.KeyVault.Keys.Cryptography.CryptographyClient"/> so that signing can
/// be exercised against a fake with no network access.
/// </summary>
internal interface IKeyVaultSigner
{
    /// <summary>
    /// Signs <paramref name="signingInput"/> using the Key Vault key version identified by
    /// <paramref name="keyVersionUri"/>.
    /// </summary>
    /// <param name="keyVersionUri">The versioned key identifier URI to sign with.</param>
    /// <param name="kid">
    /// The public, non-leaking JWK thumbprint identifying the key — used in any exception message
    /// this call raises, so a sign-time fault never discloses <paramref name="keyVersionUri"/>'s
    /// vault/key name to a caller (the same reason <c>kid</c> is a thumbprint and not the raw URI
    /// in the first place; see ADR 0011 Amendment 2(c)).
    /// </param>
    /// <param name="algorithm">The JWS algorithm to use.</param>
    /// <param name="signingInput">The exact bytes to sign — Key Vault computes the digest itself.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The raw signature bytes in the format required by <paramref name="algorithm"/>.</returns>
    ValueTask<ReadOnlyMemory<byte>> SignAsync(
        Uri keyVersionUri, string kid, SigningAlgorithm algorithm, byte[] signingInput, CancellationToken cancellationToken);
}
