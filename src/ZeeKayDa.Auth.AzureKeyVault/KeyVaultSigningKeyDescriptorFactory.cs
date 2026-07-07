using System.Security.Cryptography;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Builds <see cref="SigningKeyDescriptor"/>s — and validates that the configured
/// <see cref="SigningAlgorithm"/> matches the actual Key Vault key/certificate type — for every
/// Key Vault signing provider. Delegates the actual descriptor-building and validation logic to the
/// shared <see cref="SigningKeyDescriptorFactory"/> in core, supplying only Key-Vault-specific
/// failure code and exception message text so that text continues to render exactly as it did
/// before the shared factory existed. Not generic over the version-info types in
/// <see cref="KeyVaultSigningKeyRotation"/>: this class only ever operates on
/// <see cref="AsymmetricAlgorithm"/>, <see cref="SigningKeyType"/>, and
/// <see cref="SigningAlgorithm"/>, none of which is version-info-shaped.
/// </summary>
internal static class KeyVaultSigningKeyDescriptorFactory
{
    /// <summary>
    /// Builds a <see cref="SigningKeyDescriptor"/> — and therefore its <c>kid</c> — from a public
    /// key, after validating that <paramref name="algorithm"/>'s family matches
    /// <paramref name="keyType"/>.
    /// </summary>
    /// <param name="publicKey">The public-only key material to derive the descriptor's kid from.</param>
    /// <param name="keyType">The key's type, as reported by Key Vault.</param>
    /// <param name="algorithm">The configured signing algorithm.</param>
    /// <param name="optionsTypeName">
    /// The name of the caller's options type, for the exception message when <paramref name="algorithm"/>
    /// does not match <paramref name="keyType"/> (e.g. <c>"AzureKeyVaultRemoteSigningOptions"</c>).
    /// </param>
    /// <param name="keySourceDescription">
    /// A short description of where the key came from, for the same exception message
    /// (e.g. <c>"Key Vault key"</c> or <c>"Key Vault certificate key"</c>).
    /// </param>
    public static SigningKeyDescriptor BuildDescriptor(
        AsymmetricAlgorithm publicKey,
        SigningKeyType keyType,
        SigningAlgorithm algorithm,
        string optionsTypeName,
        string keySourceDescription) =>
        SigningKeyDescriptorFactory.BuildDescriptor(
            publicKey,
            keyType,
            algorithm,
            "signing.azure_key_vault.algorithm_key_type_mismatch",
            mismatchedKeyType => mismatchedKeyType == SigningKeyType.Rsa
                ? $"{optionsTypeName}.Algorithm is {algorithm}, but the {keySourceDescription} is an " +
                  "RSA key. Use an RSA algorithm (RS256, RS384, RS512, PS256, PS384, or PS512)."
                : $"{optionsTypeName}.Algorithm is {algorithm}, but the {keySourceDescription} is an " +
                  "EC key. Use an EC algorithm (ES256, ES384, or ES512).");
}
