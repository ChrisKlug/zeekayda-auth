using System.Security.Cryptography;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Builds <see cref="SigningKeyDescriptor"/>s — and validates that the configured
/// <see cref="SigningAlgorithm"/> matches the actual Key Vault key/certificate type — for every
/// Key Vault signing provider. Not generic over the version-info types in
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
        string keySourceDescription)
    {
        ValidateAlgorithmFamilyMatchesKeyType(keyType, algorithm, optionsTypeName, keySourceDescription);

        return keyType switch
        {
            SigningKeyType.Rsa => BuildRsaDescriptor((RSA)publicKey, algorithm),
            SigningKeyType.Ec => BuildEcDescriptor((ECDsa)publicKey, algorithm),
            _ => throw new NotSupportedException($"Signing key type {keyType} is not supported."),
        };
    }

    private static SigningKeyDescriptor BuildRsaDescriptor(RSA rsa, SigningAlgorithm algorithm)
    {
        var parameters = rsa.ExportParameters(includePrivateParameters: false);
        var kid = JwkThumbprint.Compute(parameters);
        return new SigningKeyDescriptor(kid, algorithm, parameters);
    }

    private static SigningKeyDescriptor BuildEcDescriptor(ECDsa ecdsa, SigningAlgorithm algorithm)
    {
        var parameters = ecdsa.ExportParameters(includePrivateParameters: false);
        var kid = JwkThumbprint.Compute(parameters);
        return new SigningKeyDescriptor(kid, algorithm, parameters);
    }

    /// <summary>
    /// Fails fast with a clear, Key-Vault-specific message when the configured algorithm does not
    /// match the actual key's type. Without this check the mismatch would only surface later as a
    /// more generic <c>ZeeKayDaConfigurationException</c> from the base class's
    /// <c>ValidateKeyAlgorithmCompatibility</c>, with no Key-Vault-specific remediation guidance.
    /// </summary>
    private static void ValidateAlgorithmFamilyMatchesKeyType(
        SigningKeyType keyType, SigningAlgorithm algorithm, string optionsTypeName, string keySourceDescription)
    {
        var isRsaAlgorithm = algorithm is
            SigningAlgorithm.RS256 or SigningAlgorithm.RS384 or SigningAlgorithm.RS512
            or SigningAlgorithm.PS256 or SigningAlgorithm.PS384 or SigningAlgorithm.PS512;

        if (keyType == SigningKeyType.Rsa && !isRsaAlgorithm)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.algorithm_key_type_mismatch",
                    $"{optionsTypeName}.Algorithm is {algorithm}, but the {keySourceDescription} is an " +
                    "RSA key. Use an RSA algorithm (RS256, RS384, RS512, PS256, PS384, or PS512)."));
        }

        if (keyType == SigningKeyType.Ec && isRsaAlgorithm)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.azure_key_vault.algorithm_key_type_mismatch",
                    $"{optionsTypeName}.Algorithm is {algorithm}, but the {keySourceDescription} is an " +
                    "EC key. Use an EC algorithm (ES256, ES384, or ES512)."));
        }
    }
}
