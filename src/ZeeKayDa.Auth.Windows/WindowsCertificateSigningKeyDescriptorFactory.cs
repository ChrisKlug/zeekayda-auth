using System.Security.Cryptography;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Windows;

/// <summary>
/// Builds <see cref="SigningKeyDescriptor"/>s — and validates that the configured
/// <see cref="SigningAlgorithm"/> matches the actual certificate's key type — for the Windows
/// Certificate Store signing provider.
/// </summary>
/// <remarks>
/// Structurally mirrors <c>ZeeKayDa.Auth.AzureKeyVault.KeyVaultSigningKeyDescriptorFactory</c> but
/// is deliberately not shared code with that package (different assembly; this codebase's
/// convention is to duplicate small provider-specific logic until a second real consumer exists,
/// exactly how the Key Vault rotation-timeline logic itself was only extracted after two Key Vault
/// variants shipped — see ADR 0011 Amendment 2 / issue #317).
/// </remarks>
internal static class WindowsCertificateSigningKeyDescriptorFactory
{
    /// <summary>
    /// Builds a <see cref="SigningKeyDescriptor"/> — and therefore its <c>kid</c> — from a public
    /// key, after validating that <paramref name="algorithm"/>'s family matches
    /// <paramref name="keyType"/>.
    /// </summary>
    /// <param name="publicKey">The public-only key material to derive the descriptor's kid from.</param>
    /// <param name="keyType">The certificate's key type.</param>
    /// <param name="algorithm">The configured signing algorithm.</param>
    /// <param name="thumbprint">The certificate's thumbprint, for the mismatch exception message only — never used as the kid.</param>
    public static SigningKeyDescriptor BuildDescriptor(
        AsymmetricAlgorithm publicKey, SigningKeyType keyType, SigningAlgorithm algorithm, string thumbprint)
    {
        ValidateAlgorithmFamilyMatchesKeyType(keyType, algorithm, thumbprint);

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
    /// Fails fast with a clear, thumbprint-specific message when the configured algorithm does not
    /// match the actual certificate's key type. Without this check the mismatch would only surface
    /// later as a more generic <c>ZeeKayDaConfigurationException</c> from the base class's
    /// <c>ValidateKeyAlgorithmCompatibility</c>, with no certificate-specific remediation guidance.
    /// </summary>
    private static void ValidateAlgorithmFamilyMatchesKeyType(
        SigningKeyType keyType, SigningAlgorithm algorithm, string thumbprint)
    {
        var isRsaAlgorithm = algorithm is
            SigningAlgorithm.RS256 or SigningAlgorithm.RS384 or SigningAlgorithm.RS512
            or SigningAlgorithm.PS256 or SigningAlgorithm.PS384 or SigningAlgorithm.PS512;

        if (keyType == SigningKeyType.Rsa && !isRsaAlgorithm)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.windows_certificate_store.algorithm_key_type_mismatch",
                    $"WindowsCertificateStoreSigningOptions.Algorithm is {algorithm}, but certificate " +
                    $"'{thumbprint}' is an RSA certificate. Use an RSA algorithm (RS256, RS384, RS512, PS256, PS384, or PS512)."));
        }

        if (keyType == SigningKeyType.Ec && isRsaAlgorithm)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.windows_certificate_store.algorithm_key_type_mismatch",
                    $"WindowsCertificateStoreSigningOptions.Algorithm is {algorithm}, but certificate " +
                    $"'{thumbprint}' is an EC certificate. Use an EC algorithm (ES256, ES384, or ES512)."));
        }
    }
}
