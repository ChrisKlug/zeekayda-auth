using System.Security.Cryptography;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Builds <see cref="SigningKeyDescriptor"/>s — and validates that a configured
/// <see cref="SigningAlgorithm"/> matches the actual key's type — shared by every first-party and
/// third-party <see cref="IJwtSigningService"/> implementation that derives a descriptor from raw
/// RSA/EC key material.
/// </summary>
/// <remarks>
/// <para>
/// This is a public, standalone utility — not tied to any specific provider package — for the same
/// reason <see cref="JwkThumbprint"/> is public: the RSA/EC descriptor-building and
/// algorithm-family/key-type validation logic is byte-for-byte identical across every provider that
/// signs with local RSA/EC key material (Azure Key Vault, Windows Certificate Store, and future
/// OS-native store providers), but those providers live in separate, non-friend assemblies that
/// cannot share <see langword="internal"/> members with each other or with core.
/// </para>
/// <para>
/// Exception text is deliberately left entirely to the caller: <see cref="BuildDescriptor"/> takes a
/// caller-supplied failure code and a message-building delegate, invoked only when a mismatch is
/// actually detected, so each provider's exception message continues to read exactly as it did
/// before this type existed (e.g. naming its own options type and describing the key's origin in its
/// own words).
/// </para>
/// </remarks>
public static class SigningKeyDescriptorFactory
{
    /// <summary>
    /// Builds a <see cref="SigningKeyDescriptor"/> — and therefore its <c>kid</c> — from a public
    /// key, after validating that <paramref name="algorithm"/>'s family matches
    /// <paramref name="keyType"/>.
    /// </summary>
    /// <param name="publicKey">
    /// The public-only key material to derive the descriptor's kid from. Must be an <see cref="RSA"/>
    /// instance when <paramref name="keyType"/> is <see cref="SigningKeyType.Rsa"/>, or an
    /// <see cref="ECDsa"/> instance when <paramref name="keyType"/> is <see cref="SigningKeyType.Ec"/>.
    /// </param>
    /// <param name="keyType">The key's actual type, as reported by the key's source.</param>
    /// <param name="algorithm">The configured signing algorithm.</param>
    /// <param name="mismatchFailureCode">
    /// The <see cref="ZeeKayDaConfigurationFailure.Code"/> to use when <paramref name="algorithm"/>'s
    /// family does not match <paramref name="keyType"/> (e.g.
    /// <c>"signing.azure_key_vault.algorithm_key_type_mismatch"</c>).
    /// </param>
    /// <param name="mismatchMessage">
    /// Builds the full exception message for the same mismatch, given the key's actual
    /// <see cref="SigningKeyType"/>. Invoked only when a mismatch is detected.
    /// </param>
    /// <returns>The built descriptor.</returns>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown when <paramref name="algorithm"/>'s family does not match <paramref name="keyType"/>.
    /// </exception>
    /// <exception cref="NotSupportedException">
    /// Thrown when <paramref name="keyType"/> is not a supported <see cref="SigningKeyType"/>.
    /// </exception>
    public static SigningKeyDescriptor BuildDescriptor(
        AsymmetricAlgorithm publicKey,
        SigningKeyType keyType,
        SigningAlgorithm algorithm,
        string mismatchFailureCode,
        Func<SigningKeyType, string> mismatchMessage)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(mismatchFailureCode);
        ArgumentNullException.ThrowIfNull(mismatchMessage);

        ValidateAlgorithmFamilyMatchesKeyType(keyType, algorithm, mismatchFailureCode, mismatchMessage);

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
    /// Fails fast with a clear, caller-supplied message when the configured algorithm does not match
    /// the actual key's type. Without this check the mismatch would only surface later as a more
    /// generic <c>ZeeKayDaConfigurationException</c> from the base class's
    /// <c>ValidateKeyAlgorithmCompatibility</c>, with no provider-specific remediation guidance.
    /// </summary>
    private static void ValidateAlgorithmFamilyMatchesKeyType(
        SigningKeyType keyType, SigningAlgorithm algorithm, string mismatchFailureCode, Func<SigningKeyType, string> mismatchMessage)
    {
        var isRsaAlgorithm = algorithm is
            SigningAlgorithm.RS256 or SigningAlgorithm.RS384 or SigningAlgorithm.RS512
            or SigningAlgorithm.PS256 or SigningAlgorithm.PS384 or SigningAlgorithm.PS512;

        if (keyType == SigningKeyType.Rsa && !isRsaAlgorithm)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(mismatchFailureCode, mismatchMessage(SigningKeyType.Rsa)));
        }

        if (keyType == SigningKeyType.Ec && isRsaAlgorithm)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(mismatchFailureCode, mismatchMessage(SigningKeyType.Ec)));
        }
    }
}
