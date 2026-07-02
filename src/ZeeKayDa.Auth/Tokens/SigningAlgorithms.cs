using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Algorithm-specific logic for JWT signing: key-strength enforcement, key-algorithm
/// compatibility checks, and the signing dispatch for all supported
/// <see cref="SigningAlgorithm"/> values.
/// </summary>
internal static class SigningAlgorithms
{
    // OID values are stable across all platforms (macOS, Linux, Windows) unlike friendly names.
    private static readonly HashSet<string> AcceptedEcCurveOids =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "1.2.840.10045.3.1.7", // P-256
            "1.3.132.0.34",        // P-384
            "1.3.132.0.35",        // P-521
        };

    private static readonly IReadOnlyDictionary<SigningAlgorithm, string> AlgorithmCurveOids =
        new Dictionary<SigningAlgorithm, string>
        {
            [SigningAlgorithm.ES256] = "1.2.840.10045.3.1.7", // P-256
            [SigningAlgorithm.ES384] = "1.3.132.0.34",        // P-384
            [SigningAlgorithm.ES512] = "1.3.132.0.35",        // P-521
        };

    /// <summary>
    /// Validates that the key described by <paramref name="descriptor"/> meets minimum strength
    /// requirements (RSA ≥ 2048 bits; EC curve must be P-256, P-384, or P-521).
    /// </summary>
    /// <param name="descriptor">The key descriptor to validate.</param>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown when the key is too small or uses an unsupported EC curve.
    /// </exception>
    internal static void ValidateKeyStrength(SigningKeyDescriptor descriptor)
    {
        if (descriptor.KeyType == SigningKeyType.Rsa)
        {
            var modulus = descriptor.RsaPublicParameters!.Value.Modulus;
            var bitLength = modulus is not null ? modulus.Length * 8 : 0;

            if (bitLength < 2048)
            {
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.rsa_key_too_small",
                        $"RSA key '{descriptor.Kid}' is {bitLength} bits. " +
                        "Minimum key size is 2048 bits per NIST SP 800-57."));
            }
        }
        else if (descriptor.KeyType == SigningKeyType.Ec)
        {
            var ecParams = descriptor.EcPublicParameters!.Value;
            var curveOid = ecParams.Curve.Oid?.Value;

            if (!AcceptedEcCurveOids.Contains(curveOid ?? string.Empty))
            {
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.ec_unsupported_curve",
                        $"EC key '{descriptor.Kid}' uses curve OID '{curveOid ?? "unknown"}'. " +
                        "Only NIST P-256, P-384, and P-521 are accepted."));
            }
        }
    }

    /// <summary>
    /// Validates that the algorithm declared in <paramref name="descriptor"/> is compatible with
    /// the runtime type and EC curve of <paramref name="privateKey"/>.
    /// </summary>
    /// <param name="descriptor">The key descriptor carrying the declared algorithm.</param>
    /// <param name="privateKey">The private key whose type and curve are checked.</param>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown when the private key type or EC curve does not match the declared algorithm.
    /// </exception>
    internal static void ValidateKeyAlgorithmCompatibility(
        SigningKeyDescriptor descriptor,
        AsymmetricAlgorithm privateKey)
    {
        var isRsaAlgorithm = descriptor.Algorithm is
            SigningAlgorithm.RS256 or SigningAlgorithm.RS384 or SigningAlgorithm.RS512
            or SigningAlgorithm.PS256 or SigningAlgorithm.PS384 or SigningAlgorithm.PS512;

        var isEcAlgorithm = descriptor.Algorithm is
            SigningAlgorithm.ES256 or SigningAlgorithm.ES384 or SigningAlgorithm.ES512;

        if (isRsaAlgorithm && privateKey is not RSA)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.key_algorithm_mismatch",
                    $"Key '{descriptor.Kid}' claims RSA algorithm {descriptor.Algorithm} but the private key is not an RSA key."));
        }

        if (isEcAlgorithm)
        {
            if (privateKey is not ECDsa)
            {
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.key_algorithm_mismatch",
                        $"Key '{descriptor.Kid}' claims EC algorithm {descriptor.Algorithm} but the private key is not an ECDsa key."));
            }

            // Safe cast: the type check above guarantees privateKey is ECDsa.
            ValidateEcCurveAlgorithmPairing(descriptor, (ECDsa)privateKey);
        }
    }

    /// <summary>
    /// Produces the raw signature bytes for <paramref name="signingInput"/> using the algorithm
    /// declared in <paramref name="descriptor"/> and the supplied <paramref name="privateKey"/>.
    /// </summary>
    /// <param name="descriptor">The key descriptor carrying the declared algorithm.</param>
    /// <param name="signingInput">The bytes to sign (base64url(header) + '.' + base64url(payload)).</param>
    /// <param name="privateKey">The private key to use for signing.</param>
    /// <returns>The raw signature bytes in the format required by the algorithm.</returns>
    [ExcludeFromCodeCoverage(Justification = "Unreachable default arm — all SigningAlgorithm members are handled above.")]
    internal static ReadOnlyMemory<byte> Sign(
        SigningKeyDescriptor descriptor,
        byte[] signingInput,
        AsymmetricAlgorithm privateKey)
    {
        return descriptor.Algorithm switch
        {
            SigningAlgorithm.RS256 => SignRsa((RSA)privateKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, signingInput),
            SigningAlgorithm.RS384 => SignRsa((RSA)privateKey, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1, signingInput),
            SigningAlgorithm.RS512 => SignRsa((RSA)privateKey, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1, signingInput),
            SigningAlgorithm.PS256 => SignRsa((RSA)privateKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pss, signingInput),
            SigningAlgorithm.PS384 => SignRsa((RSA)privateKey, HashAlgorithmName.SHA384, RSASignaturePadding.Pss, signingInput),
            SigningAlgorithm.PS512 => SignRsa((RSA)privateKey, HashAlgorithmName.SHA512, RSASignaturePadding.Pss, signingInput),
            SigningAlgorithm.ES256 => SignEc((ECDsa)privateKey, HashAlgorithmName.SHA256, signingInput),
            SigningAlgorithm.ES384 => SignEc((ECDsa)privateKey, HashAlgorithmName.SHA384, signingInput),
            SigningAlgorithm.ES512 => SignEc((ECDsa)privateKey, HashAlgorithmName.SHA512, signingInput),
            _ => ThrowUnsupportedAlgorithm<ReadOnlyMemory<byte>>(descriptor.Algorithm),
        };
    }

    private static void ValidateEcCurveAlgorithmPairing(SigningKeyDescriptor descriptor, ECDsa ecKey)
    {
        // AlgorithmCurveOids contains entries for all EC algorithms (ES256/384/512), and
        // this method is only called when isEcAlgorithm is true, so the lookup always succeeds.
        var expectedOid = AlgorithmCurveOids[descriptor.Algorithm];

        var ecParams = ecKey.ExportParameters(false);
        var curveOid = ecParams.Curve.Oid?.Value ?? string.Empty;

        if (!string.Equals(expectedOid, curveOid, StringComparison.OrdinalIgnoreCase))
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.ec_curve_algorithm_mismatch",
                    $"Key '{descriptor.Kid}' uses algorithm {descriptor.Algorithm} which requires " +
                    $"curve OID {expectedOid}, but the key uses curve OID '{curveOid}'."));
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte[] SignRsa(RSA rsa, HashAlgorithmName hash, RSASignaturePadding padding, byte[] input)
        => rsa.SignData(input, hash, padding);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte[] SignEc(ECDsa ec, HashAlgorithmName hash, byte[] input)
        // RFC 7518 §3.4 requires the IEEE P1363 format (raw R||S concatenation).
        // Rfc3279DerSequence (DER) is the wrong format and will fail on all standards-compliant RPs.
        => ec.SignData(input, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    /// <summary>
    /// Unreachable defensive guard for switch statements that are exhaustive over
    /// <see cref="SigningAlgorithm"/>. Throws <see cref="NotSupportedException"/>.
    /// </summary>
    [ExcludeFromCodeCoverage(Justification = "Unreachable defensive guard — all enum members are handled in callers.")]
    [DoesNotReturn]
    private static T ThrowUnsupportedAlgorithm<T>(SigningAlgorithm algorithm)
        => throw new NotSupportedException($"Signing algorithm {algorithm} is not supported.");
}
