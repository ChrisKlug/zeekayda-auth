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
            // Significant bits, not array length: a 1024-bit modulus left-padded to 256 bytes would
            // otherwise pass the 2048-bit gate and sign production tokens under a weak key.
            var bitLength = modulus is not null ? CountSignificantBits(modulus) : 0;

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
    /// Validates that <paramref name="algorithm"/> is compatible with <paramref name="publicKey"/>'s
    /// key type and, for an EC algorithm, its curve — the <see cref="PublicKeyParameters"/>
    /// counterpart of <see cref="ValidateKeyAlgorithmCompatibility(SigningKeyDescriptor, AsymmetricAlgorithm)"/>,
    /// usable before any private material exists.
    /// </summary>
    /// <param name="algorithm">The declared algorithm.</param>
    /// <param name="publicKey">The public key material whose type and curve are checked.</param>
    /// <param name="keyLabel">The configured slot's own identifier, for the exception message.</param>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown when <paramref name="publicKey"/>'s key type or EC curve does not match
    /// <paramref name="algorithm"/>.
    /// </exception>
    internal static void ValidateKeyAlgorithmCompatibility(SigningAlgorithm algorithm, PublicKeyParameters publicKey, string keyLabel)
    {
        var isRsaAlgorithm = algorithm is
            SigningAlgorithm.RS256 or SigningAlgorithm.RS384 or SigningAlgorithm.RS512
            or SigningAlgorithm.PS256 or SigningAlgorithm.PS384 or SigningAlgorithm.PS512;

        var isEcAlgorithm = algorithm is
            SigningAlgorithm.ES256 or SigningAlgorithm.ES384 or SigningAlgorithm.ES512;

        if (isRsaAlgorithm && publicKey.KeyType != SigningKeyType.Rsa)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.key_algorithm_mismatch",
                    $"Key '{keyLabel}' claims RSA algorithm {algorithm} but its public key is not an RSA key."));
        }

        if (isEcAlgorithm)
        {
            if (publicKey.KeyType != SigningKeyType.Ec)
            {
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.key_algorithm_mismatch",
                        $"Key '{keyLabel}' claims EC algorithm {algorithm} but its public key is not an EC key."));
            }

            ValidateEcCurveAlgorithmPairing(algorithm, publicKey.EcPublicParameters!.Value, keyLabel);
        }
    }

    /// <summary>
    /// Validates that the key described by <paramref name="publicKey"/> meets minimum strength
    /// requirements (RSA ≥ 2048 significant bits; EC curve must be P-256, P-384, or P-521) — the
    /// <see cref="PublicKeyParameters"/> counterpart of
    /// <see cref="ValidateKeyStrength(SigningKeyDescriptor)"/>.
    /// </summary>
    /// <param name="algorithm">
    /// The declared algorithm. Unused by this overload (<paramref name="publicKey"/>'s own
    /// <see cref="PublicKeyParameters.KeyType"/> already selects the RSA/EC branch) — kept for
    /// signature symmetry with <see cref="ValidateKeyAlgorithmCompatibility(SigningAlgorithm, PublicKeyParameters, string)"/>.
    /// </param>
    /// <param name="publicKey">The public key material to validate.</param>
    /// <param name="keyLabel">The configured slot's own identifier, for the exception message.</param>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown when the key is too small or uses an unsupported EC curve.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="publicKey"/>'s <see cref="PublicKeyParameters.KeyType"/> is
    /// neither <see cref="SigningKeyType.Rsa"/> nor <see cref="SigningKeyType.Ec"/>.
    /// </exception>
    internal static void ValidateKeyStrength(SigningAlgorithm algorithm, PublicKeyParameters publicKey, string keyLabel)
    {
        if (publicKey.KeyType == SigningKeyType.Rsa)
        {
            var modulus = publicKey.RsaPublicParameters!.Value.Modulus;
            var bitLength = modulus is not null ? CountSignificantBits(modulus) : 0;

            if (bitLength < 2048)
            {
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.rsa_key_too_small",
                        $"RSA key '{keyLabel}' is {bitLength} bits. Minimum key size is 2048 bits per NIST SP 800-57."));
            }
        }
        else if (publicKey.KeyType == SigningKeyType.Ec)
        {
            var curveOid = publicKey.EcPublicParameters!.Value.Curve.Oid?.Value;

            if (!AcceptedEcCurveOids.Contains(curveOid ?? string.Empty))
            {
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.ec_unsupported_curve",
                        $"EC key '{keyLabel}' uses curve OID '{curveOid ?? "unknown"}'. " +
                        "Only NIST P-256, P-384, and P-521 are accepted."));
            }
        }
        else
        {
            throw new ArgumentOutOfRangeException(
                nameof(publicKey), publicKey.KeyType, $"Unknown {nameof(SigningKeyType)} value.");
        }
    }

    /// <summary>
    /// Imports <paramref name="publicKey"/>'s RSA or EC parameters into the BCL's own cryptographic
    /// provider and re-exports them, both structurally validating the key (rejecting garbage such as
    /// an off-curve EC point or a non-canonical RSA modulus the BCL itself refuses) and producing a
    /// canonical copy fully decoupled from whatever a signing key source's own
    /// <see cref="PublicKeyParameters"/> instance holds.
    /// </summary>
    /// <param name="publicKey">The public key material to import.</param>
    /// <param name="keyLabel">The configured slot's own identifier, for the exception message.</param>
    /// <returns>A freshly constructed, structurally valid <see cref="PublicKeyParameters"/>.</returns>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown with failure code <c>signing.invalid_public_key</c> when the underlying cryptographic
    /// provider rejects <paramref name="publicKey"/> as structurally invalid.
    /// </exception>
    internal static PublicKeyParameters ImportAndCanonicalize(PublicKeyParameters publicKey, string keyLabel)
    {
        try
        {
            if (publicKey.KeyType == SigningKeyType.Rsa)
            {
                using var rsa = RSA.Create();
                rsa.ImportParameters(publicKey.RsaPublicParameters!.Value);
                return PublicKeyParameters.FromRsa(rsa.ExportParameters(false));
            }

            using var ec = ECDsa.Create();
            ec.ImportParameters(publicKey.EcPublicParameters!.Value);
            return PublicKeyParameters.FromEc(ec.ExportParameters(false));
        }
        // Windows CNG reports structurally invalid material — an off-curve point, say — as
        // PlatformNotSupportedException wrapping a CryptographicException, while macOS and Linux
        // raise CryptographicException directly. Both mean the same thing here: the source handed us
        // something that is not a usable public key. Catching only one of them let the raw platform
        // exception escape the builder on Windows, breaking the guarantee that every rejection
        // arrives as a ZeeKayDaConfigurationException.
        catch (Exception ex) when (ex is CryptographicException or PlatformNotSupportedException)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.invalid_public_key",
                    $"Key '{keyLabel}' is not a structurally valid public key: {ex.GetType().Name}. " +
                    "See the inner exception for the root cause."),
                ex);
        }
    }

    /// <summary>
    /// Counts the significant bits of a big-endian unsigned integer — the number of bits from the
    /// most-significant set bit down, ignoring leading zero bytes — rather than
    /// <c>value.Length * 8</c>, which a modulus left-padded to a fixed byte length would inflate.
    /// </summary>
    private static int CountSignificantBits(byte[] value)
    {
        var firstNonZero = 0;
        while (firstNonZero < value.Length && value[firstNonZero] == 0)
            firstNonZero++;

        if (firstNonZero == value.Length)
            return 0;

        var bitsInLeadingByte = 32 - System.Numerics.BitOperations.LeadingZeroCount((uint)value[firstNonZero]);
        return ((value.Length - firstNonZero - 1) * 8) + bitsInLeadingByte;
    }

    /// <summary>
    /// Verifies <paramref name="signature"/> over <paramref name="signingInput"/> against
    /// <paramref name="publicKey"/> directly, using <paramref name="algorithm"/> — the
    /// <see cref="PublicKeyParameters"/> counterpart of
    /// <see cref="Verify(SigningKeyDescriptor, ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>, used by
    /// <see cref="SigningSelfTest"/>.
    /// </summary>
    /// <param name="algorithm">The algorithm the signature was produced under.</param>
    /// <param name="publicKey">The public key to verify against.</param>
    /// <param name="signingInput">The exact bytes that were signed.</param>
    /// <param name="signature">The signature bytes to verify.</param>
    /// <returns><see langword="true"/> when the signature verifies; otherwise <see langword="false"/>.</returns>
    internal static bool Verify(
        SigningAlgorithm algorithm, PublicKeyParameters publicKey, ReadOnlySpan<byte> signingInput, ReadOnlySpan<byte> signature)
    {
        if (publicKey.KeyType == SigningKeyType.Rsa)
        {
            using var rsa = RSA.Create();
            rsa.ImportParameters(publicKey.RsaPublicParameters!.Value);
            return VerifyRsa(algorithm, rsa, signingInput, signature);
        }

        using var ec = ECDsa.Create();
        ec.ImportParameters(publicKey.EcPublicParameters!.Value);
        return VerifyEc(algorithm, ec, signingInput, signature);
    }

    /// <summary>
    /// Produces the raw signature bytes for <paramref name="signingInput"/> using the algorithm
    /// declared in <paramref name="descriptor"/> and the supplied <paramref name="privateKey"/>.
    /// </summary>
    /// <param name="descriptor">The key descriptor carrying the declared algorithm.</param>
    /// <param name="signingInput">The bytes to sign (base64url(header) + '.' + base64url(payload)).</param>
    /// <param name="privateKey">The private key to use for signing.</param>
    /// <returns>The raw signature bytes in the format required by the algorithm.</returns>
    internal static ReadOnlyMemory<byte> Sign(
        SigningKeyDescriptor descriptor,
        byte[] signingInput,
        AsymmetricAlgorithm privateKey)
        => Sign(descriptor.Algorithm, signingInput, privateKey);

    /// <summary>
    /// Produces the raw signature bytes for <paramref name="signingInput"/> using
    /// <paramref name="algorithm"/> and <paramref name="privateKey"/> directly, without requiring a
    /// <see cref="SigningKeyDescriptor"/>. Used by <see cref="LocalSigner"/>, which
    /// signs over public <see cref="KeyListing"/> data rather than a descriptor.
    /// </summary>
    /// <param name="algorithm">The signing algorithm.</param>
    /// <param name="signingInput">The bytes to sign (base64url(header) + '.' + base64url(payload)).</param>
    /// <param name="privateKey">The private key to use for signing.</param>
    /// <returns>The raw signature bytes in the format required by the algorithm.</returns>
    [ExcludeFromCodeCoverage(Justification = "Unreachable default arm — all SigningAlgorithm members are handled above.")]
    internal static ReadOnlyMemory<byte> Sign(
        SigningAlgorithm algorithm,
        byte[] signingInput,
        AsymmetricAlgorithm privateKey)
    {
        return algorithm switch
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
            _ => ThrowUnsupportedAlgorithm<ReadOnlyMemory<byte>>(algorithm),
        };
    }

    /// <summary>
    /// Verifies <paramref name="signature"/> over <paramref name="signingInput"/> against
    /// <paramref name="descriptor"/>'s own public key, using the algorithm <paramref name="descriptor"/>
    /// declares. Used exclusively by the startup self-test
    /// (<see cref="ISigningStartupSelfTest"/>) to structurally prove that the private key a provider's
    /// <c>CreateSignerAsync</c> materialized actually pairs with the public key listed for the same
    /// <c>kid</c> — never used on real token signatures, which relying parties verify independently.
    /// </summary>
    /// <param name="descriptor">The key descriptor carrying the declared algorithm and public key.</param>
    /// <param name="signingInput">The exact bytes that were signed.</param>
    /// <param name="signature">The signature bytes to verify.</param>
    /// <returns><see langword="true"/> when the signature verifies; otherwise <see langword="false"/>.</returns>
    internal static bool Verify(SigningKeyDescriptor descriptor, ReadOnlySpan<byte> signingInput, ReadOnlySpan<byte> signature)
    {
        if (descriptor.KeyType == SigningKeyType.Rsa)
        {
            using var rsa = RSA.Create();
            rsa.ImportParameters(descriptor.RsaPublicParameters!.Value);
            return VerifyRsa(descriptor.Algorithm, rsa, signingInput, signature);
        }

        using var ec = ECDsa.Create();
        ec.ImportParameters(descriptor.EcPublicParameters!.Value);
        return VerifyEc(descriptor.Algorithm, ec, signingInput, signature);
    }

    private static bool VerifyRsa(
        SigningAlgorithm algorithm, RSA rsa, ReadOnlySpan<byte> signingInput, ReadOnlySpan<byte> signature)
    {
        return algorithm switch
        {
            SigningAlgorithm.RS256 => rsa.VerifyData(signingInput, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            SigningAlgorithm.RS384 => rsa.VerifyData(signingInput, signature, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1),
            SigningAlgorithm.RS512 => rsa.VerifyData(signingInput, signature, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1),
            SigningAlgorithm.PS256 => rsa.VerifyData(signingInput, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
            SigningAlgorithm.PS384 => rsa.VerifyData(signingInput, signature, HashAlgorithmName.SHA384, RSASignaturePadding.Pss),
            SigningAlgorithm.PS512 => rsa.VerifyData(signingInput, signature, HashAlgorithmName.SHA512, RSASignaturePadding.Pss),
            _ => ThrowUnsupportedAlgorithm<bool>(algorithm),
        };
    }

    private static bool VerifyEc(
        SigningAlgorithm algorithm, ECDsa ec, ReadOnlySpan<byte> signingInput, ReadOnlySpan<byte> signature)
    {
        return algorithm switch
        {
            SigningAlgorithm.ES256 => ec.VerifyData(signingInput, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation),
            SigningAlgorithm.ES384 => ec.VerifyData(signingInput, signature, HashAlgorithmName.SHA384, DSASignatureFormat.IeeeP1363FixedFieldConcatenation),
            SigningAlgorithm.ES512 => ec.VerifyData(signingInput, signature, HashAlgorithmName.SHA512, DSASignatureFormat.IeeeP1363FixedFieldConcatenation),
            _ => ThrowUnsupportedAlgorithm<bool>(algorithm),
        };
    }

    private static void ValidateEcCurveAlgorithmPairing(SigningKeyDescriptor descriptor, ECDsa ecKey) =>
        ValidateEcCurveAlgorithmPairing(descriptor.Algorithm, ecKey.ExportParameters(false), descriptor.Kid);

    private static void ValidateEcCurveAlgorithmPairing(SigningAlgorithm algorithm, ECParameters ecParams, string keyLabel)
    {
        // AlgorithmCurveOids contains entries for all EC algorithms (ES256/384/512), and
        // this method is only called when isEcAlgorithm is true, so the lookup always succeeds.
        var expectedOid = AlgorithmCurveOids[algorithm];

        var curveOid = ecParams.Curve.Oid?.Value ?? string.Empty;

        if (!string.Equals(expectedOid, curveOid, StringComparison.OrdinalIgnoreCase))
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.ec_curve_algorithm_mismatch",
                    $"Key '{keyLabel}' uses algorithm {algorithm} which requires " +
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
