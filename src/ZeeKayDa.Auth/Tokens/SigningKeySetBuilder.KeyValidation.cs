using System.Security.Cryptography;

namespace ZeeKayDa.Auth.Tokens;

// Each check names the key by the operator's own source id, never by the derived kid, which the
// operator has never typed and would not recognise in a configuration error.
internal static partial class SigningKeySetBuilder
{
    // OID values are stable across all platforms (macOS, Linux, Windows) unlike friendly names.
    private static readonly IReadOnlyDictionary<SigningAlgorithm, string> AlgorithmCurveOids =
        new Dictionary<SigningAlgorithm, string>
        {
            [SigningAlgorithm.ES256] = "1.2.840.10045.3.1.7", // P-256
            [SigningAlgorithm.ES384] = "1.3.132.0.34",        // P-384
            [SigningAlgorithm.ES512] = "1.3.132.0.35",        // P-521
        };

    private static readonly HashSet<string> AcceptedEcCurveOids =
        new(AlgorithmCurveOids.Values, StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Rejects an RSA key under 2048 significant bits (NIST SP 800-57), or an EC key on any curve but
    /// P-256, P-384 or P-521.
    /// </summary>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown with failure code <c>signing.rsa_key_too_small</c> or <c>signing.ec_unsupported_curve</c>.
    /// </exception>
    internal static void ValidateKeyStrength(SourceKey key)
    {
        switch (key.PublicKey.KeyType)
        {
            case SigningKeyType.Rsa:
                ValidateRsaModulusSize(key);
                break;
            case SigningKeyType.Ec:
                ValidateEcCurve(key);
                break;
            default:
                throw new ArgumentOutOfRangeException(
                    nameof(key), key.PublicKey.KeyType, $"Unknown {nameof(SigningKeyType)} value.");
        }
    }

    private static void ValidateRsaModulusSize(SourceKey key)
    {
        var modulus = key.PublicKey.RsaPublicParameters!.Value.Modulus;
        var bitLength = modulus is not null ? CountSignificantBits(modulus) : 0;
        if (bitLength >= 2048)
            return;

        throw new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure(
                "signing.rsa_key_too_small",
                $"RSA key '{key.Id.Value}' is {bitLength} bits. Minimum key size is 2048 bits per NIST SP 800-57."));
    }

    private static void ValidateEcCurve(SourceKey key)
    {
        var curveOid = key.PublicKey.EcPublicParameters!.Value.Curve.Oid?.Value;
        if (AcceptedEcCurveOids.Contains(curveOid ?? string.Empty))
            return;

        throw new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure(
                "signing.ec_unsupported_curve",
                $"EC key '{key.Id.Value}' uses curve OID '{curveOid ?? "unknown"}'. " +
                "Only NIST P-256, P-384, and P-521 are accepted."));
    }

    /// <summary>
    /// Rejects a key whose type, or for an EC algorithm whose curve, does not match its declared
    /// algorithm.
    /// </summary>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown with failure code <c>signing.key_algorithm_mismatch</c> or
    /// <c>signing.ec_curve_algorithm_mismatch</c>.
    /// </exception>
    internal static void ValidateKeyAlgorithmCompatibility(SourceKey key)
    {
        var algorithm = key.Algorithm;
        var isRsaAlgorithm = algorithm is
            SigningAlgorithm.RS256 or SigningAlgorithm.RS384 or SigningAlgorithm.RS512
            or SigningAlgorithm.PS256 or SigningAlgorithm.PS384 or SigningAlgorithm.PS512;

        if (isRsaAlgorithm && key.PublicKey.KeyType != SigningKeyType.Rsa)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.key_algorithm_mismatch",
                    $"Key '{key.Id.Value}' claims RSA algorithm {algorithm} but its public key is not an RSA key."));
        }

        if (!AlgorithmCurveOids.TryGetValue(algorithm, out var expectedOid))
            return;

        if (key.PublicKey.KeyType != SigningKeyType.Ec)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.key_algorithm_mismatch",
                    $"Key '{key.Id.Value}' claims EC algorithm {algorithm} but its public key is not an EC key."));
        }

        var curveOid = key.PublicKey.EcPublicParameters!.Value.Curve.Oid?.Value ?? string.Empty;
        if (!string.Equals(expectedOid, curveOid, StringComparison.OrdinalIgnoreCase))
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.ec_curve_algorithm_mismatch",
                    $"Key '{key.Id.Value}' uses algorithm {algorithm} which requires " +
                    $"curve OID {expectedOid}, but the key uses curve OID '{curveOid}'."));
        }
    }

    /// <summary>
    /// Imports the key's public parameters into the BCL's own cryptographic provider and re-exports
    /// them: rejects structural garbage (an off-curve EC point, a non-canonical RSA modulus) and
    /// returns a canonical copy decoupled from the instance the source still holds.
    /// </summary>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown with failure code <c>signing.invalid_public_key</c>.
    /// </exception>
    internal static PublicKeyParameters ImportAndCanonicalize(SourceKey key)
    {
        var publicKey = key.PublicKey;
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
        // Windows CNG reports structurally invalid material as PlatformNotSupportedException wrapping
        // a CryptographicException; macOS and Linux raise CryptographicException directly.
        catch (Exception ex) when (ex is CryptographicException or PlatformNotSupportedException)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.invalid_public_key",
                    $"Key '{key.Id.Value}' is not a structurally valid public key: {ex.GetType().Name}. " +
                    "See the inner exception for the root cause."),
                ex);
        }
    }

    /// <summary>
    /// Counts from the most-significant set bit, so a modulus left-padded with zero bytes is not
    /// mistaken for a larger one.
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
}
