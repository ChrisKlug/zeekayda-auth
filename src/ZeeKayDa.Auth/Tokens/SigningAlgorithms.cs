using System.Collections.Frozen;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Algorithm-specific logic for JWT signing: wire names, hash functions, and the sign and verify
/// dispatch for all supported <see cref="SigningAlgorithm"/> values.
/// </summary>
internal static class SigningAlgorithms
{
    // The authoritative RFC 7518 identifier is the [JsonStringEnumMemberName] on each member —
    // the same name STJ serialises into the discovery document and JWKS. Deriving the JWS header
    // value from the attribute rather than ToString() keeps the two structurally incapable of
    // diverging, even for a future member whose C# name cannot be the wire id verbatim (EdDSA).
    private static readonly FrozenDictionary<SigningAlgorithm, string> WireNames =
        Enum.GetValues<SigningAlgorithm>().ToFrozenDictionary(
            algorithm => algorithm,
            algorithm => typeof(SigningAlgorithm).GetField(algorithm.ToString())!
                .GetCustomAttribute<System.Text.Json.Serialization.JsonStringEnumMemberNameAttribute>()?.Name
                ?? algorithm.ToString());

    /// <summary>
    /// The RFC 7518 identifier for <paramref name="algorithm"/>, exactly as it appears on the wire
    /// in a JWS <c>alg</c> header, the discovery document, and the JWKS.
    /// </summary>
    internal static string WireName(SigningAlgorithm algorithm) => WireNames[algorithm];

    /// <summary>The hash function an algorithm signs over — also the one its ID tokens hash <c>at_hash</c> with.</summary>
    internal static HashAlgorithmName HashAlgorithm(SigningAlgorithm algorithm) => algorithm switch
    {
        SigningAlgorithm.RS256 or SigningAlgorithm.PS256 or SigningAlgorithm.ES256 => HashAlgorithmName.SHA256,
        SigningAlgorithm.RS384 or SigningAlgorithm.PS384 or SigningAlgorithm.ES384 => HashAlgorithmName.SHA384,
        SigningAlgorithm.RS512 or SigningAlgorithm.PS512 or SigningAlgorithm.ES512 => HashAlgorithmName.SHA512,
        _ => ThrowUnsupportedAlgorithm<HashAlgorithmName>(algorithm),
    };

    /// <summary>
    /// Verifies <paramref name="signature"/> over <paramref name="signingInput"/> against
    /// <paramref name="publicKey"/> directly, using <paramref name="algorithm"/>. Used by
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
    /// Produces the raw signature bytes for <paramref name="signingInput"/> using
    /// <paramref name="algorithm"/> and <paramref name="privateKey"/>. Used by
    /// <see cref="LocalSigner"/>.
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
        var hash = HashAlgorithm(algorithm);
        return algorithm switch
        {
            SigningAlgorithm.RS256 or SigningAlgorithm.RS384 or SigningAlgorithm.RS512 => SignRsa((RSA)privateKey, hash, RSASignaturePadding.Pkcs1, signingInput),
            SigningAlgorithm.PS256 or SigningAlgorithm.PS384 or SigningAlgorithm.PS512 => SignRsa((RSA)privateKey, hash, RSASignaturePadding.Pss, signingInput),
            SigningAlgorithm.ES256 or SigningAlgorithm.ES384 or SigningAlgorithm.ES512 => SignEc((ECDsa)privateKey, hash, signingInput),
            _ => ThrowUnsupportedAlgorithm<ReadOnlyMemory<byte>>(algorithm),
        };
    }

    private static bool VerifyRsa(
        SigningAlgorithm algorithm, RSA rsa, ReadOnlySpan<byte> signingInput, ReadOnlySpan<byte> signature)
    {
        var hash = HashAlgorithm(algorithm);
        return algorithm switch
        {
            SigningAlgorithm.RS256 or SigningAlgorithm.RS384 or SigningAlgorithm.RS512 => rsa.VerifyData(signingInput, signature, hash, RSASignaturePadding.Pkcs1),
            SigningAlgorithm.PS256 or SigningAlgorithm.PS384 or SigningAlgorithm.PS512 => rsa.VerifyData(signingInput, signature, hash, RSASignaturePadding.Pss),
            _ => ThrowUnsupportedAlgorithm<bool>(algorithm),
        };
    }

    private static bool VerifyEc(
        SigningAlgorithm algorithm, ECDsa ec, ReadOnlySpan<byte> signingInput, ReadOnlySpan<byte> signature)
    {
        return algorithm switch
        {
            SigningAlgorithm.ES256 or SigningAlgorithm.ES384 or SigningAlgorithm.ES512 =>
                ec.VerifyData(signingInput, signature, HashAlgorithm(algorithm), DSASignatureFormat.IeeeP1363FixedFieldConcatenation),
            _ => ThrowUnsupportedAlgorithm<bool>(algorithm),
        };
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
