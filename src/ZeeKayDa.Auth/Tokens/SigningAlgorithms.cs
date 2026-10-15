using System.Collections.Frozen;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>Wire names, hash functions, and sign and verify dispatch for every <see cref="SigningAlgorithm"/>.</summary>
internal static class SigningAlgorithms
{
    // From each member's [JsonStringEnumMemberName], the name discovery and the JWKS serialize, so the
    // JWS header can never diverge from them.
    private static readonly FrozenDictionary<SigningAlgorithm, string> WireNames =
        Enum.GetValues<SigningAlgorithm>().ToFrozenDictionary(
            algorithm => algorithm,
            algorithm => typeof(SigningAlgorithm).GetField(algorithm.ToString())!
                .GetCustomAttribute<System.Text.Json.Serialization.JsonStringEnumMemberNameAttribute>()?.Name
                ?? algorithm.ToString());

    /// <summary>The RFC 7518 identifier for <paramref name="algorithm"/>, as the <c>alg</c> header, discovery and the JWKS carry it.</summary>
    internal static string WireName(SigningAlgorithm algorithm) => WireNames[algorithm];

    /// <summary>The hash function an algorithm signs over — also the one its ID tokens hash <c>at_hash</c> with.</summary>
    internal static HashAlgorithmName HashAlgorithm(SigningAlgorithm algorithm) => algorithm switch
    {
        SigningAlgorithm.RS256 or SigningAlgorithm.PS256 or SigningAlgorithm.ES256 => HashAlgorithmName.SHA256,
        SigningAlgorithm.RS384 or SigningAlgorithm.PS384 or SigningAlgorithm.ES384 => HashAlgorithmName.SHA384,
        SigningAlgorithm.RS512 or SigningAlgorithm.PS512 or SigningAlgorithm.ES512 => HashAlgorithmName.SHA512,
        _ => ThrowUnsupportedAlgorithm<HashAlgorithmName>(algorithm),
    };

    /// <summary>Whether <paramref name="signature"/> over <paramref name="signingInput"/> verifies against <paramref name="publicKey"/>.</summary>
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

    /// <summary>The raw signature over <paramref name="signingInput"/>, in the format <paramref name="algorithm"/> requires.</summary>
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
        // RFC 7518 §3.4 requires IEEE P1363 (raw R||S), not DER.
        => ec.SignData(input, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    /// <summary>The unreachable default arm of a switch over every <see cref="SigningAlgorithm"/>.</summary>
    [ExcludeFromCodeCoverage(Justification = "Unreachable defensive guard — all enum members are handled in callers.")]
    [DoesNotReturn]
    private static T ThrowUnsupportedAlgorithm<T>(SigningAlgorithm algorithm)
        => throw new NotSupportedException($"Signing algorithm {algorithm} is not supported.");
}
