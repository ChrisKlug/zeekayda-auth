using System.Security.Cryptography;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// Builds real <see cref="SigningKeySet"/> instances from freshly generated key material, so tests
/// that need a key set do not each repeat the crypto boilerplate — and never disagree about it.
/// </summary>
internal static class TestSigningKeys
{
    /// <summary>
    /// Builds a key set whose signing key uses <paramref name="signingAlgorithm"/>, optionally
    /// publishing further keys under <paramref name="alsoPublished"/>. At most two extra algorithms
    /// can be published: the set has exactly three slots (Previous/Current/Next).
    /// </summary>
    public static SigningKeySet KeySet(
        SigningAlgorithm signingAlgorithm, params SigningAlgorithm[] alsoPublished)
    {
        var current = SourceKey("current", signingAlgorithm);
        var previous = alsoPublished.Length > 0 ? SourceKey("previous", alsoPublished[0]) : null;
        var next = alsoPublished.Length > 1 ? SourceKey("next", alsoPublished[1]) : null;

        return SigningKeySetBuilder.Build(SourceKeySet.Create(previous, current, next));
    }

    /// <summary>Generates one key of the type and strength <paramref name="algorithm"/> requires.</summary>
    public static SourceKey SourceKey(string id, SigningAlgorithm algorithm)
        => new(new SourceKeyId(id), algorithm, PublicKey(algorithm), ExpiresAt: null);

    private static PublicKeyParameters PublicKey(SigningAlgorithm algorithm)
    {
        switch (algorithm)
        {
            case SigningAlgorithm.ES256:
            case SigningAlgorithm.ES384:
            case SigningAlgorithm.ES512:
                using (var ec = ECDsa.Create(Curve(algorithm)))
                    return PublicKeyParameters.FromEc(ec.ExportParameters(includePrivateParameters: false));
            default:
                using (var rsa = RSA.Create(2048))
                    return PublicKeyParameters.FromRsa(rsa.ExportParameters(includePrivateParameters: false));
        }
    }

    private static ECCurve Curve(SigningAlgorithm algorithm) => algorithm switch
    {
        SigningAlgorithm.ES256 => ECCurve.NamedCurves.nistP256,
        SigningAlgorithm.ES384 => ECCurve.NamedCurves.nistP384,
        _ => ECCurve.NamedCurves.nistP521,
    };
}
