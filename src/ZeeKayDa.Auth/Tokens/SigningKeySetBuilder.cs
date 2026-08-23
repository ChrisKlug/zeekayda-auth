using System.Collections.Immutable;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Builds a <see cref="SigningKeySet"/> from a <see cref="SourceKeySet"/>: the single choke point
/// where a weak, mismatched, or ambiguously identified signing key is rejected.
/// </summary>
/// <remarks>
/// <para>
/// A pure, total function: no clock, no policy object, no I/O. It runs entirely over public data,
/// before any private key material exists, and always derives every <c>kid</c> from the key's own
/// public material via <see cref="JwkThumbprint"/> — a caller cannot supply one.
/// </para>
/// <para>
/// Every rejection throws <see cref="ZeeKayDaConfigurationException"/>; this method never returns
/// a partial <see cref="SigningKeySet"/>.
/// </para>
/// </remarks>
public static class SigningKeySetBuilder
{
    /// <summary>
    /// Builds a <see cref="SigningKeySet"/> from <paramref name="keys"/>, validating every key
    /// before any is included.
    /// </summary>
    /// <param name="keys">The keys reported by a signing key source.</param>
    /// <returns>The validated, immutable key set.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="keys"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown with failure code <c>signing.empty_key_id</c> when a key's source id is empty or
    /// whitespace; <c>signing.duplicate_key_id</c> when two keys share a source id;
    /// <c>signing.duplicate_kid</c> when two keys derive the same <c>kid</c>;
    /// <c>signing.key_algorithm_mismatch</c> or <c>signing.ec_curve_algorithm_mismatch</c> when a
    /// key's declared algorithm does not match its key type or EC curve; or
    /// <c>signing.rsa_key_too_small</c> or <c>signing.ec_unsupported_curve</c> when a key fails
    /// minimum key-strength requirements.
    /// </exception>
    public static SigningKeySet Build(SourceKeySet keys)
    {
        ArgumentNullException.ThrowIfNull(keys);

        var seenSourceIds = new HashSet<string>(StringComparer.Ordinal);
        var seenKids = new HashSet<string>(StringComparer.Ordinal);
        var published = ImmutableArray.CreateBuilder<SigningKey>(keys.Keys.Count);
        SigningKey? signingKey = null;

        foreach (var sourceKey in keys.Keys)
        {
            var builtKey = BuildAndValidate(sourceKey, seenSourceIds, seenKids);
            published.Add(builtKey);

            if (ReferenceEquals(sourceKey, keys.SigningKey))
                signingKey = builtKey;
        }

        // Cannot be null: keys.SigningKey is always one of the SourceKey instances in keys.Keys
        // (SourceKeySet's own constructors guarantee this), so the ReferenceEquals check above
        // matches exactly once.
        var advertisedAlgorithms = published
            .Select(k => k.Algorithm)
            .Distinct()
            .OrderBy(a => a)
            .ToImmutableArray();

        return new SigningKeySet(signingKey!, published.ToImmutable(), advertisedAlgorithms);
    }

    private static SigningKey BuildAndValidate(
        SourceKey sourceKey, HashSet<string> seenSourceIds, HashSet<string> seenKids)
    {
        if (string.IsNullOrWhiteSpace(sourceKey.Id.Value))
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.empty_key_id",
                    "A signing key source id is empty or whitespace. Every SourceKey.Id must be a " +
                    "non-empty, non-whitespace identifier."));
        }

        if (!seenSourceIds.Add(sourceKey.Id.Value))
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.duplicate_key_id",
                    $"The signing key source reported duplicate source id '{sourceKey.Id.Value}'. " +
                    "Each SourceKey.Id must be unique among the keys reported by ReadAsync."));
        }

        var kid = ComputeKidOrThrowConfigurationException(sourceKey.PublicKey);

        if (!seenKids.Add(kid))
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.duplicate_kid",
                    $"The signing key source reported duplicate kid '{kid}', derived from the public " +
                    $"key of source id '{sourceKey.Id.Value}'. Each key must have a unique, stable " +
                    "kid — check for two distinct source ids sharing the same public key."));
        }

        SigningAlgorithms.ValidateKeyAlgorithmCompatibility(sourceKey.Algorithm, sourceKey.PublicKey, kid);
        SigningAlgorithms.ValidateKeyStrength(sourceKey.Algorithm, sourceKey.PublicKey, kid);

        return new SigningKey(sourceKey.Id, kid, sourceKey.Algorithm, sourceKey.PublicKey, sourceKey.ExpiresAt);
    }

    /// <summary>
    /// Derives the <c>kid</c> via <see cref="JwkThumbprint"/>, translating the unsupported-curve
    /// failure <see cref="JwkThumbprint.Compute(System.Security.Cryptography.ECParameters)"/> throws
    /// into the same <see cref="ZeeKayDaConfigurationException"/> shape every other builder
    /// rejection uses, rather than letting a differently shaped <see cref="NotSupportedException"/>
    /// escape this single choke point.
    /// </summary>
    private static string ComputeKidOrThrowConfigurationException(PublicKeyParameters publicKey)
    {
        if (publicKey.KeyType == SigningKeyType.Rsa)
            return JwkThumbprint.Compute(publicKey.RsaPublicParameters!.Value);

        try
        {
            return JwkThumbprint.Compute(publicKey.EcPublicParameters!.Value);
        }
        catch (NotSupportedException ex)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.ec_unsupported_curve",
                    $"EC key uses an unsupported curve: {ex.Message} Only NIST P-256, P-384, and " +
                    "P-521 are accepted."),
                ex);
        }
    }
}
