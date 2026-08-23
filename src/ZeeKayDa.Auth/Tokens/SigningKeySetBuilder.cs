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
    /// <c>signing.undefined_algorithm</c> when a key declares an undefined
    /// <see cref="SigningAlgorithm"/> value; <c>signing.key_algorithm_mismatch</c> or
    /// <c>signing.ec_curve_algorithm_mismatch</c> when a key's declared algorithm does not match its
    /// key type or EC curve; <c>signing.rsa_key_too_small</c> or <c>signing.ec_unsupported_curve</c>
    /// when a key fails minimum key-strength requirements; <c>signing.invalid_public_key</c> when a
    /// key's public material is not structurally valid; or <c>signing.duplicate_kid</c> when two
    /// keys derive the same <c>kid</c>.
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
        var keyLabel = sourceKey.Id.Value;

        if (string.IsNullOrWhiteSpace(keyLabel))
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.empty_key_id",
                    "A signing key source id is empty or whitespace. Every SourceKey.Id must be a " +
                    "non-empty, non-whitespace identifier."));
        }

        if (!seenSourceIds.Add(keyLabel))
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.duplicate_key_id",
                    $"The signing key source reported duplicate source id '{keyLabel}'. " +
                    "Each SourceKey.Id must be unique among the keys reported by ReadAsync."));
        }

        if (!Enum.IsDefined(sourceKey.Algorithm))
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.undefined_algorithm",
                    $"Key '{keyLabel}' declares algorithm value {(int)sourceKey.Algorithm}, which is " +
                    $"not a defined {nameof(SigningAlgorithm)} member."));
        }

        // Every check below runs keyed on the operator's own source id — never on the derived kid,
        // which the operator has never typed and would not recognise in a configuration error.
        // Strength runs first: it is a property of the key alone (is this curve supported at all,
        // is this modulus big enough), so a globally-unsupported curve is reported as that rather
        // than as an algorithm/curve pairing mismatch — a property of the combination, checked next.
        SigningAlgorithms.ValidateKeyStrength(sourceKey.Algorithm, sourceKey.PublicKey, keyLabel);
        SigningAlgorithms.ValidateKeyAlgorithmCompatibility(sourceKey.Algorithm, sourceKey.PublicKey, keyLabel);

        // Imports the public material into the BCL's own cryptographic provider, rejecting
        // structural garbage (an off-curve EC point, a non-canonical RSA key) the checks above
        // cannot catch, and returns a canonical copy fully decoupled from whatever PublicKeyParameters
        // instance the source itself still holds a reference to.
        var canonicalPublicKey = SigningAlgorithms.ImportAndCanonicalize(sourceKey.PublicKey, keyLabel);
        var kid = DeriveKid(canonicalPublicKey);

        if (!seenKids.Add(kid))
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.duplicate_kid",
                    $"The signing key source reported duplicate kid '{kid}', derived from the public " +
                    $"key of source id '{keyLabel}'. Each key must have a unique, stable " +
                    "kid — check for two distinct source ids sharing the same public key."));
        }

        return new SigningKey(sourceKey.Id, kid, sourceKey.Algorithm, canonicalPublicKey, sourceKey.ExpiresAt);
    }

    /// <summary>
    /// Derives the <c>kid</c> via <see cref="JwkThumbprint"/>. <paramref name="publicKey"/> has
    /// already passed <see cref="SigningAlgorithms.ImportAndCanonicalize"/> by the time this runs, so
    /// its curve is always one <see cref="JwkThumbprint"/> accepts — the unsupported-curve branch is
    /// unreachable here, not a possible outcome this method needs to translate.
    /// </summary>
    private static string DeriveKid(PublicKeyParameters publicKey) =>
        publicKey.KeyType == SigningKeyType.Rsa
            ? JwkThumbprint.Compute(publicKey.RsaPublicParameters!.Value)
            : JwkThumbprint.Compute(publicKey.EcPublicParameters!.Value);
}
