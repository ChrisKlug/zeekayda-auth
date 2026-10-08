namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Turns the keys a source lists into a <see cref="SigningKeyTimeline"/>: rejects a weak, mismatched
/// or ambiguously identified key, derives every <c>kid</c>, and orders the keys oldest first.
/// </summary>
/// <remarks>
/// Every <c>kid</c> is derived from the key's own public material via <see cref="JwkThumbprint"/> —
/// a source cannot supply one. Every rejection throws <see cref="ZeeKayDaConfigurationException"/>.
/// Which key signs and which are published is the timeline's to decide, at each instant.
/// </remarks>
internal static partial class SigningKeySetBuilder
{
    /// <summary>
    /// The order that decides which key is newer: a later <see cref="SigningKey.NotBefore"/>, then on
    /// equal dates the ordinally greater source id.
    /// </summary>
    internal static readonly IComparer<SigningKey> OldestFirst = Comparer<SigningKey>.Create((x, y) =>
    {
        var byDate = x.NotBefore.CompareTo(y.NotBefore);
        return byDate != 0 ? byDate : string.CompareOrdinal(x.SourceId.Value, y.SourceId.Value);
    });

    /// <summary>
    /// Validates every key in <paramref name="keys"/> against <paramref name="algorithm"/> and returns
    /// them as a timeline.
    /// </summary>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown with failure code <c>signing.undefined_algorithm</c> when <paramref name="algorithm"/> is
    /// not a defined <see cref="SigningAlgorithm"/> member; <c>signing.no_keys</c> when <paramref name="keys"/> is empty;
    /// <c>signing.null_key</c> when it contains a <see langword="null"/>;
    /// <c>signing.undated_key</c> when one of two or more keys has no <see cref="SourceKey.NotBefore"/>;
    /// <c>signing.invalid_validity_window</c> when a key expires before it becomes valid; or any
    /// per-key code from validation (<c>signing.empty_key_id</c>, <c>signing.duplicate_key_id</c>,
    /// <c>signing.key_algorithm_mismatch</c>,
    /// <c>signing.ec_curve_algorithm_mismatch</c>, <c>signing.rsa_key_too_small</c>,
    /// <c>signing.ec_unsupported_curve</c>, <c>signing.invalid_public_key</c>,
    /// <c>signing.duplicate_kid</c>).
    /// </exception>
    internal static SigningKeyTimeline Build(
        IReadOnlyList<SourceKey> keys, SigningAlgorithm algorithm, SigningKeyOptions options)
    {
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(options);

        if (!Enum.IsDefined(algorithm))
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.undefined_algorithm",
                    $"The signing key source declares algorithm value {(int)algorithm}, which is not a " +
                    $"defined {nameof(SigningAlgorithm)} member."));
        }

        return new SigningKeyTimeline([.. BuildAll(keys, algorithm).Order(OldestFirst)], options);
    }

    private static List<SigningKey> BuildAll(IReadOnlyList<SourceKey> keys, SigningAlgorithm algorithm)
    {
        if (keys.Count == 0)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.no_keys",
                    "The signing key source listed no keys. ReadAsync must list at least one key."));
        }

        var seenSourceIds = new HashSet<string>(StringComparer.Ordinal);
        var seenKids = new HashSet<string>(StringComparer.Ordinal);
        var built = new List<SigningKey>(keys.Count);

        foreach (var sourceKey in keys)
        {
            if (sourceKey is null)
            {
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.null_key",
                        "The signing key source listed a null key. Every element ReadAsync returns must be non-null."));
            }

            ValidateDates(sourceKey, keys.Count);
            built.Add(BuildAndValidate(sourceKey, algorithm, seenSourceIds, seenKids));
        }

        return built;
    }

    /// <summary>
    /// An undated key has no place in the ordering, so it can only stand alone.
    /// </summary>
    private static void ValidateDates(SourceKey key, int keyCount)
    {
        if (key.NotBefore == DateTimeOffset.MinValue && keyCount > 1)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.undated_key",
                    $"Key '{key.Id.Value}' has no NotBefore date, but the source lists {keyCount} keys. " +
                    "When a source lists more than one key, every key must be dated so the newest can be found."));
        }

        if (key.NotBefore >= key.ExpiresAt)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.invalid_validity_window",
                    $"Key '{key.Id.Value}' expires at {key.ExpiresAt:O}, which is not after its NotBefore {key.NotBefore:O}."));
        }
    }

    private static SigningKey BuildAndValidate(
        SourceKey sourceKey, SigningAlgorithm algorithm, HashSet<string> seenSourceIds, HashSet<string> seenKids)
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

        // Strength first: an unsupported curve is reported as that, not as a curve/algorithm mismatch.
        ValidateKeyStrength(sourceKey);
        ValidateKeyAlgorithmCompatibility(sourceKey, algorithm);

        var canonicalPublicKey = ImportAndCanonicalize(sourceKey);
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

        return new SigningKey(
            sourceKey.Id, kid, algorithm, canonicalPublicKey, sourceKey.NotBefore, sourceKey.ExpiresAt);
    }

    /// <summary>
    /// <paramref name="publicKey"/> has already passed <see cref="ImportAndCanonicalize"/>, so its
    /// curve is always one <see cref="JwkThumbprint"/> accepts.
    /// </summary>
    private static string DeriveKid(PublicKeyParameters publicKey) =>
        publicKey.KeyType == SigningKeyType.Rsa
            ? JwkThumbprint.Compute(publicKey.RsaPublicParameters!.Value)
            : JwkThumbprint.Compute(publicKey.EcPublicParameters!.Value);
}
