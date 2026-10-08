namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Turns the keys a source lists into a <see cref="SigningKeyTimeline"/>: drops a key that is weak,
/// mismatched or malformed, rejects a list that is ambiguous, derives every <c>kid</c>, and orders the
/// keys oldest first.
/// </summary>
/// <remarks>
/// Every <c>kid</c> is derived from the key's own public material via <see cref="JwkThumbprint"/> —
/// a source cannot supply one. A problem with one key drops that key into
/// <see cref="SigningKeyTimeline.Dropped"/>, so a bad staged key cannot stop the keys around it; a
/// problem with the list itself throws <see cref="ZeeKayDaConfigurationException"/>. Which key signs
/// and which are published is the timeline's to decide, at each instant — including whether a
/// dropped key was the one due to sign, which the ring refuses at startup.
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
    /// them as a timeline, with any key whose own material or dates are unusable dropped.
    /// </summary>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown with failure code <c>signing.undefined_algorithm</c> when <paramref name="algorithm"/> is
    /// not a defined <see cref="SigningAlgorithm"/> member; <c>signing.no_keys</c> when <paramref name="keys"/>
    /// is empty; <c>signing.null_key</c> when it contains a <see langword="null"/>;
    /// <c>signing.empty_key_id</c> or <c>signing.duplicate_key_id</c> for a missing or repeated source id;
    /// <c>signing.undated_key</c> when one of two or more keys has no <see cref="SourceKey.NotBefore"/>;
    /// <c>signing.duplicate_kid</c> when two keys share public material; or, when every key was dropped,
    /// every dropped key's failure.
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
        var dropped = new List<DroppedKey>();

        foreach (var sourceKey in keys)
        {
            ValidateListing(sourceKey, keys.Count, seenSourceIds);

            if (TryBuildKey(sourceKey, algorithm, dropped) is not { } key)
                continue;

            if (!seenKids.Add(key.Kid))
            {
                throw new ZeeKayDaConfigurationException(
                    new ZeeKayDaConfigurationFailure(
                        "signing.duplicate_kid",
                        $"The signing key source reported duplicate kid '{key.Kid}', derived from the public " +
                        $"key of source id '{key.SourceId.Value}'. Each key must have a unique, stable " +
                        "kid — check for two distinct source ids sharing the same public key."));
            }

            built.Add(key);
        }

        if (built.Count == 0)
            throw new ZeeKayDaConfigurationException([.. dropped.Select(drop => drop.Failure)]);

        return new SigningKeyTimeline([.. built.Order(OldestFirst)], [.. dropped], options);
    }

    /// <summary>
    /// The problems that make the list itself ambiguous: a key that cannot be told apart from another,
    /// or an undated key, which has no place in the ordering and so can only stand alone.
    /// </summary>
    private static void ValidateListing(SourceKey? key, int keyCount, HashSet<string> seenSourceIds)
    {
        if (key is null)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.null_key",
                    "The signing key source listed a null key. Every element ReadAsync returns must be non-null."));
        }

        var keyLabel = key.Id.Value;

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

        if (key.NotBefore == DateTimeOffset.MinValue && keyCount > 1)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.undated_key",
                    $"Key '{keyLabel}' has no NotBefore date, but the source lists {keyCount} keys. " +
                    "When a source lists more than one key, every key must be dated so the newest can be found."));
        }
    }

    /// <summary>
    /// Builds <paramref name="sourceKey"/>, or adds it to <paramref name="dropped"/> with the first
    /// problem in its own dates or material and returns <see langword="null"/>.
    /// </summary>
    private static SigningKey? TryBuildKey(SourceKey sourceKey, SigningAlgorithm algorithm, List<DroppedKey> dropped)
    {
        try
        {
            ValidateValidityWindow(sourceKey);

            // Strength first: an unsupported curve is reported as that, not as a curve/algorithm mismatch.
            ValidateKeyStrength(sourceKey);
            ValidateKeyAlgorithmCompatibility(sourceKey, algorithm);

            var canonicalPublicKey = ImportAndCanonicalize(sourceKey);
            return new SigningKey(
                sourceKey.Id, DeriveKid(canonicalPublicKey), algorithm, canonicalPublicKey, sourceKey.NotBefore, sourceKey.ExpiresAt);
        }
        catch (ZeeKayDaConfigurationException ex)
        {
            dropped.Add(new DroppedKey(sourceKey, ex.AggregatedFailures[0]));
            return null;
        }
    }

    private static void ValidateValidityWindow(SourceKey key)
    {
        if (key.NotBefore >= key.ExpiresAt)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.invalid_validity_window",
                    $"Key '{key.Id.Value}' expires at {key.ExpiresAt:O}, which is not after its NotBefore {key.NotBefore:O}."));
        }
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
