namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Turns what a source lists into a <see cref="SigningKeyTimeline"/>: drops a key that is weak,
/// mismatched or malformed, rejects a list that is ambiguous, derives every <c>kid</c>, builds the
/// entries listing one key pair into one key, and orders the keys oldest first.
/// </summary>
/// <remarks>
/// Every <c>kid</c> is derived from the key's own public material via <see cref="JwkThumbprint"/> —
/// a source cannot supply one. A problem with one key drops that key into
/// <see cref="SigningKeyTimeline.Dropped"/>, alongside every entry the source reported as a failure,
/// so a bad staged key cannot stop the keys around it; a problem with the list itself throws
/// <see cref="ZeeKayDaConfigurationException"/>. Which key signs
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
    /// Validates every key in <paramref name="listing"/> against <paramref name="algorithm"/> and returns
    /// them as a timeline, with any key whose own material or dates are unusable dropped alongside the
    /// entries the source reported as failures, and the entries listing one key pair built into one key.
    /// </summary>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown with failure code <c>signing.undefined_algorithm</c> when <paramref name="algorithm"/> is
    /// not a defined <see cref="SigningAlgorithm"/> member; <c>signing.no_keys</c> when <paramref name="listing"/>
    /// holds neither keys nor failures; <c>signing.null_key</c> or <c>signing.null_failure</c> when it
    /// contains a <see langword="null"/>;
    /// <c>signing.empty_key_id</c> or <c>signing.duplicate_key_id</c> for a missing or repeated source id,
    /// among keys and failures alike;
    /// <c>signing.undated_key</c> when one of two or more keys has no <see cref="SourceKey.NotBefore"/>;
    /// or, when no key is usable, every dropped key's and every reported failure's failure.
    /// </exception>
    internal static SigningKeyTimeline Build(
        SourceKeyListing listing, SigningAlgorithm algorithm, SigningKeyOptions options)
    {
        ArgumentNullException.ThrowIfNull(listing);
        ArgumentNullException.ThrowIfNull(options);
        var keys = listing.Keys;
        ValidateSource(listing, algorithm);

        var seenSourceIds = new HashSet<string>(StringComparer.Ordinal);
        var usable = new List<SigningKey>(keys.Count);
        var dropped = new List<DroppedKey>();

        foreach (var sourceKey in keys)
        {
            ValidateListing(sourceKey, keys.Count, seenSourceIds);

            if (TryBuildKey(sourceKey, algorithm, dropped) is { } key)
                usable.Add(key);
        }

        foreach (var failure in listing.Failures)
        {
            ValidateFailure(failure, seenSourceIds);
            dropped.Add(new DroppedKey(failure.Id, Key: null, failure.Failure));
        }

        if (usable.Count == 0)
            throw new ZeeKayDaConfigurationException([.. dropped.Select(drop => drop.Failure)]);

        var keyPairs = usable.GroupBy(key => key.Kid, StringComparer.Ordinal).Select(entries => Merge([.. entries])).ToList();
        return new SigningKeyTimeline(
            [.. keyPairs.Select(keyPair => keyPair.Key).Order(OldestFirst)],
            [.. dropped],
            [.. keyPairs.Where(keyPair => keyPair.SourceIds.Length > 1)],
            algorithm,
            options);
    }

    private static void ValidateSource(SourceKeyListing listing, SigningAlgorithm algorithm)
    {
        if (!Enum.IsDefined(algorithm))
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.undefined_algorithm",
                    $"The signing key source declares algorithm value {(int)algorithm}, which is not a " +
                    $"defined {nameof(SigningAlgorithm)} member."));
        }

        if (listing.Keys.Count == 0 && listing.Failures.Count == 0)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.no_keys",
                    "The signing key source listed no keys. ReadAsync must list at least one key."));
        }
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
        ValidateSourceId(keyLabel, seenSourceIds);

        if (key.NotBefore == DateTimeOffset.MinValue && keyCount > 1)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.undated_key",
                    $"Key '{keyLabel}' has no NotBefore date, but the source lists {keyCount} keys. " +
                    "When a source lists more than one key, every key must be dated so the newest can be found."));
        }
    }

    private static void ValidateFailure(SourceKeyFailure? failure, HashSet<string> seenSourceIds)
    {
        if (failure?.Failure is null)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.null_failure",
                    "The signing key source reported a null failure. Every SourceKeyFailure ReadAsync " +
                    "returns, and its Failure, must be non-null."));
        }

        ValidateSourceId(failure.Id.Value, seenSourceIds);
    }

    private static void ValidateSourceId(string? sourceId, HashSet<string> seenSourceIds)
    {
        if (string.IsNullOrWhiteSpace(sourceId))
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.empty_key_id",
                    "A signing key source id is empty or whitespace. Every SourceKey.Id and " +
                    "SourceKeyFailure.Id must be a non-empty, non-whitespace identifier."));
        }

        if (!seenSourceIds.Add(sourceId))
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.duplicate_key_id",
                    $"The signing key source reported duplicate source id '{sourceId}'. Each source id " +
                    "must be unique among the keys and failures reported by ReadAsync."));
        }
    }

    /// <summary>
    /// Builds <paramref name="sourceKey"/>, or adds it to <paramref name="dropped"/> with the first
    /// problem in its material or dates and returns <see langword="null"/>.
    /// </summary>
    private static SigningKey? TryBuildKey(SourceKey sourceKey, SigningAlgorithm algorithm, List<DroppedKey> dropped)
    {
        try
        {
            // Strength first: an unsupported curve is reported as that, not as a curve/algorithm mismatch.
            ValidateKeyStrength(sourceKey);
            ValidateKeyAlgorithmCompatibility(sourceKey, algorithm);

            var canonicalPublicKey = ImportAndCanonicalize(sourceKey);
            ValidateValidityWindow(sourceKey);
            return new SigningKey(
                sourceKey.Id, DeriveKid(canonicalPublicKey), algorithm, canonicalPublicKey, sourceKey.NotBefore, sourceKey.ExpiresAt);
        }
        catch (ZeeKayDaConfigurationException ex)
        {
            dropped.Add(new DroppedKey(sourceKey.Id, sourceKey, ex.AggregatedFailures[0]));
            return null;
        }
    }

    private static void ValidateValidityWindow(SourceKey key)
    {
        if (key.NotBefore < key.ExpiresAt)
            return;

        throw new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure(
                "signing.invalid_validity_window",
                $"Key '{key.Id.Value}' expires at {key.ExpiresAt:O}, which is not after its NotBefore {key.NotBefore:O}."));
    }

    /// <summary>
    /// The entries listing one key pair as one key, published from the first's NotBefore to the last's
    /// expiry. It opens through the entry that expires last, ties to the ordinally greater source id:
    /// that certificate is the one still valid at the end.
    /// </summary>
    private static MergedKey Merge(IReadOnlyList<SigningKey> entries)
    {
        var lastToExpire = entries
            .OrderBy(entry => entry.ExpiresAt)
            .ThenBy(entry => entry.SourceId.Value, StringComparer.Ordinal)
            .Last();

        var key = new SigningKey(
            lastToExpire.SourceId,
            lastToExpire.Kid,
            lastToExpire.Algorithm,
            lastToExpire.PublicKey,
            entries.Min(entry => entry.NotBefore),
            lastToExpire.ExpiresAt);

        return new MergedKey(key, [.. entries.Select(entry => entry.SourceId).OrderBy(id => id.Value, StringComparer.Ordinal)]);
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
