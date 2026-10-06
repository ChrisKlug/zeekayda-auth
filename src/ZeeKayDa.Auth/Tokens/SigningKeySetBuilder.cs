using System.Collections.Immutable;
using Microsoft.Extensions.Logging;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Builds a <see cref="SigningKeySet"/> from the keys a source lists: rejects a weak, mismatched or
/// ambiguously identified key, then decides from the dates alone which key signs and which keys are
/// published.
/// </summary>
/// <remarks>
/// <para>
/// The newest valid key published for at least <see cref="SigningKeyOptions.LeadTime"/> signs. When
/// no key has been, the oldest valid key signs and a Warning is logged. "Newer" means a later
/// <see cref="SourceKey.NotBefore"/>; on equal dates, the ordinally greater source id.
/// </para>
/// <para>
/// Retention keeps every key that may have signed a token still in force. The ring reads keys only
/// at startup, so a successor takes over at the first restart after its lead time, not at the
/// instant the lead time ends: the signing key's predecessor therefore stays published for as long
/// as the signing key signs. An older key stays published until a newer key is
/// <see cref="SigningKeyOptions.LeadTime"/> plus <see cref="SigningKeyOptions.RetainRetiredKeysFor"/>
/// old, and an expired key until <see cref="SigningKeyOptions.RetainRetiredKeysFor"/> after it expired.
/// </para>
/// <para>
/// Every <c>kid</c> is derived from the key's own public material via <see cref="JwkThumbprint"/> —
/// a source cannot supply one. Every rejection throws <see cref="ZeeKayDaConfigurationException"/>.
/// </para>
/// </remarks>
internal static partial class SigningKeySetBuilder
{
    // No relying party can observe a key's NotBefore — it is not a JWK member (RFC 7517 §4) — so
    // signing a few minutes early is harmless, while a host clock trailing the machine that minted
    // the credential would otherwise fail startup. The expiry end has real observers and stays exact.
    private static readonly TimeSpan NotBeforeGrace = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Validates every key in <paramref name="keys"/> and builds the key set in force at
    /// <paramref name="now"/>.
    /// </summary>
    /// <exception cref="ZeeKayDaConfigurationException">
    /// Thrown with failure code <c>signing.no_keys</c> when <paramref name="keys"/> is empty;
    /// <c>signing.null_key</c> when it contains a <see langword="null"/>;
    /// <c>signing.undated_key</c> when one of two or more keys has no <see cref="SourceKey.NotBefore"/>;
    /// <c>signing.invalid_validity_window</c> when a key expires before it becomes valid;
    /// <c>signing.signing_key_not_yet_valid</c> or <c>signing.signing_key_expired</c> when no key is
    /// valid at <paramref name="now"/>; or any per-key code from validation
    /// (<c>signing.empty_key_id</c>, <c>signing.duplicate_key_id</c>, <c>signing.undefined_algorithm</c>,
    /// <c>signing.key_algorithm_mismatch</c>, <c>signing.ec_curve_algorithm_mismatch</c>,
    /// <c>signing.rsa_key_too_small</c>, <c>signing.ec_unsupported_curve</c>,
    /// <c>signing.invalid_public_key</c>, <c>signing.duplicate_kid</c>).
    /// </exception>
    internal static SigningKeySet Build(
        IReadOnlyList<SourceKey> keys, DateTimeOffset now, SigningKeyOptions options, ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);

        var oldestFirst = BuildAll(keys)
            .OrderBy(key => key.NotBefore)
            .ThenBy(key => key.SourceId.Value, StringComparer.Ordinal)
            .ToList();

        var signingKey = ChooseSigningKey(oldestFirst, now, options, logger);
        var published = WithoutRetiredKeys(oldestFirst, signingKey, now, options);
        var advertisedAlgorithms = published
            .Select(k => k.Algorithm)
            .Distinct()
            .OrderBy(a => a)
            .ToImmutableArray();

        return new SigningKeySet(signingKey, published, advertisedAlgorithms);
    }

    private static List<SigningKey> BuildAll(IReadOnlyList<SourceKey> keys)
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
            built.Add(BuildAndValidate(sourceKey, seenSourceIds, seenKids));
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

    private static SigningKey ChooseSigningKey(
        List<SigningKey> oldestFirst, DateTimeOffset now, SigningKeyOptions options, ILogger logger)
    {
        // Written as a difference rather than `NotBefore - grace`, which underflows for an undated key.
        var valid = oldestFirst.Where(key => key.NotBefore - now <= NotBeforeGrace && key.ExpiresAt > now).ToList();
        if (valid.Count == 0)
            throw NoValidKey(oldestFirst, now);

        var newestReady = valid.LastOrDefault(key => now - key.NotBefore >= options.LeadTime);
        if (newestReady is not null)
            return newestReady;

        var oldest = valid[0];
        logger.LogWarning(
            "Signing with key {Kid} ({SourceKeyId}), published less than the lead time of {LeadTime} ago. " +
            "Relying parties with a cached key set may reject its tokens until they refresh.",
            oldest.Kid, oldest.SourceId.Value, options.LeadTime);
        return oldest;
    }

    private static ZeeKayDaConfigurationException NoValidKey(List<SigningKey> oldestFirst, DateTimeOffset now)
    {
        var unexpired = oldestFirst.Where(key => key.ExpiresAt > now).ToList();
        if (unexpired.Count == 0)
        {
            var last = oldestFirst.MaxBy(key => key.ExpiresAt)!;
            return new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.signing_key_expired",
                    $"Every listed signing key has expired; the last, '{last.SourceId.Value}', expired at {last.ExpiresAt:O}. " +
                    "An expired key issues tokens no relying party will accept."));
        }

        var earliest = unexpired[0];
        return new ZeeKayDaConfigurationException(
            new ZeeKayDaConfigurationFailure(
                "signing.signing_key_not_yet_valid",
                $"No listed signing key is valid yet; the earliest, '{earliest.SourceId.Value}', is valid from " +
                $"{earliest.NotBefore:O}. Keep the key it replaces listed until then."));
    }

    /// <summary>
    /// Drops a key only once no token it signed can still be in force: it expired more than the
    /// retention ago, or it is older than the signing key's predecessor and a newer key is past the
    /// lead time plus the retention.
    /// </summary>
    private static ImmutableArray<SigningKey> WithoutRetiredKeys(
        List<SigningKey> oldestFirst, SigningKey signingKey, DateTimeOffset now, SigningKeyOptions options)
    {
        var retention = options.RetainRetiredKeysFor
            ?? throw new InvalidOperationException(
                $"{nameof(SigningKeyOptions.RetainRetiredKeysFor)} is resolved when the options are configured.");
        var supersededAfter = TokenLifetimes.Sum(options.LeadTime, retention);

        // A key that expired more than the retention ago is gone first, so it can never stand in for
        // the signing key's predecessor.
        var live = oldestFirst.Where(key => key == signingKey || now - key.ExpiresAt < retention).ToList();
        var predecessor = live.IndexOf(signingKey) - 1;
        var newestEstablished = live.FindLastIndex(key => now - key.NotBefore >= supersededAfter);
        var firstKept = Math.Min(predecessor, newestEstablished);

        return [.. live.Skip(Math.Max(firstKept, 0))];
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

        // Strength first: an unsupported curve is reported as that, not as a curve/algorithm mismatch.
        ValidateKeyStrength(sourceKey);
        ValidateKeyAlgorithmCompatibility(sourceKey);

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
            sourceKey.Id, kid, sourceKey.Algorithm, canonicalPublicKey, sourceKey.NotBefore, sourceKey.ExpiresAt);
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
