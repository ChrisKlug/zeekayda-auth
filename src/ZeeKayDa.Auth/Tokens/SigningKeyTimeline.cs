using System.Collections.Immutable;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>The validated keys a source listed, and the date rules that pick the signing and published keys at any instant.</summary>
internal sealed class SigningKeyTimeline
{
    private readonly ImmutableArray<SigningKey> _oldestFirst;
    private readonly SigningAlgorithm _algorithm;
    private readonly TimeSpan _leadTime;
    private readonly TimeSpan _retention;

    /// <param name="oldestFirst">Validated keys in <see cref="SigningKeySetBuilder.OldestFirst"/> order; never empty.</param>
    /// <param name="dropped">The listed keys whose own dates or material were unusable.</param>
    /// <param name="merged">The keys of <paramref name="oldestFirst"/> the source listed more than once.</param>
    /// <param name="algorithm">The algorithm every key signs under.</param>
    /// <param name="options">The lead time and the resolved retention.</param>
    internal SigningKeyTimeline(
        ImmutableArray<SigningKey> oldestFirst,
        ImmutableArray<DroppedKey> dropped,
        ImmutableArray<MergedKey> merged,
        SigningAlgorithm algorithm,
        SigningKeyOptions options)
    {
        _oldestFirst = oldestFirst;
        Dropped = dropped;
        Merged = merged;
        _algorithm = algorithm;
        _leadTime = options.LeadTime;
        _retention = options.RetainRetiredKeysFor
            ?? throw new InvalidOperationException(
                $"{nameof(SigningKeyOptions.RetainRetiredKeysFor)} is resolved when the options are configured.");
        SetAside = [];
    }

    /// <summary>The keys of <paramref name="listed"/>, with <paramref name="setAside"/> set aside.</summary>
    private SigningKeyTimeline(SigningKeyTimeline listed, ImmutableList<SigningKey> setAside)
    {
        _oldestFirst = listed._oldestFirst;
        Dropped = listed.Dropped;
        Merged = listed.Merged;
        _algorithm = listed._algorithm;
        _leadTime = listed._leadTime;
        _retention = listed._retention;
        SetAside = setAside;
    }

    /// <summary>Gets how long a key is published before it may sign.</summary>
    internal TimeSpan LeadTime => _leadTime;

    /// <summary>Gets every listed key that was not dropped, oldest first.</summary>
    internal ImmutableArray<SigningKey> Keys => _oldestFirst;

    /// <summary>Keys whose signer failed when due, in failure order; published but never signing.</summary>
    internal ImmutableList<SigningKey> SetAside { get; }

    /// <summary>Listed keys with unusable dates or material, and failures the source reported; neither published nor signing.</summary>
    internal ImmutableArray<DroppedKey> Dropped { get; }

    /// <summary>Gets the keys the source listed more than once, each under every source id that listed it.</summary>
    internal ImmutableArray<MergedKey> Merged { get; }

    /// <summary>Every source id listing <paramref name="key"/>'s key pair.</summary>
    internal IEnumerable<SourceKeyId> SourceIdsOf(SigningKey key) =>
        Merged.FirstOrDefault(merged => merged.Key.Kid == key.Kid)?.SourceIds ?? [key.SourceId];

    /// <summary>The key set in force at <paramref name="now"/>.</summary>
    internal SigningKeySet At(DateTimeOffset now)
    {
        var unexpired = _oldestFirst.Where(key => key.ExpiresAt > now).ToList();
        var signingKey = ChooseSigningKey(unexpired, now);
        var keptUnexpired = KeptUnexpired(unexpired, now);

        ImmutableArray<SigningKey> published =
        [
            .. _oldestFirst.Where(key => key == signingKey || IsKept(key, now, keptUnexpired)),
        ];

        return new SigningKeySet(_algorithm, signingKey, published);
    }

    /// <summary>The key that signs at <paramref name="now"/>.</summary>
    internal SigningKey SigningKeyAt(DateTimeOffset now) =>
        ChooseSigningKey([.. _oldestFirst.Where(key => key.ExpiresAt > now)], now);

    /// <summary>Whether <paramref name="key"/> is published only because it signs, so other replicas no longer verify its tokens.</summary>
    internal bool IsPublishedOnlyBecauseItSigns(SigningKey key, DateTimeOffset now)
    {
        // Compared by kid: the caller's instance need not be this timeline's own.
        var listed = _oldestFirst.FirstOrDefault(k => k.Kid == key.Kid) ?? key;
        return !IsKept(listed, now, KeptUnexpired([.. _oldestFirst.Where(k => k.ExpiresAt > now)], now));
    }

    /// <summary>The unexpired keys still published: all but those older than the newest one past lead time plus retention.</summary>
    private HashSet<SigningKey> KeptUnexpired(List<SigningKey> unexpired, DateTimeOffset now)
    {
        var supersededAfter = TokenLifetimes.Sum(_leadTime, _retention);
        var newestEstablished = unexpired.FindLastIndex(key => now - key.NotBefore >= supersededAfter);
        return unexpired.Skip(Math.Max(newestEstablished, 0)).ToHashSet();
    }

    private bool IsKept(SigningKey key, DateTimeOffset now, HashSet<SigningKey> keptUnexpired) =>
        keptUnexpired.Contains(key) || (key.ExpiresAt <= now && now - key.ExpiresAt < _retention);

    /// <summary>The same keys with <paramref name="kid"/> set aside, or <see langword="null"/> when no other key could sign.</summary>
    internal SigningKeyTimeline? SettingAside(string kid)
    {
        if (_oldestFirst.All(key => key.Kid == kid || SetAside.Contains(key)))
            return null;

        return new(this, SetAside.Add(_oldestFirst.Single(key => key.Kid == kid)));
    }

    /// <summary>Whether set-aside <paramref name="key"/> must stay aside: the key it would replace is already superseded.</summary>
    internal bool IsTooLateToTakeOver(SigningKey key, DateTimeOffset now) =>
        now - key.NotBefore >= TokenLifetimes.Sum(_leadTime, _retention);

    /// <summary>Whether <paramref name="key"/> has been published for the lead time at <paramref name="now"/>.</summary>
    internal bool IsEstablished(SigningKey key, DateTimeOffset now) => now - key.NotBefore >= _leadTime;

    /// <summary>
    /// The dropped key the rules would have chosen to sign at <paramref name="now"/>, or <see langword="null"/>
    /// when the key due is usable. A failure the source reported has no dates, so is never due.
    /// </summary>
    internal DroppedKey? DroppedKeyDueAt(DateTimeOffset now)
    {
        var listed = _oldestFirst
            .Select(key => new ListedKey(key.NotBefore, key.ExpiresAt, key.SourceId.Value, Dropped: null))
            .Concat(DatedDrops())
            .Where(key => key.ExpiresAt > now)
            .OrderBy(key => key.NotBefore)
            .ThenBy(key => key.Id, StringComparer.Ordinal)
            .ToList();

        var due = listed.FindLastIndex(key => now - key.NotBefore >= _leadTime);
        return listed.Count == 0 ? null : listed[Math.Max(due, 0)].Dropped;
    }

    /// <summary>The instant the last usable key expires, when dropped keys would have covered longer; else <see langword="null"/>.</summary>
    internal DateTimeOffset? CoverageCutShortTo()
    {
        var droppedExpiries = Dropped.Select(drop => drop.Dates?.ExpiresAt).OfType<DateTimeOffset>().ToList();
        if (droppedExpiries.Count == 0)
            return null;

        var usableUntil = _oldestFirst.Max(key => key.ExpiresAt);
        return droppedExpiries.Max() > usableUntil ? usableUntil : null;
    }

    /// <summary>The first instant after <paramref name="now"/> at which <see cref="At"/> may change, or <see cref="DateTimeOffset.MaxValue"/>.</summary>
    internal DateTimeOffset NextChangeAfter(DateTimeOffset now)
    {
        var supersededAfter = TokenLifetimes.Sum(_leadTime, _retention);

        return _oldestFirst
            .SelectMany(key => new[]
            {
                TokenLifetimes.ExpiresAt(key.NotBefore, _leadTime),
                TokenLifetimes.ExpiresAt(key.NotBefore, supersededAfter),
                key.ExpiresAt,
                TokenLifetimes.ExpiresAt(key.ExpiresAt, _retention),
            })
            .Where(instant => instant > now)
            .DefaultIfEmpty(DateTimeOffset.MaxValue)
            .Min();
    }

    private IEnumerable<ListedKey> DatedDrops() =>
        from drop in Dropped
        let dates = drop.Dates
        where dates.HasValue
        select new ListedKey(dates.Value.NotBefore, dates.Value.ExpiresAt, drop.Id.Value, drop);

    /// <summary>A listed key's dates and source id, and the drop record when it was unusable.</summary>
    private readonly record struct ListedKey(
        DateTimeOffset NotBefore, DateTimeOffset ExpiresAt, string Id, DroppedKey? Dropped);

    private SigningKey ChooseSigningKey(List<SigningKey> unexpired, DateTimeOffset now)
    {
        var eligible = unexpired.Where(key => !SetAside.Contains(key)).ToList();
        return eligible.LastOrDefault(key => IsEstablished(key, now))
            ?? eligible.FirstOrDefault()
            ?? _oldestFirst.Where(key => !SetAside.Contains(key))
                .Aggregate((last, key) => key.ExpiresAt >= last.ExpiresAt ? key : last);
    }
}
