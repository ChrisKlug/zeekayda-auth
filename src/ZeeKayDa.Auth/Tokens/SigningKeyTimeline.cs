using System.Collections.Immutable;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The validated keys a source listed, and the rules that decide from their dates alone which key
/// signs and which keys are published at any instant.
/// </summary>
/// <remarks>
/// <para>
/// The newest unexpired key whose <see cref="SigningKey.NotBefore"/> is at least
/// <see cref="SigningKeyOptions.LeadTime"/> ago signs. When none is, the oldest unexpired key signs:
/// a first deployment and an emergency replacement alike. When every key has expired, the last to
/// expire keeps signing, and the health check reports it.
/// <see cref="SigningKey.NotBefore"/> orders the keys and starts the lead-time clock — it is not a
/// validity gate, since no relying party can observe it (RFC 7517 §4 has no date member).
/// </para>
/// <para>
/// Every unexpired key is published, except that an older key drops once a newer key is
/// <see cref="SigningKeyOptions.LeadTime"/> plus <see cref="SigningKeyOptions.RetainRetiredKeysFor"/>
/// old: the newer key took over at its lead time, so the older key's last token expired by then. An
/// expired key stays published until <see cref="SigningKeyOptions.RetainRetiredKeysFor"/> after it
/// expired. The signing key is always published.
/// </para>
/// <para>
/// A key in <see cref="SetAside"/> never signs but is otherwise treated as listed: it is published,
/// and it supersedes older keys on its ordinary schedule, exactly as on a replica whose handover to
/// it succeeded. The key signing on in its place stays published here only because it signs; once
/// the other replicas drop it, their key sets no longer verify its tokens.
/// </para>
/// </remarks>
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

    /// <summary>
    /// Gets the keys whose signer failed to open or self-test when they were due to sign, in the
    /// order they failed. They stay published but never sign.
    /// </summary>
    internal ImmutableList<SigningKey> SetAside { get; }

    /// <summary>
    /// Gets the listed keys whose own dates or material were unusable. They are neither published nor
    /// ever sign; the rules carry on with the keys around them.
    /// </summary>
    internal ImmutableArray<DroppedKey> Dropped { get; }

    /// <summary>Gets the keys the source listed more than once, each under every source id that listed it.</summary>
    internal ImmutableArray<MergedKey> Merged { get; }

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

    /// <summary>
    /// Whether <paramref name="key"/> is published at <paramref name="now"/> only because it signs:
    /// every replica whose handover succeeded has dropped it, so they no longer verify its tokens.
    /// </summary>
    internal bool IsPublishedOnlyBecauseItSigns(SigningKey key, DateTimeOffset now)
    {
        // Compared by kid: the caller's instance need not be this timeline's own.
        var listed = _oldestFirst.FirstOrDefault(k => k.Kid == key.Kid) ?? key;
        return !IsKept(listed, now, KeptUnexpired([.. _oldestFirst.Where(k => k.ExpiresAt > now)], now));
    }

    /// <summary>
    /// The unexpired keys still published: all but those older than the newest key that is
    /// <see cref="SigningKeyOptions.LeadTime"/> plus <see cref="SigningKeyOptions.RetainRetiredKeysFor"/> old.
    /// </summary>
    private HashSet<SigningKey> KeptUnexpired(List<SigningKey> unexpired, DateTimeOffset now)
    {
        var supersededAfter = TokenLifetimes.Sum(_leadTime, _retention);
        var newestEstablished = unexpired.FindLastIndex(key => now - key.NotBefore >= supersededAfter);
        return unexpired.Skip(Math.Max(newestEstablished, 0)).ToHashSet();
    }

    private bool IsKept(SigningKey key, DateTimeOffset now, HashSet<SigningKey> keptUnexpired) =>
        keptUnexpired.Contains(key) || (key.ExpiresAt <= now && now - key.ExpiresAt < _retention);

    /// <summary>
    /// The same keys with the one whose <see cref="SigningKey.Kid"/> is <paramref name="kid"/> set
    /// aside: it never signs, so the rules carry on with the keys around it. Or <see langword="null"/>
    /// when no other key could sign.
    /// </summary>
    internal SigningKeyTimeline? SettingAside(string kid)
    {
        if (_oldestFirst.All(key => key.Kid == kid || SetAside.Contains(key)))
            return null;

        return new(this, SetAside.Add(_oldestFirst.Single(key => key.Kid == kid)));
    }

    /// <summary>
    /// Whether <paramref name="key"/>, set aside, must stay set aside however healthy its signer
    /// becomes: by now the key it would replace is superseded, and may no longer be published where
    /// tokens it signed are verified.
    /// </summary>
    internal bool IsTooLateToTakeOver(SigningKey key, DateTimeOffset now) =>
        now - key.NotBefore >= TokenLifetimes.Sum(_leadTime, _retention);

    /// <summary>
    /// Whether <paramref name="key"/> has been published for the lead time at <paramref name="now"/>;
    /// a signing key that has not been may produce tokens a relying party with a cached key set rejects.
    /// </summary>
    internal bool IsEstablished(SigningKey key, DateTimeOffset now) => now - key.NotBefore >= _leadTime;

    /// <summary>
    /// The dropped key the rules would have chosen to sign at <paramref name="now"/> had it been
    /// usable, or <see langword="null"/> when the key due now is a usable one. Startup refuses the
    /// first; a running ring skips it and the key before it signs on.
    /// </summary>
    internal DroppedKey? DroppedKeyDueAt(DateTimeOffset now)
    {
        var listed = _oldestFirst
            .Select(key => new ListedKey(key.NotBefore, key.ExpiresAt, key.SourceId.Value, Dropped: null))
            .Concat(Dropped.Select(drop => new ListedKey(drop.Key.NotBefore, drop.Key.ExpiresAt, drop.Key.Id.Value, drop)))
            .Where(key => key.ExpiresAt > now)
            .OrderBy(key => key.NotBefore)
            .ThenBy(key => key.Id, StringComparer.Ordinal)
            .ToList();

        var due = listed.FindLastIndex(key => now - key.NotBefore >= _leadTime);
        return listed.Count == 0 ? null : listed[Math.Max(due, 0)].Dropped;
    }

    /// <summary>
    /// When dropping keys left the usable keys expiring before the listed keys would have, the instant
    /// the last usable key expires; otherwise <see langword="null"/>.
    /// </summary>
    internal DateTimeOffset? CoverageCutShortTo()
    {
        if (Dropped.IsEmpty)
            return null;

        var usableUntil = _oldestFirst.Max(key => key.ExpiresAt);
        return Dropped.Max(drop => drop.Key.ExpiresAt) > usableUntil ? usableUntil : null;
    }

    /// <summary>
    /// The first instant after <paramref name="now"/> at which <see cref="At"/> may return a
    /// different set, or <see cref="DateTimeOffset.MaxValue"/> when none will come.
    /// </summary>
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
