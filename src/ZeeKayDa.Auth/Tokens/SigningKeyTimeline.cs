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
/// expire keeps signing; startup refuses that state and the health check reports it.
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
/// it succeeded — so every replica publishes the same set.
/// </para>
/// </remarks>
internal sealed class SigningKeyTimeline
{
    private readonly ImmutableArray<SigningKey> _oldestFirst;
    private readonly TimeSpan _leadTime;
    private readonly TimeSpan _retention;

    /// <param name="oldestFirst">Validated keys in <see cref="SigningKeySetBuilder.OldestFirst"/> order; never empty.</param>
    /// <param name="options">The lead time and the resolved retention.</param>
    internal SigningKeyTimeline(ImmutableArray<SigningKey> oldestFirst, SigningKeyOptions options)
        : this(
            oldestFirst,
            options.LeadTime,
            options.RetainRetiredKeysFor
                ?? throw new InvalidOperationException(
                    $"{nameof(SigningKeyOptions.RetainRetiredKeysFor)} is resolved when the options are configured."),
            [])
    {
    }

    private SigningKeyTimeline(
        ImmutableArray<SigningKey> oldestFirst, TimeSpan leadTime, TimeSpan retention, ImmutableList<SigningKey> setAside)
    {
        _oldestFirst = oldestFirst;
        _leadTime = leadTime;
        _retention = retention;
        SetAside = setAside;
    }

    /// <summary>Gets how long a key is published before it may sign.</summary>
    internal TimeSpan LeadTime => _leadTime;

    /// <summary>
    /// Gets the keys whose signer failed to open or self-test when they were due to sign, in the
    /// order they failed. They stay published but never sign.
    /// </summary>
    internal ImmutableList<SigningKey> SetAside { get; }

    /// <summary>The key set in force at <paramref name="now"/>.</summary>
    internal SigningKeySet At(DateTimeOffset now)
    {
        var unexpired = _oldestFirst.Where(key => key.ExpiresAt > now).ToList();
        var signingKey = ChooseSigningKey(unexpired, now);

        var supersededAfter = TokenLifetimes.Sum(_leadTime, _retention);
        var newestEstablished = unexpired.FindLastIndex(key => now - key.NotBefore >= supersededAfter);
        var keptUnexpired = unexpired.Skip(Math.Max(newestEstablished, 0)).ToHashSet();

        ImmutableArray<SigningKey> published =
        [
            .. _oldestFirst.Where(key =>
                key == signingKey
                || keptUnexpired.Contains(key)
                || (key.ExpiresAt <= now && now - key.ExpiresAt < _retention)),
        ];

        return new SigningKeySet(signingKey, published);
    }

    /// <summary>
    /// The same keys with the one whose <see cref="SigningKey.Kid"/> is <paramref name="kid"/> set
    /// aside: it never signs, so the rules carry on with the keys around it, and it is never tried
    /// again.
    /// </summary>
    internal SigningKeyTimeline SettingAside(string kid) =>
        new(_oldestFirst, _leadTime, _retention, SetAside.Add(_oldestFirst.Single(key => key.Kid == kid)));

    /// <summary>
    /// Whether <paramref name="key"/> has been published for the lead time at <paramref name="now"/>;
    /// a signing key that has not been may produce tokens a relying party with a cached key set rejects.
    /// </summary>
    internal bool IsEstablished(SigningKey key, DateTimeOffset now) => now - key.NotBefore >= _leadTime;

    /// <summary>
    /// The first instant after <paramref name="now"/> at which <see cref="At"/> may return a
    /// different set, or <see cref="DateTimeOffset.MaxValue"/> when none will come.
    /// </summary>
    internal DateTimeOffset NextChangeAfter(DateTimeOffset now)
    {
        var supersededAfter = TokenLifetimes.Sum(_leadTime, _retention);
        var next = DateTimeOffset.MaxValue;

        foreach (var key in _oldestFirst)
        {
            ReadOnlySpan<DateTimeOffset> instants =
            [
                TokenLifetimes.ExpiresAt(key.NotBefore, _leadTime),
                TokenLifetimes.ExpiresAt(key.NotBefore, supersededAfter),
                key.ExpiresAt,
                TokenLifetimes.ExpiresAt(key.ExpiresAt, _retention),
            ];

            foreach (var instant in instants)
            {
                if (instant > now && instant < next)
                    next = instant;
            }
        }

        return next;
    }

    private SigningKey ChooseSigningKey(List<SigningKey> unexpired, DateTimeOffset now)
    {
        var eligible = unexpired.Where(key => !SetAside.Contains(key)).ToList();
        return eligible.LastOrDefault(key => IsEstablished(key, now))
            ?? eligible.FirstOrDefault()
            ?? _oldestFirst.Where(key => !SetAside.Contains(key))
                .Aggregate((last, key) => key.ExpiresAt >= last.ExpiresAt ? key : last);
    }
}
