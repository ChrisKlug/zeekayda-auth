namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// A single signing key's stable identity and precomputed activation window, for use with
/// <see cref="SigningKeyRotation"/>.
/// </summary>
/// <param name="Id">
/// A stable identifier for this key, unique among every key passed to the same
/// <see cref="SigningKeyRotation"/> call (e.g. a certificate thumbprint). Not the <c>kid</c>.
/// </param>
/// <param name="ActivatesAt">
/// The instant this key becomes eligible to be the active signer, already fully resolved by the
/// caller. <see cref="SigningKeyRotation"/> treats this as an opaque, precomputed fact and applies
/// no further delay or flooring logic of its own.
/// </param>
/// <param name="ExpiresAt">
/// The instant this key stops being eligible to sign or be trusted (e.g. an X.509 certificate's
/// <c>NotAfter</c>, converted to UTC).
/// </param>
public readonly record struct RotationKey(string Id, DateTimeOffset ActivatesAt, DateTimeOffset ExpiresAt);

/// <summary>
/// A single key's position in the activation timeline built by <see cref="SigningKeyRotation.BuildActivationTimeline"/>.
/// </summary>
/// <param name="Key">The underlying key identity and activation window.</param>
/// <param name="RetiredAt">
/// The <see cref="ActivatesAt"/> of the key that actually superseded this one as the active signer,
/// if any.
/// </param>
public readonly record struct RotationEntry(RotationKey Key, DateTimeOffset? RetiredAt)
{
    /// <summary>
    /// Gets the earliest instant this key could ever legitimately win
    /// <see cref="SigningKeyRotation.SelectActiveKey"/>'s selection. Always equal to
    /// <see cref="RotationKey.ActivatesAt"/>.
    /// </summary>
    public DateTimeOffset ActivatesAt => Key.ActivatesAt;
}

/// <summary>
/// The stateless, anchor-agnostic rotation-timeline derivation shared by every signing provider that
/// derives its trusted-key set from a precomputed per-key activation/expiry window: which key is the
/// currently active signer, which others are still trusted (not-yet-active, or still within their
/// retirement window), and whether a rotated-in key's activation is scheduled too soon.
/// </summary>
/// <remarks>
/// Operates purely on <see cref="RotationKey"/>'s already-resolved
/// <see cref="RotationKey.ActivatesAt"/>/<see cref="RotationKey.ExpiresAt"/> pair, with no dependency
/// on any provider-specific key type. Each provider maps its own durable per-key timestamp onto
/// <see cref="RotationKey"/> before calling in, letting multiple providers share this same logic.
/// </remarks>
public static class SigningKeyRotation
{
    /// <summary>
    /// Builds the ascending activation timeline for every supplied key.
    /// </summary>
    /// <param name="keys">Every key currently registered with the calling provider.</param>
    public static IReadOnlyList<RotationEntry> BuildActivationTimeline(IReadOnlyList<RotationKey> keys)
    {
        var ordered = keys
            .OrderBy(k => k.ActivatesAt)
            .ThenBy(k => k.Id, StringComparer.Ordinal)
            .ToList();

        // RetiredAt(k) is the ActivatesAt of whichever key actually superseded k — the next entry,
        // in order, that could legitimately win SelectActiveKey's selection. A key already past its
        // own ExpiresAt by the time it would activate is skipped: it can never be anyone's successor.
        var entries = new RotationEntry[ordered.Count];
        DateTimeOffset? nextEligibleSuccessorActivatesAt = null;

        for (var i = ordered.Count - 1; i >= 0; i--)
        {
            entries[i] = new RotationEntry(ordered[i], nextEligibleSuccessorActivatesAt);

            if (IsEligibleAt(ordered[i], ordered[i].ActivatesAt))
                nextEligibleSuccessorActivatesAt = ordered[i].ActivatesAt;
        }

        return entries;
    }

    /// <summary>
    /// Picks the currently active signing key for a <c>KeySourceOptions</c> (Tier B) provider — a
    /// live listing that can shrink at runtime. Never grants the single-key bootstrap exemption
    /// (see <see cref="SelectActiveKeyForFixedKeySet"/>), regardless of how the current listing
    /// came to contain only one key — in particular, a listing shrunk to one key via operator
    /// revocation mid-incident must not have that key treated as immediately active on a process
    /// restart or scale-out.
    /// </summary>
    /// <remarks>
    /// <strong>Callers must fail closed on a <see langword="null"/> return</strong> — refuse to sign
    /// rather than falling back to an arbitrary key, since signing with an expired or
    /// not-yet-activated key would issue tokens relying parties are entitled to reject.
    /// </remarks>
    /// <param name="timeline">The activation timeline, as built by <see cref="BuildActivationTimeline"/>.</param>
    /// <param name="now">The current instant to select against.</param>
    /// <returns>
    /// The active entry, or <see langword="null"/> if no key is currently eligible to sign (the
    /// caller must fail closed in this case — see remarks).
    /// </returns>
    public static RotationEntry? SelectActiveKey(IReadOnlyList<RotationEntry> timeline, DateTimeOffset now)
    {
        // Timeline is sorted ascending by ActivatesAt, so the last eligible match has the greatest
        // ActivatesAt <= now. Projected to RotationEntry? so an empty result yields null, not
        // default(RotationEntry).
        return timeline
            .Where(entry => entry.ActivatesAt <= now && IsEligibleAt(entry.Key, now))
            .Select(entry => (RotationEntry?)entry)
            .LastOrDefault();
    }

    /// <summary>
    /// Picks the currently active signing key for a <c>KeySetOptions</c> (Tier A) provider — a
    /// fixed key set known in full at configuration time.
    /// </summary>
    /// <remarks>
    /// <strong>Callers must fail closed on a <see langword="null"/> return</strong> — refuse to sign
    /// rather than falling back to an arbitrary key, since signing with an expired or
    /// not-yet-activated key would issue tokens relying parties are entitled to reject.
    /// <para>
    /// <strong>Single-key bootstrap exemption:</strong> with exactly one registered key, that key
    /// is active immediately regardless of its <see cref="RotationKey.ActivatesAt"/> — there is no
    /// prior published JWKS state any relying party could have cached. This applies only to
    /// activation timing, not expiry: an already-expired sole key still fails closed.
    /// </para>
    /// <para>
    /// Only a fixed <c>KeySetOptions</c> tier ever gets this exemption — <see cref="SelectActiveKey"/>
    /// itself never grants it, so a <c>KeySourceOptions</c> caller cannot obtain it no matter which
    /// method it calls.
    /// </para>
    /// </remarks>
    /// <param name="timeline">The activation timeline, as built by <see cref="BuildActivationTimeline"/>.</param>
    /// <param name="now">The current instant to select against.</param>
    /// <returns>
    /// The active entry, or <see langword="null"/> if no key is currently eligible to sign (the
    /// caller must fail closed in this case — see remarks).
    /// </returns>
    public static RotationEntry? SelectActiveKeyForFixedKeySet(IReadOnlyList<RotationEntry> timeline, DateTimeOffset now) =>
        SelectSoleEligibleKey(timeline, now) ?? SelectActiveKey(timeline, now);

    /// <summary>
    /// Selects every key that should currently be exposed via the JWKS: the active key (first), plus
    /// every other key that is either not yet active or still within its retirement window.
    /// </summary>
    public static IReadOnlyList<RotationEntry> SelectIncludedKeys(
        IReadOnlyList<RotationEntry> timeline, RotationEntry active, DateTimeOffset now, TimeSpan retirementWindow)
    {
        var included = new List<RotationEntry> { active };

        included.AddRange(timeline.Where(entry =>
            !string.Equals(entry.Key.Id, active.Key.Id, StringComparison.Ordinal) &&
            IsNotYetActiveOrStillWithinRetirementWindow(entry, now, retirementWindow)));

        return included;
    }

    /// <summary>
    /// True when 2+ keys are registered and the soonest not-yet-active key's
    /// <see cref="RotationKey.ActivatesAt"/> is less than <paramref name="assumedJwksPropagationDelay"/>
    /// away from <paramref name="now"/> — a relying party polling the JWKS at that cadence may not
    /// have observed the key's public material before it starts signing.
    /// </summary>
    public static bool HasTooSoonPendingActivation(
        IReadOnlyList<RotationEntry> timeline, RotationEntry active, DateTimeOffset now,
        TimeSpan assumedJwksPropagationDelay, out RotationEntry? soonestPending)
    {
        soonestPending = null;

        if (timeline.Count < 2)
            return false;

        // Projected to RotationEntry? so an empty result yields null rather than
        // default(RotationEntry), which would wrongly make `soonestPending` non-null.
        soonestPending = timeline
            .Where(entry => !string.Equals(entry.Key.Id, active.Key.Id, StringComparison.Ordinal) && entry.ActivatesAt > now)
            .OrderBy(entry => entry.ActivatesAt)
            .Select(entry => (RotationEntry?)entry)
            .FirstOrDefault();

        return soonestPending is { } pending && pending.ActivatesAt - now < assumedJwksPropagationDelay;
    }

    /// <summary>
    /// Selects every timeline entry that is not yet active but could still legitimately become the
    /// active signer once its own <see cref="RotationKey.ActivatesAt"/> arrives — i.e. it would
    /// still be eligible (not yet expired) at that point. A staged key whose
    /// <see cref="RotationKey.ExpiresAt"/> falls before its own <see cref="RotationKey.ActivatesAt"/>
    /// is excluded: it would already be expired by the time it could take over, so it can never
    /// actually sign anything, regardless of how far in the future its activation is scheduled.
    /// </summary>
    /// <param name="timeline">The activation timeline, as built by <see cref="BuildActivationTimeline"/>.</param>
    /// <param name="active">The currently active entry, as returned by <see cref="SelectActiveKey"/>
    /// or <see cref="SelectActiveKeyForFixedKeySet"/>.</param>
    /// <param name="now">The current instant to select against.</param>
    public static IReadOnlyList<RotationEntry> SelectFutureSigners(
        IReadOnlyList<RotationEntry> timeline, RotationEntry active, DateTimeOffset now) =>
        timeline
            .Where(entry =>
                !string.Equals(entry.Key.Id, active.Key.Id, StringComparison.Ordinal) &&
                entry.ActivatesAt > now &&
                IsEligibleAt(entry.Key, entry.ActivatesAt))
            .ToList();

    // Named generically ("At", not "Now") because this ExpiresAt check is evaluated both at the
    // current wall-clock time and at a candidate's own ActivatesAt.
    private static bool IsEligibleAt(RotationKey key, DateTimeOffset pointInTime) =>
        pointInTime <= key.ExpiresAt;

    // The single-key bootstrap exemption: the sole registered key, bypassing its own ActivatesAt,
    // as long as it hasn't already expired — or null if there isn't exactly one key, or there is
    // but it's expired. Both null cases are deliberately not distinguished: SelectActiveKey's
    // normal per-entry selection (SelectActiveKeyForFixedKeySet's fallback) rejects an expired sole
    // key identically via IsEligibleAt, so "no exemption to give" and "exemption doesn't apply
    // here" are equally just "fall through."
    private static RotationEntry? SelectSoleEligibleKey(IReadOnlyList<RotationEntry> timeline, DateTimeOffset now) =>
        timeline.Count == 1 && IsEligibleAt(timeline[0].Key, now) ? timeline[0] : null;

    private static bool IsNotYetActiveOrStillWithinRetirementWindow(
        RotationEntry entry, DateTimeOffset now, TimeSpan retirementWindow)
    {
        var notYetActive = entry.ActivatesAt > now;
        var stillWithinRetirementWindow = entry.RetiredAt is { } retiredAt && now - retiredAt <= retirementWindow;

        return notYetActive || stillWithinRetirementWindow;
    }
}
