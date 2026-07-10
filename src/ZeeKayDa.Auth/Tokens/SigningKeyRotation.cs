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
/// caller (e.g. an X.509 certificate's <c>NotBefore</c>, converted to UTC, or an explicit
/// operator-supplied activation time for a bare, certificate-less key). <see cref="SigningKeyRotation"/>
/// treats this as an opaque, precomputed fact and applies no further delay or flooring logic of its
/// own.
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
    /// <see cref="RotationKey.ActivatesAt"/> — anchor-agnostic rotation applies no additional delay
    /// or flooring on top of the caller-supplied activation time, so this is a computed accessor
    /// over <see cref="Key"/> rather than a separately stored (and potentially divergent) field.
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
/// <para>
/// This component operates purely on <see cref="RotationKey"/>'s already-resolved
/// <see cref="RotationKey.ActivatesAt"/>/<see cref="RotationKey.ExpiresAt"/> pair — it has no
/// dependency on <see cref="System.Security.Cryptography.X509Certificates.X509Certificate2"/> or any
/// other provider-specific type. Each provider maps its own durable per-key timestamp (an X.509
/// certificate's <c>NotBefore</c>/<c>NotAfter</c>, or an explicit activation time for a bare,
/// certificate-less key) onto <see cref="RotationKey"/> before calling in. This is what lets a
/// certificate-backed provider (the Windows Certificate Store provider) and a potential future
/// bare-key provider share the exact same rotation logic.
/// </para>
/// <para>
/// Structurally analogous to the Azure Key Vault providers' internal rotation-timeline derivation,
/// but anchored differently and simpler: Key Vault anchors on each version's durable,
/// service-stamped <c>CreatedOn</c> timestamp, applies a publish-then-activate delay on top, tracks
/// an <c>Enabled</c> flag, and detects "previously-published kid vanished early" anomalies via live
/// polling. None of that applies here — every key eligible for this component is already fully
/// resolved and visible as of process start, with no live external state to poll. That Key Vault
/// logic is intentionally not part of this type and stays where it already lives.
/// </para>
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

        // RetiredAt(k) must be the ActivatesAt of whichever key *actually* superseded k as the
        // active signer — i.e. the next entry, in ActivatesAt order, that could ever legitimately
        // win SelectActiveKey's selection. A key that is already past its own ExpiresAt by the time
        // it would activate can never win that selection, so it must be skipped when looking for a
        // predecessor's real successor — it is simply never anyone's successor.
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
    /// Picks the currently active signing key out of an ascending activation timeline.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>Callers must fail closed on a <see langword="null"/> return.</strong> A
    /// <see langword="null"/> result means no key is currently eligible to sign; the caller must
    /// refuse to sign (e.g. by throwing a configuration exception), never fall back to an arbitrary
    /// key from the timeline — signing with an expired or not-yet-activated key would issue tokens
    /// relying parties are entitled to reject, and silently picking one would mask the very
    /// misconfiguration this <see langword="null"/> exists to surface.
    /// </para>
    /// <para>
    /// <strong>Single-key bootstrap exemption:</strong> with exactly one registered key it is active
    /// immediately regardless of its <see cref="RotationKey.ActivatesAt"/> — there is no prior
    /// published JWKS state any relying party could have cached. This also covers the steady state
    /// after a rotation completes and the retiring key is removed from configuration, since that key
    /// was already active and published well before the cleanup redeploy. The exemption applies only
    /// to activation timing, not to expiry: an already-expired sole key still fails closed (returns
    /// <see langword="null"/>) rather than being silently used to sign.
    /// </para>
    /// </remarks>
    /// <returns>
    /// The active entry, or <see langword="null"/> if no key is currently eligible to sign (the
    /// caller must fail closed in this case — see remarks).
    /// </returns>
    public static RotationEntry? SelectActiveKey(IReadOnlyList<RotationEntry> timeline, DateTimeOffset now)
    {
        if (timeline.Count == 1)
            return IsEligibleAt(timeline[0].Key, now) ? timeline[0] : null;

        // The timeline is sorted ascending by ActivatesAt (BuildActivationTimeline's contract), so
        // the last eligible match is always the one with the greatest ActivatesAt <= now. Projected
        // to RotationEntry? so LastOrDefault() on an empty filtered sequence yields null rather than
        // default(RotationEntry).
        return timeline
            .Where(entry => entry.ActivatesAt <= now && IsEligibleAt(entry.Key, now))
            .Select(entry => (RotationEntry?)entry)
            .LastOrDefault();
    }

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
    /// <see cref="RotationKey.ActivatesAt"/> is less than <paramref name="refreshInterval"/> away
    /// from <paramref name="now"/> — a relying party polling the JWKS at that cadence may not have
    /// observed the key's public material before it starts signing.
    /// </summary>
    public static bool HasTooSoonPendingActivation(
        IReadOnlyList<RotationEntry> timeline, RotationEntry active, DateTimeOffset now,
        TimeSpan refreshInterval, out RotationEntry? soonestPending)
    {
        soonestPending = null;

        if (timeline.Count < 2)
            return false;

        // Projected to RotationEntry? (not a plain .OrderBy().FirstOrDefault<RotationEntry>()):
        // RotationEntry is a readonly record struct, so FirstOrDefault() on an empty filtered
        // sequence would otherwise return default(RotationEntry) rather than null, wrongly making
        // `soonestPending` non-null when nothing is actually pending.
        soonestPending = timeline
            .Where(entry => !string.Equals(entry.Key.Id, active.Key.Id, StringComparison.Ordinal) && entry.ActivatesAt > now)
            .OrderBy(entry => entry.ActivatesAt)
            .Select(entry => (RotationEntry?)entry)
            .FirstOrDefault();

        return soonestPending is { } pending && pending.ActivatesAt - now < refreshInterval;
    }

    // Named generically ("At", not "Now") because this same ExpiresAt check is evaluated at two
    // different kinds of point in time: the current wall-clock time (from SelectActiveKey, to pick
    // today's active signer) and each candidate's own ActivatesAt (from BuildActivationTimeline, to
    // decide whether that candidate could ever legitimately have won that same selection once it
    // activated).
    private static bool IsEligibleAt(RotationKey key, DateTimeOffset pointInTime) =>
        pointInTime <= key.ExpiresAt;

    private static bool IsNotYetActiveOrStillWithinRetirementWindow(
        RotationEntry entry, DateTimeOffset now, TimeSpan retirementWindow)
    {
        var notYetActive = entry.ActivatesAt > now;
        var stillWithinRetirementWindow = entry.RetiredAt is { } retiredAt && now - retiredAt <= retirementWindow;

        return notYetActive || stillWithinRetirementWindow;
    }
}
