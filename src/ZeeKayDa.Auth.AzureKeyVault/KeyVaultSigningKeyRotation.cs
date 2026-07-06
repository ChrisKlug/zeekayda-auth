namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// The stateless Key Vault rotation-timeline derivation shared by every Key Vault signing
/// provider: which version is the currently active signer, which other versions are still trusted
/// (not-yet-active, or still within their retirement window), and "previously-published kid
/// vanished early" anomaly detection. Every member is generic over the version-info type so the
/// exact same logic — moved here verbatim from what were previously two independent, identical
/// copies — applies equally to Key Vault key versions (<see cref="KeyVaultKeyVersionInfo"/>) and
/// certificate versions (<see cref="KeyVaultCertificateVersionInfo"/>). See ADR 0011 §3.3/§3.5 and
/// issue #300 for the full rationale behind this derivation.
/// </summary>
internal static class KeyVaultSigningKeyRotation
{
    /// <summary>
    /// Builds the ascending activation timeline for every known version of <typeparamref name="T"/>.
    /// </summary>
    /// <param name="allVersions">Every version Key Vault has ever recorded, including disabled and expired ones.</param>
    /// <param name="refreshInterval">The publish-then-activate delay applied to every version except the very first ever created.</param>
    public static List<ActivationEntry<T>> BuildActivationTimeline<T>(
        IReadOnlyList<T> allVersions, TimeSpan refreshInterval)
        where T : struct, IKeyVaultVersionInfo
    {
        var firstEverVersion = allVersions
            .OrderBy(v => v.CreatedOn)
            .ThenBy(v => v.Version, StringComparer.Ordinal)
            .First()
            .Version;

        // ActivatesAt is the earliest instant a version could ever legitimately win
        // SelectActiveVersion's selection — the publish-then-activate delay (or the immediate
        // bootstrap exemption for the very first version ever created), floored by NotBefore when
        // the operator has explicitly scheduled the version's go-live later than that. Folding
        // NotBefore in here (rather than treating it as a separate check applied only at "now")
        // means every downstream computation that orders by, or reasons about, ActivatesAt
        // automatically accounts for it correctly — there is no other point in this method that
        // needs to know about NotBefore specially.
        var ordered = allVersions
            .Select(v => new
            {
                Version = v,
                ActivatesAt = Max(
                    v.Version == firstEverVersion ? v.CreatedOn : v.CreatedOn + refreshInterval,
                    v.NotBefore ?? DateTimeOffset.MinValue),
            })
            .OrderBy(x => x.ActivatesAt)
            .ThenBy(x => x.Version.CreatedOn)
            .ThenBy(x => x.Version.Version, StringComparer.Ordinal)
            .ToList();

        // RetiredAt(v) must be the ActivatesAt of whichever version *actually* superseded v as the
        // active signer — i.e. the next entry, in ActivatesAt order, that could ever legitimately
        // win SelectActiveVersion's selection. A version that is disabled, or that is already
        // outside its own ExpiresOn window at the instant it would activate, can never win that
        // selection (see IsEligibleAt / SelectActiveVersion), so it must be skipped when looking for
        // a predecessor's real successor — it is simply never anyone's successor. Naively using the
        // positionally-next entry regardless of eligibility lets a chronologically-intervening but
        // never-actually-active version's ActivatesAt gate a real predecessor's retirement window far
        // too early, silently dropping a still-legitimately-active (or still-within-window) key out
        // of GetSigningKeysAsync()/the JWKS before its already-issued tokens have stopped being
        // relied upon — exactly the trust-boundary regression ADR 0011 §3.3 exists to prevent.
        //
        // Eligibility here is evaluated at the *candidate's own* ActivatesAt. Because ActivatesAt
        // already incorporates NotBefore (above), IsEligibleAt's NotBefore check is satisfied by
        // construction at that point — what remains to test is exactly Enabled and "already past
        // ExpiresOn by the time it would activate", both permanent, non-time-varying disqualifications:
        // such a version can never win SelectActiveVersion at any "now", so skipping it here is
        // unconditionally correct. There is no residual imprecision left in this derivation.
        var entries = new ActivationEntry<T>[ordered.Count];
        DateTimeOffset? nextEligibleSuccessorActivatesAt = null;
        for (var i = ordered.Count - 1; i >= 0; i--)
        {
            entries[i] = new ActivationEntry<T>(ordered[i].Version, ordered[i].ActivatesAt, nextEligibleSuccessorActivatesAt);

            if (IsEligibleAt(ordered[i].Version, ordered[i].ActivatesAt))
                nextEligibleSuccessorActivatesAt = ordered[i].ActivatesAt;
        }

        return [.. entries];
    }

    /// <summary>
    /// Picks the currently active signing version out of an ascending activation timeline.
    /// </summary>
    public static ActivationEntry<T>? SelectActiveVersion<T>(
        IReadOnlyList<ActivationEntry<T>> ascendingTimeline, DateTimeOffset now)
        where T : struct, IKeyVaultVersionInfo
    {
        // The timeline is sorted ascending by ActivatesAt, so the last eligible match encountered
        // while scanning forward is always the one with the greatest ActivatesAt <= now.
        ActivationEntry<T>? active = null;
        foreach (var entry in ascendingTimeline.Where(entry => entry.ActivatesAt <= now && IsEligibleAt(entry.Version, now)))
        {
            active = entry;
        }

        return active;
    }

    /// <summary>
    /// Selects every version that should currently be exposed via the JWKS: the active version
    /// (first), plus every other enabled version that is either not yet active or still within its
    /// retirement window.
    /// </summary>
    public static List<ActivationEntry<T>> SelectIncludedVersions<T>(
        IReadOnlyList<ActivationEntry<T>> timeline, ActivationEntry<T> active, DateTimeOffset now, TimeSpan retirementWindow)
        where T : struct, IKeyVaultVersionInfo
    {
        // Active goes first — the base class treats index 0 as the active signing key.
        var included = new List<ActivationEntry<T>> { active };

        foreach (var entry in timeline.Where(entry => entry.Version.Version != active.Version.Version))
        {
            // Disabled is an immediate, unconditional exclusion — bypasses the retirement window
            // entirely, so an operator disabling a suspected-compromised key takes effect at once.
            if (!entry.Version.Enabled)
                continue;

            var notYetActive = entry.ActivatesAt > now;
            var stillWithinRetirementWindow = entry.RetiredAt is { } retiredAt && now - retiredAt <= retirementWindow;

            if (notYetActive || stillWithinRetirementWindow)
                included.Add(entry);
        }

        return included;
    }

    // Named generically ("At", not "Now") because this same Enabled/NotBefore/ExpiresOn check is
    // evaluated at two different kinds of point in time: the current wall-clock time (from
    // SelectActiveVersion, to pick today's active signer) and each candidate's own ActivatesAt
    // (from BuildActivationTimeline, to decide whether that candidate could ever legitimately have
    // won that same selection once it activated). The NotBefore half of this check is, by the time
    // BuildActivationTimeline calls it, already guaranteed true against ActivatesAt — see that
    // method's comments — but it is left in place because SelectActiveVersion still needs it
    // checked against the real wall-clock "now".
    public static bool IsEligibleAt<T>(T version, DateTimeOffset pointInTime)
        where T : struct, IKeyVaultVersionInfo =>
        version.Enabled
        && (version.NotBefore is not { } notBefore || notBefore <= pointInTime)
        && (version.ExpiresOn is not { } expiresOn || pointInTime <= expiresOn);

    /// <summary>
    /// The pure "previously-published kid vanished early" detection logic (ADR 0011 §3.5): finds
    /// every kid that was published as of the previous <c>LoadKeysAsync</c> call, is no longer among
    /// the newly-published kids, and whose underlying Key Vault version is no longer present at all
    /// (as opposed to still present but disabled, or fully and expectedly retired). Callers are
    /// responsible for logging each returned pair with their own provider-specific message text.
    /// </summary>
    public static IEnumerable<(string Kid, string Version)> FindVanishedKids<T>(
        IReadOnlyDictionary<string, string> previouslyPublishedKidVersions,
        IEnumerable<string> newKids,
        IReadOnlyList<T> currentRawVersions)
        where T : struct, IKeyVaultVersionInfo
    {
        if (previouslyPublishedKidVersions.Count == 0)
            yield break;

        var newKidSet = new HashSet<string>(newKids, StringComparer.Ordinal);
        var currentVersionStrings = new HashSet<string>(
            currentRawVersions.Select(v => v.Version), StringComparer.Ordinal);

        foreach (var (kid, version) in previouslyPublishedKidVersions)
        {
            if (newKidSet.Contains(kid))
                continue;

            if (currentVersionStrings.Contains(version))
                continue; // Still in Key Vault — excluded for an expected reason (disabled or fully retired).

            yield return (kid, version);
        }
    }

    private static DateTimeOffset Max(DateTimeOffset a, DateTimeOffset b) => a >= b ? a : b;

    /// <summary>
    /// A single version's position in the activation timeline: when it becomes eligible to be the
    /// active signer, and — if it was ever actually superseded — when its successor took over.
    /// </summary>
    /// <param name="Version">The underlying version metadata.</param>
    /// <param name="ActivatesAt">The earliest instant this version could ever legitimately win <see cref="SelectActiveVersion{T}"/>'s selection.</param>
    /// <param name="RetiredAt">
    /// The <see cref="ActivatesAt"/> of the version that actually superseded this one as the active
    /// signer, if any.
    /// </param>
    public readonly record struct ActivationEntry<T>(T Version, DateTimeOffset ActivatesAt, DateTimeOffset? RetiredAt)
        where T : struct, IKeyVaultVersionInfo;
}
