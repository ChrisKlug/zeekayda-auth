using System.Linq;

namespace ZeeKayDa.Auth.Windows;

/// <summary>
/// The stateless, <c>NotBefore</c>-anchored rotation-timeline derivation for the Windows
/// Certificate Store signing provider: which registered certificate is the currently active
/// signer, which others are still trusted (not-yet-active, or still within their retirement
/// window), and whether a rotated-in certificate's activation is scheduled too soon.
/// </summary>
/// <remarks>
/// <para>
/// Structurally analogous to <c>ZeeKayDa.Auth.AzureKeyVault.KeyVaultSigningKeyRotation</c> but
/// anchored differently and simpler, per issue #282's rotation model for the OS-native store
/// providers (#289/#290/#291):
/// </para>
/// <para>
/// Key Vault anchors on each version's durable, service-stamped <c>CreatedOn</c> timestamp — a
/// fact Key Vault itself records and that is consistent across every replica and restart. A
/// certificate sitting in a Windows Certificate Store has no equivalent "added to this store"
/// timestamp. What it does carry durably — embedded in the certificate itself by the issuing CA,
/// immutable, and identical across every replica and restart with no store dependency at all — is
/// <c>NotBefore</c>/<c>NotAfter</c>. So here <c>NotBefore</c> is promoted to the primary
/// activation-ordering field directly, rather than merely flooring a separately-tracked creation
/// time as it does for Key Vault. There is also no publish-then-activate delay term added on top:
/// every registered certificate is already visible in the JWKS as of process start (there is no
/// incremental "did the store durably record this yet" question the way there is for a Key Vault
/// version that might not yet be durably recorded).
/// </para>
/// <para>
/// There is no equivalent of Key Vault's <c>Enabled</c> flag (it does not exist for store
/// certificates) and no "vanished kid" anomaly detection (there is no live store polling to notice
/// a disappearance against — adding or removing a registered certificate requires a host restart,
/// out of scope per the issue).
/// </para>
/// </remarks>
internal static class WindowsCertificateStoreSigningKeyRotation
{
    /// <summary>A single registered certificate's identity and validity window.</summary>
    /// <param name="Thumbprint">The normalized certificate thumbprint.</param>
    /// <param name="NotBefore">The certificate's <c>NotBefore</c>, converted to UTC.</param>
    /// <param name="NotAfter">The certificate's <c>NotAfter</c>, converted to UTC.</param>
    public readonly record struct RegisteredCertificateInfo(
        string Thumbprint, DateTimeOffset NotBefore, DateTimeOffset NotAfter);

    /// <summary>
    /// A single certificate's position in the activation timeline: when it becomes eligible to be
    /// the active signer, and — if it was ever actually superseded — when its successor took over.
    /// </summary>
    /// <param name="Certificate">The underlying certificate metadata.</param>
    /// <param name="ActivatesAt">The earliest instant this certificate could ever legitimately win <see cref="SelectActiveVersion"/>'s selection.</param>
    /// <param name="RetiredAt">The <see cref="ActivatesAt"/> of the certificate that actually superseded this one as the active signer, if any.</param>
    public readonly record struct ActivationEntry(
        RegisteredCertificateInfo Certificate, DateTimeOffset ActivatesAt, DateTimeOffset? RetiredAt);

    /// <summary>
    /// Builds the ascending activation timeline for every registered certificate.
    /// </summary>
    public static IReadOnlyList<ActivationEntry> BuildActivationTimeline(
        IReadOnlyList<RegisteredCertificateInfo> certificates)
    {
        var ordered = certificates
            .OrderBy(c => c.NotBefore)
            .ThenBy(c => c.Thumbprint, StringComparer.Ordinal)
            .ToList();

        // RetiredAt(v) must be the ActivatesAt of whichever certificate *actually* superseded v as
        // the active signer — i.e. the next entry, in ActivatesAt order, that could ever
        // legitimately win SelectActiveVersion's selection. A certificate that is already past its
        // own NotAfter by the time it would activate can never win that selection, so it must be
        // skipped when looking for a predecessor's real successor — it is simply never anyone's
        // successor. Scanning backwards mirrors KeyVaultSigningKeyRotation.BuildActivationTimeline.
        var entries = new ActivationEntry[ordered.Count];
        DateTimeOffset? nextEligibleSuccessorActivatesAt = null;

        for (var i = ordered.Count - 1; i >= 0; i--)
        {
            entries[i] = new ActivationEntry(ordered[i], ordered[i].NotBefore, nextEligibleSuccessorActivatesAt);

            if (IsEligibleAt(ordered[i], ordered[i].NotBefore))
                nextEligibleSuccessorActivatesAt = ordered[i].NotBefore;
        }

        return entries;
    }

    /// <summary>
    /// Picks the currently active signing certificate out of an ascending activation timeline.
    /// </summary>
    /// <remarks>
    /// <strong>Single-certificate bootstrap exemption</strong> (issue #282): with exactly one
    /// registered certificate it is active immediately regardless of its <c>NotBefore</c> — there
    /// is no prior published JWKS state any relying party could have cached. This also covers the
    /// steady state after a rotation completes and the retiring certificate is removed from
    /// config, since that certificate was already active and published well before the cleanup
    /// redeploy. The exemption applies only to <c>NotBefore</c> timing, not to expiry: an
    /// already-expired sole certificate still fails closed (returns <see langword="null"/>) rather
    /// than being silently used to sign, mirroring the Key Vault providers' documented fail-closed
    /// behavior when the active key reaches its <c>ExpiresOn</c> with no eligible successor.
    /// </remarks>
    /// <returns>
    /// The active entry, or <see langword="null"/> if no registered certificate is currently
    /// eligible to sign (the caller fails closed in this case).
    /// </returns>
    public static ActivationEntry? SelectActiveVersion(IReadOnlyList<ActivationEntry> timeline, DateTimeOffset now)
    {
        if (timeline.Count == 1)
            return IsEligibleAt(timeline[0].Certificate, now) ? timeline[0] : null;

        ActivationEntry? active = null;
        foreach (var entry in System.Linq.Enumerable.Where(
            timeline,
            entry => entry.ActivatesAt <= now && IsEligibleAt(entry.Certificate, now)))
        {
            active = entry;
        }

        return active;
    }

    /// <summary>
    /// Selects every certificate that should currently be exposed via the JWKS: the active
    /// certificate (first), plus every other certificate that is either not yet active or still
    /// within its retirement window.
    /// </summary>
    public static IReadOnlyList<ActivationEntry> SelectIncludedCertificates(
        IReadOnlyList<ActivationEntry> timeline, ActivationEntry active, DateTimeOffset now, TimeSpan retirementWindow)
    {
        var included = new List<ActivationEntry> { active };

        foreach (var entry in timeline.Where(entry =>
            !string.Equals(entry.Certificate.Thumbprint, active.Certificate.Thumbprint, StringComparison.Ordinal)))
        {
            var notYetActive = entry.ActivatesAt > now;
            var stillWithinRetirementWindow = entry.RetiredAt is { } retiredAt && now - retiredAt <= retirementWindow;

            if (notYetActive || stillWithinRetirementWindow)
                included.Add(entry);
        }

        return included;
    }

    /// <summary>
    /// AC #7: true when 2+ certificates are registered and the soonest not-yet-active certificate's
    /// <c>NotBefore</c> is less than <paramref name="refreshInterval"/> away from <paramref name="now"/> —
    /// a relying party polling the JWKS at that cadence may not have observed the certificate's
    /// public key before it starts signing (ADR 0011 §3.5 / issue #282: the operator is expected to
    /// set a rotated-in certificate's <c>NotBefore</c> at least <c>RefreshInterval</c> in the future).
    /// </summary>
    public static bool HasTooSoonPendingActivation(
        IReadOnlyList<ActivationEntry> timeline, ActivationEntry active, DateTimeOffset now,
        TimeSpan refreshInterval, out ActivationEntry? soonestPending)
    {
        soonestPending = null;

        if (timeline.Count < 2)
            return false;

        soonestPending = timeline
            .Where(entry =>
                !string.Equals(entry.Certificate.Thumbprint, active.Certificate.Thumbprint, StringComparison.Ordinal) &&
                entry.ActivatesAt > now)
            .OrderBy(entry => entry.ActivatesAt)
            .FirstOrDefault();

        return soonestPending is { } pending && pending.ActivatesAt - now < refreshInterval;
    }

    // Named generically ("At", not "Now") because this same NotAfter check is evaluated at two
    // different kinds of point in time: the current wall-clock time (from SelectActiveVersion, to
    // pick today's active signer) and each candidate's own ActivatesAt (from
    // BuildActivationTimeline, to decide whether that candidate could ever legitimately have won
    // that same selection once it activated).
    private static bool IsEligibleAt(RegisteredCertificateInfo certificate, DateTimeOffset pointInTime) =>
        pointInTime <= certificate.NotAfter;
}
