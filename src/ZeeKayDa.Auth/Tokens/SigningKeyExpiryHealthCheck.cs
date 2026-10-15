using System.Diagnostics;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Reports whether the ring can sign now, and whether some key will still be able to sign
/// <see cref="SigningKeyExpiryHealthCheckOptions.DegradedThreshold"/> from now.
/// </summary>
/// <remarks>
/// <see cref="HealthStatus.Unhealthy"/> when signing has stopped, the signing key has expired, or it is
/// published only because it signs, once replicas whose handover succeeded have dropped it.
/// <see cref="HealthStatus.Degraded"/>, naming every reason, when the last read failed, a listed key was
/// dropped or is due though dropped, a successor was set aside, a handover is still running, or no key
/// will be able to sign at the end of <see cref="SigningKeyExpiryHealthCheckOptions.DegradedThreshold"/>.
/// The look-ahead asks the ring's own rules, so a staged successor keeps the check Healthy. Every
/// published key appears in the result data.
/// </remarks>
public sealed class SigningKeyExpiryHealthCheck : IHealthCheck
{
    private readonly SigningKeyRing? _ring;
    private readonly TimeProvider _timeProvider;
    private readonly IOptions<SigningKeyExpiryHealthCheckOptions> _options;

    /// <summary>
    /// Initialises a <see cref="SigningKeyExpiryHealthCheck"/>.
    /// </summary>
    /// <param name="ring">The ring to report on, or <see langword="null"/> when none is registered, which reports Unhealthy rather than failing resolution.</param>
    /// <param name="timeProvider">Used to evaluate remaining lifetime at probe time.</param>
    /// <param name="options">The degraded threshold to evaluate against.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="timeProvider"/> or <paramref name="options"/> is
    /// <see langword="null"/>.
    /// </exception>
    public SigningKeyExpiryHealthCheck(
        SigningKeyRing? ring, TimeProvider timeProvider, IOptions<SigningKeyExpiryHealthCheckOptions> options)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(options);

        _ring = ring;
        _timeProvider = timeProvider;
        _options = options;
    }

    /// <inheritdoc/>
    public Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        if (_ring is null)
        {
            return Task.FromResult(HealthCheckResult.Unhealthy(
                "No SigningKeyRing is registered. Call builder.AddSigningKeySource<TSource>() to " +
                "register a signing key source."));
        }

        if (_ring.StateOrNull is not { } state)
        {
            return Task.FromResult(HealthCheckResult.Unhealthy(
                "The signing key ring has not completed startup initialization yet."));
        }

        return Task.FromResult(state switch
        {
            SigningKeyRingState.Signing signing => WithReadFailure(
                Evaluate(signing.Timeline, signing.KeySet, _timeProvider.GetUtcNow(), _options.Value.DegradedThreshold),
                signing.ReadFailure),
            SigningKeyRingState.Resuming resuming => HealthCheckResult.Unhealthy(
                $"Signing has stopped ({resuming.Reason}) until the handover to the key due to sign completes; the log " +
                "names the cause.",
                exception: null,
                KeyData(resuming.KeySet.Published, signingKid: null, _timeProvider.GetUtcNow())),
            SigningKeyRingState.Stopped stopped => HealthCheckResult.Unhealthy(
                $"Signing has stopped ({stopped.Reason}) and no key is published; the log names the cause. Signing " +
                "resumes once the source lists keys the ring can use."),
            _ => throw new UnreachableException(),
        });
    }

    /// <summary>A ring serving the list before a failed read is at best Degraded.</summary>
    private static HealthCheckResult WithReadFailure(HealthCheckResult result, string? readFailure)
    {
        if (readFailure is null || result.Status == HealthStatus.Unhealthy)
            return result;

        var reason = $"The last read of the signing key source failed ({readFailure}); the ring serves the list it read before.";
        var description = result.Status == HealthStatus.Degraded ? $"{reason} {result.Description}" : reason;
        return HealthCheckResult.Degraded(description, exception: null, result.Data);
    }

    /// <summary>Judges <paramref name="set"/> against <paramref name="timeline"/> at <paramref name="now"/>.</summary>
    /// <param name="timeline">The listed keys, the keys set aside, and the rules that choose among them.</param>
    /// <param name="set">The key set the ring is serving now.</param>
    /// <param name="now">The current time.</param>
    /// <param name="degradedThreshold">How far ahead a key must still be able to sign for <see cref="HealthStatus.Healthy"/>.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="set"/> has no signing key.</exception>
    internal static HealthCheckResult Evaluate(
        SigningKeyTimeline timeline, SigningKeySet set, DateTimeOffset now, TimeSpan degradedThreshold)
    {
        var signingKey = set.SigningKey ?? throw new ArgumentException("The key set must have a signing key.", nameof(set));
        var data = KeyData(set.Published, signingKey.Kid, now);

        if (signingKey.ExpiresAt <= now)
        {
            return HealthCheckResult.Unhealthy(
                $"Signing key '{signingKey.Kid}' expired at {signingKey.ExpiresAt:O}, and no unexpired key can sign.",
                exception: null, data);
        }

        if (timeline.IsPublishedOnlyBecauseItSigns(signingKey, now))
        {
            return HealthCheckResult.Unhealthy(
                $"Signing key '{signingKey.Kid}' signs on after a failed or unfinished handover, and every replica " +
                "whose handover succeeded has now dropped it from its key set, so they no longer verify its tokens. " +
                StrandedRemedy(timeline, now),
                exception: null, data);
        }

        var reasons = DegradedReasons(timeline, signingKey, now, degradedThreshold).ToList();
        if (reasons.Count > 0)
            return HealthCheckResult.Degraded(string.Join(" ", reasons), exception: null, data);

        return NeverExpires(signingKey)
            ? HealthCheckResult.Healthy($"Signing key '{signingKey.Kid}' has no expiry.", data)
            : HealthCheckResult.Healthy($"Signing key '{signingKey.Kid}' expires at {signingKey.ExpiresAt:O}.", data);
    }

    /// <summary>What the operator can do for a key signing on past its retention.</summary>
    private static string StrandedRemedy(SigningKeyTimeline timeline, DateTimeOffset now) =>
        timeline.SetAside.Count > 0
            ? "The key that should have taken over failed and can no longer do so; list a fresh key."
            : $"The handover to '{timeline.SigningKeyAt(now).Kid}' has not completed yet; it takes over once its signer opens.";

    private static IEnumerable<string> DegradedReasons(
        SigningKeyTimeline timeline, SigningKey signingKey, DateTimeOffset now, TimeSpan degradedThreshold)
    {
        if (!timeline.Dropped.IsEmpty)
        {
            // Codes only: a source id may be a file path or vault URI, and this text can be public.
            yield return
                $"Source entries that could not be used were dropped ({timeline.Dropped.Length}: " +
                $"{string.Join(", ", timeline.Dropped.Select(drop => drop.Failure.Code).Distinct())}); " +
                "the log names them. Fix the keys; the next read picks them up.";
        }

        if (timeline.DroppedKeyDueAt(now) is { } droppedDue)
        {
            yield return
                $"The key due to sign now was dropped ({droppedDue.Failure.Code}), so '{signingKey.Kid}' signs in its " +
                "place. Fix the key; the next read tries it again, unless the key it would replace is superseded by " +
                "then, when only a fresh key can take over.";
        }

        if (timeline.SetAside.Count > 0)
        {
            yield return
                $"{string.Join(", ", timeline.SetAside.Select(key => $"'{key.Kid}'"))} could not sign when due (its signer " +
                "failed, or it was dropped), so it is set aside. Fix the key; the next read tries it again, unless the " +
                "key it would replace is superseded by then: then list a fresh key, and remove this one.";
        }

        var due = timeline.SigningKeyAt(now);
        if (due.Kid != signingKey.Kid)
            yield return $"Key '{due.Kid}' is due to sign, but its handover has not completed; '{signingKey.Kid}' still signs.";
        else if (due.SourceId != signingKey.SourceId)
            yield return $"Key '{due.Kid}' is listed again by a renewal whose signer has not opened, or failed; the earlier entry's signer still signs.";

        var horizon = TokenLifetimes.ExpiresAt(now, degradedThreshold);
        var signingKeyThen = timeline.SigningKeyAt(horizon);
        if (signingKeyThen.ExpiresAt <= horizon)
        {
            yield return
                $"No key will be able to sign at {horizon:O}: '{signingKeyThen.Kid}', the last to expire, expires at " +
                $"{signingKeyThen.ExpiresAt:O}, within the configured {degradedThreshold} threshold. List a successor.";
        }
    }

    private static Dictionary<string, object> KeyData(IReadOnlyList<SigningKey> published, string? signingKid, DateTimeOffset now) =>
        published.ToDictionary(
            key => key.Kid,
            object (key) => new SigningKeyExpiryStatus(
                key.Kid,
                IsSigningKey: string.Equals(key.Kid, signingKid, StringComparison.Ordinal),
                NeverExpires(key) ? null : key.ExpiresAt,
                RemainingLifetime: NeverExpires(key) ? null : key.ExpiresAt - now));

    private static bool NeverExpires(SigningKey key) => key.ExpiresAt == DateTimeOffset.MaxValue;
}
