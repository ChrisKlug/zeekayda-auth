using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Reports whether the ring can sign now, and whether some key will still be able to sign
/// <see cref="SigningKeyExpiryHealthCheckOptions.DegradedThreshold"/> from now.
/// </summary>
/// <remarks>
/// <see cref="HealthStatus.Unhealthy"/> when the key signing now has expired. Otherwise
/// <see cref="HealthStatus.Degraded"/>, naming every reason that applies, when a successor's signer
/// failed to open or self-test and was set aside until a restart; when the key due to sign now is
/// not the key signing, because a handover is still running; or when the key set in force at the
/// end of <see cref="SigningKeyExpiryHealthCheckOptions.DegradedThreshold"/> has no unexpired key to
/// sign with. Otherwise <see cref="HealthStatus.Healthy"/>. The look-ahead asks the ring's own
/// rules, so a staged successor that will take over in time keeps the check Healthy. Every
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
    /// <param name="ring">
    /// The signing key ring to report on, or <see langword="null"/> when no
    /// <see cref="SigningKeyRing"/> is registered — this health check can be registered
    /// independently of a ring, and must not itself fail host startup or resolution when one is
    /// absent.
    /// </param>
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

        var set = _ring.CurrentOrNull;
        if (set is null)
        {
            return Task.FromResult(HealthCheckResult.Unhealthy(
                "The signing key ring has not completed startup initialization yet."));
        }

        return Task.FromResult(Evaluate(
            _ring.TimelineOrNull!, set, _timeProvider.GetUtcNow(), _options.Value.DegradedThreshold));
    }

    /// <summary>
    /// The pure evaluation logic: no ring, no clock dependency beyond the values passed in.
    /// </summary>
    /// <param name="timeline">The listed keys, the keys set aside, and the rules that choose among them.</param>
    /// <param name="set">The key set the ring is serving now.</param>
    /// <param name="now">The current time.</param>
    /// <param name="degradedThreshold">
    /// How far ahead a key must still be able to sign for <see cref="HealthStatus.Healthy"/>.
    /// </param>
    internal static HealthCheckResult Evaluate(
        SigningKeyTimeline timeline, SigningKeySet set, DateTimeOffset now, TimeSpan degradedThreshold)
    {
        var data = set.Published.ToDictionary(
            key => key.Kid,
            object (key) => new SigningKeyExpiryStatus(
                key.Kid,
                IsSigningKey: string.Equals(key.Kid, set.SigningKey.Kid, StringComparison.Ordinal),
                NeverExpires(key) ? null : key.ExpiresAt,
                RemainingLifetime: NeverExpires(key) ? null : key.ExpiresAt - now));

        var signingKey = set.SigningKey;

        if (signingKey.ExpiresAt <= now)
        {
            return HealthCheckResult.Unhealthy(
                $"Signing key '{signingKey.Kid}' expired at {signingKey.ExpiresAt:O}, and no unexpired key can sign.",
                exception: null, data);
        }

        var reasons = DegradedReasons(timeline, signingKey, now, degradedThreshold).ToList();
        if (reasons.Count > 0)
            return HealthCheckResult.Degraded(string.Join(" ", reasons), exception: null, data);

        return NeverExpires(signingKey)
            ? HealthCheckResult.Healthy($"Signing key '{signingKey.Kid}' has no expiry.", data)
            : HealthCheckResult.Healthy($"Signing key '{signingKey.Kid}' expires at {signingKey.ExpiresAt:O}.", data);
    }

    private static IEnumerable<string> DegradedReasons(
        SigningKeyTimeline timeline, SigningKey signingKey, DateTimeOffset now, TimeSpan degradedThreshold)
    {
        if (timeline.SetAside.Count > 0)
        {
            yield return
                $"The signer of {string.Join(", ", timeline.SetAside.Select(key => $"'{key.Kid}'"))} failed to open or " +
                "self-test when due to sign, so it is set aside until a restart. Fix the key and restart.";
        }

        var due = timeline.At(now).SigningKey;
        if (due.Kid != signingKey.Kid)
            yield return $"Key '{due.Kid}' is due to sign, but its handover has not completed; '{signingKey.Kid}' still signs.";

        var horizon = TokenLifetimes.ExpiresAt(now, degradedThreshold);
        var signingKeyThen = timeline.At(horizon).SigningKey;
        if (signingKeyThen.ExpiresAt <= horizon)
        {
            yield return
                $"No key will be able to sign at {horizon:O}: '{signingKeyThen.Kid}', the last to expire, expires at " +
                $"{signingKeyThen.ExpiresAt:O}, within the configured {degradedThreshold} threshold. List a successor.";
        }
    }

    private static bool NeverExpires(SigningKey key) => key.ExpiresAt == DateTimeOffset.MaxValue;
}
