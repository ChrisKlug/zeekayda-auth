using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Reports whether the current signing key is approaching or past its expiry — the only thing
/// watching once <see cref="StaticSigningKeyRing"/> has finished its one-time startup read, since a
/// static ring never notices the signing key expiring after that.
/// </summary>
/// <remarks>
/// <see cref="Microsoft.Extensions.Diagnostics.HealthChecks.HealthStatus.Unhealthy"/> once the
/// signing key's expiry has passed, <see cref="Microsoft.Extensions.Diagnostics.HealthChecks.HealthStatus.Degraded"/>
/// within the configured <see cref="SigningKeyExpiryHealthCheckOptions.DegradedThreshold"/> of it,
/// otherwise <see cref="Microsoft.Extensions.Diagnostics.HealthChecks.HealthStatus.Healthy"/> —
/// including when the signing key has no expiry at all. <c>Previous</c>/<c>Next</c> keys are
/// reported in the result data but never drive the verdict; only the key that actually signs does.
/// </remarks>
public sealed class SigningKeyExpiryHealthCheck : IHealthCheck
{
    private readonly ISigningKeyRing? _ring;
    private readonly TimeProvider _timeProvider;
    private readonly IOptions<SigningKeyExpiryHealthCheckOptions> _options;

    /// <summary>
    /// Initialises a <see cref="SigningKeyExpiryHealthCheck"/>.
    /// </summary>
    /// <param name="ring">
    /// The signing key ring to report on, or <see langword="null"/> when no
    /// <see cref="ISigningKeyRing"/> is registered — this health check can be registered
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
        ISigningKeyRing? ring, TimeProvider timeProvider, IOptions<SigningKeyExpiryHealthCheckOptions> options)
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
                "No ISigningKeyRing is registered. Call AddZeeKayDaSigningKeySource<TSource>() to " +
                "register a signing key source."));
        }

        var set = _ring.CurrentOrNull;
        if (set is null)
        {
            return Task.FromResult(HealthCheckResult.Unhealthy(
                "The signing key ring has not completed startup initialization yet."));
        }

        return Task.FromResult(Evaluate(set, _timeProvider.GetUtcNow(), _options.Value.DegradedThreshold));
    }

    /// <summary>
    /// The pure evaluation logic: no ring, no clock dependency beyond the values passed in.
    /// </summary>
    /// <param name="set">The current signing key set.</param>
    /// <param name="now">The current time.</param>
    /// <param name="degradedThreshold">
    /// How far in advance of expiry to report <see cref="HealthStatus.Degraded"/>.
    /// </param>
    internal static HealthCheckResult Evaluate(SigningKeySet set, DateTimeOffset now, TimeSpan degradedThreshold)
    {
        var data = set.Published.ToDictionary(
            key => key.Kid,
            object (key) => new SigningKeyExpiryStatus(
                key.Kid,
                IsSigningKey: string.Equals(key.Kid, set.SigningKey.Kid, StringComparison.Ordinal),
                key.ExpiresAt,
                RemainingLifetime: key.ExpiresAt is { } expiresAt ? expiresAt - now : null));

        var signingKey = set.SigningKey;

        if (signingKey.ExpiresAt is not { } signingKeyExpiresAt)
            return HealthCheckResult.Healthy($"Signing key '{signingKey.Kid}' has no expiry.", data);

        var remaining = signingKeyExpiresAt - now;

        if (remaining <= TimeSpan.Zero)
        {
            return HealthCheckResult.Unhealthy(
                $"Signing key '{signingKey.Kid}' expired at {signingKeyExpiresAt:O}.", exception: null, data);
        }

        if (remaining <= degradedThreshold)
        {
            return HealthCheckResult.Degraded(
                $"Signing key '{signingKey.Kid}' expires at {signingKeyExpiresAt:O}, within the " +
                $"configured {degradedThreshold} threshold.", exception: null, data);
        }

        return HealthCheckResult.Healthy($"Signing key '{signingKey.Kid}' expires at {signingKeyExpiresAt:O}.", data);
    }
}
