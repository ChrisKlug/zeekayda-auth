namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Options for <see cref="SigningKeyExpiryHealthCheck"/>.
/// </summary>
public sealed class SigningKeyExpiryHealthCheckOptions
{
    /// <summary>
    /// Gets or sets how far in advance of the signing key's expiry the health check reports
    /// <see cref="Microsoft.Extensions.Diagnostics.HealthChecks.HealthStatus.Degraded"/> rather than
    /// <see cref="Microsoft.Extensions.Diagnostics.HealthChecks.HealthStatus.Healthy"/>. Defaults to
    /// 14 days.
    /// </summary>
    public TimeSpan DegradedThreshold { get; set; } = TimeSpan.FromDays(14);
}
