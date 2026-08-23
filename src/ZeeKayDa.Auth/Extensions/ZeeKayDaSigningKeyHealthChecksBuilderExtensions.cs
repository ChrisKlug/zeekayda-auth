using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Extensions;

/// <summary>
/// Extension methods for registering <see cref="SigningKeyExpiryHealthCheck"/> against an
/// <see cref="IHealthChecksBuilder"/>.
/// </summary>
public static class ZeeKayDaSigningKeyHealthChecksBuilderExtensions
{
    /// <summary>
    /// Registers <see cref="SigningKeyExpiryHealthCheck"/>.
    /// </summary>
    /// <param name="builder">The health checks builder to add the check to.</param>
    /// <param name="configure">An optional callback to configure <see cref="SigningKeyExpiryHealthCheckOptions"/>.</param>
    /// <param name="name">The health check's registered name.</param>
    /// <param name="failureStatus">
    /// The <see cref="HealthStatus"/> to report when the check reports failure; <see langword="null"/>
    /// to use the check's own reported status.
    /// </param>
    /// <param name="tags">Tags for filtering which health checks run for a given request.</param>
    /// <returns><paramref name="builder"/> for chaining.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    /// <remarks>
    /// Registers no <see cref="ISigningKeyRing"/> and no <see cref="ISigningKeySource"/> — an
    /// application that adds only this health check still starts, and the probe reports
    /// <see cref="HealthStatus.Unhealthy"/> naming the missing registration rather than throwing.
    /// Call <see cref="ZeeKayDaSigningKeyServiceCollectionExtensions.AddZeeKayDaSigningKeySource{TSource}"/>
    /// separately to register a ring for this check to report on.
    /// </remarks>
    public static IHealthChecksBuilder AddZeeKayDaSigningKeys(
        this IHealthChecksBuilder builder,
        Action<SigningKeyExpiryHealthCheckOptions>? configure = null,
        string name = "zeekayda-signing-keys",
        HealthStatus? failureStatus = null,
        IEnumerable<string>? tags = null)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Services.AddOptions<SigningKeyExpiryHealthCheckOptions>();
        if (configure is not null)
            builder.Services.Configure(configure);

        builder.Services.TryAddSingleton<TimeProvider>(TimeProvider.System);

        return builder.Add(new HealthCheckRegistration(
            name,
            static serviceProvider => new SigningKeyExpiryHealthCheck(
                serviceProvider.GetService<ISigningKeyRing>(),
                serviceProvider.GetRequiredService<TimeProvider>(),
                serviceProvider.GetRequiredService<IOptions<SigningKeyExpiryHealthCheckOptions>>()),
            failureStatus,
            tags));
    }
}
