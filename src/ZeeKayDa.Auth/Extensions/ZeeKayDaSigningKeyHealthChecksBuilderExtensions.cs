using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Tokens;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>Registers <see cref="SigningKeyExpiryHealthCheck"/> with an <see cref="IHealthChecksBuilder"/>.</summary>
public static class ZeeKayDaSigningKeyHealthChecksBuilderExtensions
{
    /// <summary>
    /// Registers <see cref="SigningKeyExpiryHealthCheck"/>.
    /// </summary>
    /// <param name="builder">The health checks builder to add the check to.</param>
    /// <param name="configure">An optional callback to configure <see cref="SigningKeyExpiryHealthCheckOptions"/>.</param>
    /// <param name="name">The health check's registered name.</param>
    /// <param name="failureStatus">The status to report on failure, or <see langword="null"/> for the check's own.</param>
    /// <param name="tags">Tags for filtering which health checks run for a given request.</param>
    /// <returns><paramref name="builder"/> for chaining.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    /// <remarks>
    /// Registers no signing key ring: without one, the probe reports <see cref="HealthStatus.Unhealthy"/>
    /// naming the missing registration.
    /// </remarks>
    public static IHealthChecksBuilder AddZeeKayDaSigningKeys(
        this IHealthChecksBuilder builder,
        Action<SigningKeyExpiryHealthCheckOptions>? configure = null,
        string name = "zeekayda-signing-keys",
        HealthStatus? failureStatus = null,
        IEnumerable<string>? tags = null)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Services.AddZeeKayDaOptions<SigningKeyExpiryHealthCheckOptions>();
        if (configure is not null)
            builder.Services.Configure(configure);

        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<SigningKeyExpiryHealthCheckOptions>, SigningKeyExpiryHealthCheckOptionsValidator>());
        builder.Services.TryAddSingleton<TimeProvider>(TimeProvider.System);

        return builder.Add(new HealthCheckRegistration(
            name,
            static serviceProvider => new SigningKeyExpiryHealthCheck(
                serviceProvider.GetService<SigningKeyRing>(),
                serviceProvider.GetRequiredService<TimeProvider>(),
                serviceProvider.GetRequiredService<IOptions<SigningKeyExpiryHealthCheckOptions>>()),
            failureStatus,
            tags));
    }
}
