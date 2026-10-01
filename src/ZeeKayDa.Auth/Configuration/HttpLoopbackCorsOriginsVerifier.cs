using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// Records at startup that <see cref="DevelopmentOptions.AllowHttpLoopbackCorsOrigins"/> is
/// enabled: at <see cref="LogLevel.Information"/> in Development, where it is the expected choice,
/// and at <see cref="LogLevel.Critical"/> anywhere else. It never fails startup, for the reason
/// <see cref="HttpLoopbackIssuerVerifier"/> gives: the flag is itself the opt-out, and a non-loopback
/// HTTP origin fails startup whatever the flag says.
/// </summary>
internal sealed class HttpLoopbackCorsOriginsVerifier(
    IOptions<AuthorizationServerOptions> options,
    IHostEnvironment environment) : IStartupVerifier
{
    internal const string ActiveMessage =
        "Development.AllowHttpLoopbackCorsOrigins is enabled: CorsOrigins may contain HTTP loopback origins. " +
        "This is a DEVELOPMENT-ONLY setting and must NEVER be used in production.";

    internal const string NonDevelopmentCriticalMessage =
        "Development.AllowHttpLoopbackCorsOrigins is enabled outside a Development environment: " +
        "CorsOrigins may contain HTTP loopback origins. Ensure this host is an intentional " +
        "non-Development test host, and remove the setting before this configuration reaches production.";

    /// <inheritdoc/>
    public string Name => "HttpLoopbackCorsOrigins";

    /// <inheritdoc/>
    public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
        if (!options.Value.Development.AllowHttpLoopbackCorsOrigins)
            return Task.CompletedTask;

        // The flag is itself the opt-out, so the gate never answers Rejected.
        if (EnvironmentGate.Evaluate(environment, allowOutsideDevelopment: true) == EnvironmentGate.Verdict.ExpectedInDevelopment)
            context.AddWarning("cors_origins.http_loopback_allowed", ActiveMessage, LogLevel.Information);
        else
            context.AddWarning("cors_origins.http_loopback_allowed_outside_development", NonDevelopmentCriticalMessage, LogLevel.Critical);

        return Task.CompletedTask;
    }
}
