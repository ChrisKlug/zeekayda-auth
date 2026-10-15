using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// Logs that <see cref="DevelopmentOptions.AllowHttpLoopbackIssuer"/> is on, critically outside
/// Development. It never fails startup: the flag is its own opt-out, and HTTP stays loopback-only.
/// </summary>
internal sealed class HttpLoopbackIssuerVerifier(
    IOptions<AuthorizationServerOptions> options,
    IHostEnvironment environment) : IStartupVerifier
{
    /// <summary>Named-placeholder template for the Development message.</summary>
    internal const string ActiveMessageFormat =
        "Development.AllowHttpLoopbackIssuer is enabled for issuer '{Issuer}'. " +
        "This is a LOOPBACK DEVELOPMENT-ONLY setting and must NEVER be used in production. " +
        "Remove Development.AllowHttpLoopbackIssuer = true before deploying to any non-development environment.";

    /// <summary>Named-placeholder template for the non-Development message.</summary>
    internal const string NonDevelopmentCriticalMessageFormat =
        "Development.AllowHttpLoopbackIssuer is enabled for issuer '{Issuer}' outside a Development environment. " +
        "This is a LOOPBACK DEVELOPMENT-ONLY setting: the issuer is served over HTTP, so every " +
        "token and code exchanged with it crosses the network in the clear. Ensure this host is " +
        "an intentional non-Development test host, and remove Development.AllowHttpLoopbackIssuer = true before " +
        "this configuration reaches production.";

    /// <inheritdoc/>
    public string Name => "HttpLoopbackIssuer";

    /// <inheritdoc/>
    public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
        if (!options.Value.Development.AllowHttpLoopbackIssuer)
            return Task.CompletedTask;

        // The flag is itself the opt-out, so the gate never answers Rejected.
        if (EnvironmentGate.Evaluate(environment, allowOutsideDevelopment: true) == EnvironmentGate.Verdict.ExpectedInDevelopment)
        {
            context.AddWarning(
                "issuer.insecure_allowed",
                ActiveMessageFormat,
                LogLevel.Information,
                options.Value.Issuer);
        }
        else
        {
            context.AddWarning(
                "issuer.insecure_allowed_outside_development",
                NonDevelopmentCriticalMessageFormat,
                LogLevel.Critical,
                options.Value.Issuer);
        }

        return Task.CompletedTask;
    }
}
