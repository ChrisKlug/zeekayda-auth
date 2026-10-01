using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Configuration;

/// <summary>
/// Records at startup that <see cref="DevelopmentOptions.AllowHttpLoopbackIssuer"/> is
/// enabled, so an insecure development configuration is never silently deployed.
/// </summary>
/// <remarks>
/// <para>
/// In Development, where an <c>http</c> loopback issuer is the expected choice, this is logged at
/// <see cref="LogLevel.Information"/>. Outside it, the same configuration is logged at
/// <see cref="LogLevel.Critical"/> on every start.
/// </para>
/// <para>
/// <strong>It does not fail startup, and there is no opt-out parameter, because the flag is
/// itself the opt-out.</strong> A host had to set <c>AllowHttpLoopbackIssuer</c> deliberately, so this
/// is the "log <see cref="LogLevel.Critical"/> when they do" half of the environment rule rather
/// than a missing gate; an option whose only job is to authorise another option would be one more
/// thing to get wrong. The blast radius is capped elsewhere:
/// <c>IssuerValidator.ValidateScheme</c> permits <c>http</c> only for a loopback host and fails
/// startup for any other, so an insecure issuer cannot be a public deployment in any environment.
/// Failing here would instead break an intentional non-Development test host on
/// <c>http://localhost</c>.
/// </para>
/// </remarks>
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
    public Task VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
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
