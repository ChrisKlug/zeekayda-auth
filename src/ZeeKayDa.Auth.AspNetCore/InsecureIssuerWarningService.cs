using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Records at startup that <see cref="AuthorizationServerOptions.AllowInsecureIssuer"/> is
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
/// itself the opt-out.</strong> A host had to set <c>AllowInsecureIssuer</c> deliberately, so this
/// is the "log <see cref="LogLevel.Critical"/> when they do" half of the environment rule rather
/// than a missing gate; an option whose only job is to authorise another option would be one more
/// thing to get wrong. The blast radius is capped elsewhere:
/// <c>IssuerValidator.ValidateScheme</c> permits <c>http</c> only for a loopback host and fails
/// startup for any other, so an insecure issuer cannot be a public deployment in any environment.
/// Failing here would instead break an intentional non-Development test host on
/// <c>http://localhost</c>.
/// </para>
/// </remarks>
internal sealed class InsecureIssuerWarningService : IStartupVerifier
{
    /// <summary>Named-placeholder template for the Development message.</summary>
    internal const string ActiveMessageFormat =
        "AllowInsecureIssuer is enabled for issuer '{Issuer}'. " +
        "This is a LOOPBACK DEVELOPMENT-ONLY setting and must NEVER be used in production. " +
        "Remove AllowInsecureIssuer = true before deploying to any non-development environment.";

    /// <summary>Named-placeholder template for the non-Development message.</summary>
    internal const string NonDevelopmentCriticalMessageFormat =
        "AllowInsecureIssuer is enabled for issuer '{Issuer}' outside a Development environment. " +
        "This is a LOOPBACK DEVELOPMENT-ONLY setting: the issuer is served over HTTP, so every " +
        "token and code exchanged with it crosses the network in the clear. Ensure this host is " +
        "an intentional non-Development test host, and remove AllowInsecureIssuer = true before " +
        "this configuration reaches production.";

    private readonly IOptions<AuthorizationServerOptions> _options;
    private readonly IHostEnvironment _environment;

    public InsecureIssuerWarningService(
        IOptions<AuthorizationServerOptions> options,
        IHostEnvironment environment)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(environment);

        _options = options;
        _environment = environment;
    }

    /// <inheritdoc/>
    public string Name => "InsecureIssuer";

    /// <inheritdoc/>
    public ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        if (!_options.Value.AllowInsecureIssuer)
            return ValueTask.CompletedTask;

        if (_environment.IsDevelopment())
        {
            context.AddWarning(
                "issuer.insecure_allowed",
                ActiveMessageFormat,
                LogLevel.Information,
                _options.Value.Issuer);
        }
        else
        {
            context.AddWarning(
                "issuer.insecure_allowed_outside_development",
                NonDevelopmentCriticalMessageFormat,
                LogLevel.Critical,
                _options.Value.Issuer);
        }

        return ValueTask.CompletedTask;
    }
}
