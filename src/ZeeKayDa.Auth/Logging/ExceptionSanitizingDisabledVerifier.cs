using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Configuration;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Logging;

/// <summary>
/// Records at startup that <see cref="DevelopmentOptions.DisableExceptionSanitizing"/> is enabled:
/// at <see cref="LogLevel.Information"/> in Development, and at <see cref="LogLevel.Critical"/>
/// anywhere else, where exception messages carrying credential material would reach production log
/// sinks. It never fails startup: the flag is itself the opt-out.
/// </summary>
internal sealed class ExceptionSanitizingDisabledVerifier(
    IOptions<AuthorizationServerOptions> options,
    IHostEnvironment environment) : IStartupVerifier
{
    internal const string ActiveMessage =
        "Exception message sanitization is disabled via AuthorizationServerOptions.Development.DisableExceptionSanitizing. " +
        "Exception messages logged by ZeeKayDa.Auth services may contain credential material " +
        "and will reach log sinks unredacted.";

    internal const string NonDevelopmentCriticalMessage =
        "Exception message sanitization is disabled via AuthorizationServerOptions.Development.DisableExceptionSanitizing " +
        "outside a Development environment. Exception messages logged by ZeeKayDa.Auth services may contain " +
        "credential material and will reach log sinks unredacted. Remove the setting before this " +
        "configuration reaches production.";

    /// <inheritdoc/>
    public string Name => "ExceptionSanitizingDisabled";

    /// <inheritdoc/>
    public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
        if (!options.Value.Development.DisableExceptionSanitizing)
            return Task.CompletedTask;

        // The flag is itself the opt-out, so the gate never answers Rejected.
        if (EnvironmentGate.Evaluate(environment, allowOutsideDevelopment: true) == EnvironmentGate.Verdict.ExpectedInDevelopment)
            context.AddWarning("logging.exception_sanitizing_disabled", ActiveMessage, LogLevel.Information);
        else
            context.AddWarning("logging.exception_sanitizing_disabled_outside_development", NonDevelopmentCriticalMessage, LogLevel.Critical);

        return Task.CompletedTask;
    }
}
