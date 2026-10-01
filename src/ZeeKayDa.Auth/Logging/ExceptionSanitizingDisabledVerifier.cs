using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.Logging;

/// <summary>
/// Emits a startup warning when exception message sanitization has been disabled via
/// <see cref="LoggingOptions.DisableExceptionSanitizing"/>, alerting operators that exception
/// messages may reach log sinks unredacted.
/// </summary>
internal sealed class ExceptionSanitizingDisabledVerifier(
    IOptions<AuthorizationServerOptions> options) : IStartupVerifier
{
    internal const string WarningMessage =
        "Exception message sanitization is disabled via AuthorizationServerOptions.Logging.DisableExceptionSanitizing. " +
        "Exception messages logged by ZeeKayDa.Auth services may contain credential material " +
        "and will reach log sinks unredacted.";

    /// <inheritdoc/>
    public string Name => "ExceptionSanitizingDisabled";

    /// <inheritdoc/>
    public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
        if (options.Value.Logging.DisableExceptionSanitizing)
        {
            context.AddWarning("logging.exception_sanitizing_disabled", WarningMessage);
        }

        return Task.CompletedTask;
    }
}
