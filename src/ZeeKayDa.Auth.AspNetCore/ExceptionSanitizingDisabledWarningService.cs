using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Emits a startup warning when exception message sanitization has been disabled via
/// <see cref="LoggingOptions.DisableExceptionSanitizing"/>, alerting operators that exception
/// messages may reach log sinks unredacted.
/// </summary>
internal sealed class ExceptionSanitizingDisabledWarningService : IStartupVerifier
{
    internal const string WarningMessage =
        "Exception message sanitization is disabled via AuthorizationServerOptions.Logging.DisableExceptionSanitizing. " +
        "Exception messages logged by ZeeKayDa.Auth services may contain credential material " +
        "and will reach log sinks unredacted.";

    private readonly IOptions<AuthorizationServerOptions> _options;

    public ExceptionSanitizingDisabledWarningService(IOptions<AuthorizationServerOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
    }

    /// <inheritdoc/>
    public string Name => "ExceptionSanitizingDisabled";

    /// <inheritdoc/>
    public ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        if (_options.Value.Logging.DisableExceptionSanitizing)
        {
            context.AddWarning("logging.exception_sanitizing_disabled", WarningMessage);
        }

        return ValueTask.CompletedTask;
    }
}
