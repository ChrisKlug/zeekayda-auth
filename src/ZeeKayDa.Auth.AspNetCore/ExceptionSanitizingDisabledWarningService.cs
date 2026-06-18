using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Emits a startup warning when exception message sanitization has been disabled via
/// <see cref="LoggingOptions.DisableExceptionSanitizing"/>, alerting operators that exception
/// messages may reach log sinks unredacted.
/// </summary>
internal sealed class ExceptionSanitizingDisabledWarningService : IHostedService
{
    internal const string WarningMessage =
        "Exception message sanitization is disabled via AuthorizationServerOptions.Logging.DisableExceptionSanitizing. " +
        "Exception messages logged by ZeeKayDa.Auth services may contain credential material " +
        "and will reach log sinks unredacted.";

    private readonly IOptions<AuthorizationServerOptions> _options;
    private readonly ISanitizingLogger<ExceptionSanitizingDisabledWarningService> _logger;

    public ExceptionSanitizingDisabledWarningService(
        IOptions<AuthorizationServerOptions> options,
        ISanitizingLogger<ExceptionSanitizingDisabledWarningService> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);
        _options = options;
        _logger = logger;
    }

    /// <inheritdoc/>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (_options.Value.Logging.DisableExceptionSanitizing)
        {
            _logger.Log(LogLevel.Warning, WarningMessage);
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
