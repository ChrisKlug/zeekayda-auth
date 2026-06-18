using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Emits a startup warning when exception message sanitization has been disabled via
/// <c>DisableExceptionSanitizing()</c>, alerting operators that exception messages may reach log
/// sinks unredacted.
/// </summary>
internal sealed class ExceptionSanitizingDisabledWarningService : IHostedService
{
    internal const string WarningMessage =
        "Exception message sanitization is disabled via DisableExceptionSanitizing(). " +
        "Exception messages logged by ZeeKayDa.Auth services may contain credential material " +
        "and will reach log sinks unredacted.";

    private readonly IHostEnvironment _environment;
    private readonly ISanitizingLogger<ExceptionSanitizingDisabledWarningService> _logger;

    public ExceptionSanitizingDisabledWarningService(
        IHostEnvironment environment,
        ISanitizingLogger<ExceptionSanitizingDisabledWarningService> logger)
    {
        ArgumentNullException.ThrowIfNull(environment);
        ArgumentNullException.ThrowIfNull(logger);
        _environment = environment;
        _logger = logger;
    }

    /// <inheritdoc/>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        // Escalate to Error in production so the message is visible even when Warning-level
        // logging is suppressed or routed to a low-priority sink.
        var level = _environment.IsProduction() ? LogLevel.Error : LogLevel.Warning;
        _logger.Log(level, WarningMessage);
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
