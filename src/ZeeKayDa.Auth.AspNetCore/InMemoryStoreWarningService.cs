using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Emits a startup warning when in-memory token stores are active, alerting operators that
/// tokens will be lost on process restart and that single-use enforcement and reuse detection
/// are disabled across multiple instances.
/// </summary>
internal sealed class InMemoryStoreWarningService : IHostedService
{
    internal const string WarningMessage =
        "ZeeKayDa.Auth: in-memory token stores are active. All issued tokens will be lost on " +
        "process restart, and single-use enforcement and reuse detection are disabled across " +
        "multiple instances. This configuration is intended for development and testing only " +
        "and must not be used in production.";

    private readonly ISanitizingLogger<InMemoryStoreWarningService> _logger;

    public InMemoryStoreWarningService(ISanitizingLogger<InMemoryStoreWarningService> logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        _logger = logger;
    }

    /// <inheritdoc/>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.Log(LogLevel.Warning, WarningMessage);
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
