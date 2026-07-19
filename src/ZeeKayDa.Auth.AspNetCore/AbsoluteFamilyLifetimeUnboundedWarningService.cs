using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Emits a startup warning when <c>AuthorizationServerOptions.TokenEndpoint.AbsoluteFamilyLifetime</c>
/// is set to the <see cref="TimeSpan.MaxValue"/> escape-hatch sentinel, so that an unbounded
/// refresh-token-family lifetime is never a silent configuration accident (ADR 0014 §5).
/// </summary>
internal sealed class AbsoluteFamilyLifetimeUnboundedWarningService : IHostedService
{
    private readonly IOptions<AuthorizationServerOptions> _options;
    private readonly ISanitizingLogger<AbsoluteFamilyLifetimeUnboundedWarningService> _logger;

    public AbsoluteFamilyLifetimeUnboundedWarningService(
        IOptions<AuthorizationServerOptions> options,
        ISanitizingLogger<AbsoluteFamilyLifetimeUnboundedWarningService> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);

        _options = options;
        _logger = logger;
    }

    /// <inheritdoc/>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (_options.Value.TokenEndpoint.AbsoluteFamilyLifetime == TimeSpan.MaxValue)
        {
            _logger.LogWarning(
                "AuthorizationServerOptions.TokenEndpoint.AbsoluteFamilyLifetime is set to the " +
                "unbounded escape-hatch sentinel (TimeSpan.MaxValue). Refresh token families will " +
                "never hit an absolute lifetime cap, causing unbounded row growth in a persisted " +
                "refresh-token grant store over time. Ensure this is an intentional choice.");
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
