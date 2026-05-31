using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Emits a startup warning when <see cref="AuthorizationServerOptions.AllowInsecureIssuer"/> is
/// enabled, so that insecure development configurations are never silently deployed to production.
/// </summary>
internal sealed class InsecureIssuerWarningService : IHostedService
{
    private readonly IOptions<AuthorizationServerOptions> _options;
    private readonly ILogger<InsecureIssuerWarningService> _logger;

    public InsecureIssuerWarningService(
        IOptions<AuthorizationServerOptions> options,
        ILogger<InsecureIssuerWarningService> logger)
    {
        _options = options;
        _logger = logger;
    }

    /// <inheritdoc/>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (_options.Value.AllowInsecureIssuer)
        {
            _logger.LogWarning(
                "AllowInsecureIssuer is enabled for issuer '{Issuer}'. " +
                "This is a DEVELOPMENT-ONLY setting and must NEVER be used in production. " +
                "Remove AllowInsecureIssuer = true before deploying to any non-development environment.",
                _options.Value.Issuer);
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
