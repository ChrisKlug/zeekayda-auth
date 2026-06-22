using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Emits a startup warning when in-memory token stores are active, alerting operators that
/// tokens will be lost on process restart and that single-use enforcement and reuse detection
/// are disabled across multiple instances.
/// </summary>
/// <remarks>
/// When the host environment is not <c>Development</c> and
/// <see cref="AuthorizationServerOptions.AllowInMemoryStoresOutsideDevelopment"/> is
/// <see langword="false"/>, startup fails with a <see cref="ZeeKayDaConfigurationException"/>
/// so that accidental in-memory configurations are never silently deployed to non-development
/// hosts. Set the flag to <see langword="true"/> only in test hosts that intentionally run
/// outside Development.
/// </remarks>
internal sealed class InMemoryStoreWarningService : IHostedService
{
    internal const string WarningMessage =
        "ZeeKayDa.Auth: in-memory token stores are active. All issued tokens will be lost on " +
        "process restart, and single-use enforcement and reuse detection are disabled across " +
        "multiple instances. This configuration is intended for development and testing only " +
        "and must not be used in production.";

    internal const string NonDevelopmentOverrideWarningMessage =
        "ZeeKayDa.Auth: in-memory token stores are active outside a Development environment. " +
        "AllowInMemoryStoresOutsideDevelopment has been set — ensure this is intentional (e.g. " +
        "an integration test host). Do not use in-memory stores in production.";

    private readonly IHostEnvironment _environment;
    private readonly IOptions<AuthorizationServerOptions> _options;
    private readonly ISanitizingLogger<InMemoryStoreWarningService> _logger;

    public InMemoryStoreWarningService(
        IHostEnvironment environment,
        IOptions<AuthorizationServerOptions> options,
        ISanitizingLogger<InMemoryStoreWarningService> logger)
    {
        ArgumentNullException.ThrowIfNull(environment);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);

        _environment = environment;
        _options = options;
        _logger = logger;
    }

    /// <inheritdoc/>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (_environment.IsDevelopment())
        {
            _logger.Log(LogLevel.Warning, WarningMessage);
            return Task.CompletedTask;
        }

        if (!_options.Value.AllowInMemoryStoresOutsideDevelopment)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "stores.inmemory.non_development",
                    "In-memory token stores are active outside a Development environment. " +
                    "This is a configuration error: in-memory stores lose all tokens on restart " +
                    "and disable single-use enforcement across instances. " +
                    "Replace AddInMemoryStores() with a persistent store implementation, or set " +
                    "AllowInMemoryStoresOutsideDevelopment = true if this host is an intentional " +
                    "non-Development test host."));
        }

        _logger.Log(LogLevel.Warning, NonDevelopmentOverrideWarningMessage);
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
