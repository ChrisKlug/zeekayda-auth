using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Emits a startup warning when an in-memory token store is active, alerting operators that
/// tokens will be lost on process restart and that single-use enforcement and reuse detection
/// are disabled across multiple instances.
/// </summary>
/// <remarks>
/// <para>
/// One instance of this service is registered per in-memory store registration call
/// (<c>AddInMemoryAuthorizationCodeStore()</c>, <c>AddInMemoryRefreshTokenStore()</c>, or both
/// via <c>AddInMemoryStores()</c>), each capturing the <c>allowOutsideDevelopment</c> value
/// supplied to its own registration call. This means the gate is enforced independently per
/// store: a consumer who calls <c>AddInMemoryAuthorizationCodeStore(allowOutsideDevelopment:
/// true)</c> and <c>AddInMemoryRefreshTokenStore()</c> (defaulting to <see langword="false"/>)
/// on the same builder still fails startup outside <c>Development</c>, because the refresh
/// token store's instance of this service was never granted the override.
/// </para>
/// <para>
/// When the host environment is not <c>Development</c> and the captured
/// <c>allowOutsideDevelopment</c> value is <see langword="false"/>, startup fails with a
/// <see cref="ZeeKayDaConfigurationException"/> so that accidental in-memory configurations are
/// never silently deployed to non-development hosts. Pass <see langword="true"/> only in test
/// hosts that intentionally run outside Development.
/// </para>
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
        "allowOutsideDevelopment has been set to true for this registration — ensure this is " +
        "intentional (e.g. an integration test host). Do not use in-memory stores in production.";

    private readonly IHostEnvironment _environment;
    private readonly bool _allowOutsideDevelopment;
    private readonly ISanitizingLogger<InMemoryStoreWarningService> _logger;

    public InMemoryStoreWarningService(
        IHostEnvironment environment,
        bool allowOutsideDevelopment,
        ISanitizingLogger<InMemoryStoreWarningService> logger)
    {
        ArgumentNullException.ThrowIfNull(environment);
        ArgumentNullException.ThrowIfNull(logger);

        _environment = environment;
        _allowOutsideDevelopment = allowOutsideDevelopment;
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

        if (!_allowOutsideDevelopment)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "stores.inmemory.non_development",
                    "In-memory token stores are active outside a Development environment. " +
                    "This is a configuration error: in-memory stores lose all tokens on restart " +
                    "and disable single-use enforcement across instances. " +
                    "Replace this registration with a persistent store implementation, or pass " +
                    "allowOutsideDevelopment: true if this host is an intentional " +
                    "non-Development test host."));
        }

        _logger.Log(LogLevel.Critical, NonDevelopmentOverrideWarningMessage);
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
