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
/// via <c>AddInMemoryStores()</c>), each capturing the <c>allowOutsideDevelopment</c> value and
/// the <c>storeName</c> supplied to its own registration call. Naming the store in the log text
/// means <c>AddInMemoryStores()</c>, which registers two instances of this service, emits two
/// distinctly-worded log lines rather than the same line twice. This also means the gate is
/// enforced independently per store: a consumer who calls
/// <c>AddInMemoryAuthorizationCodeStore(allowOutsideDevelopment: true)</c> and
/// <c>AddInMemoryRefreshTokenStore()</c> (defaulting to <see langword="false"/>) on the same
/// builder still fails startup outside <c>Development</c>, because the refresh token store's
/// instance of this service was never granted the override.
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
    /// <summary>The store name passed for the authorization code store registration.</summary>
    internal const string AuthorizationCodeStoreName = "authorization code store";

    /// <summary>The store name passed for the refresh token store registration.</summary>
    internal const string RefreshTokenStoreName = "refresh token store";

    /// <summary>
    /// Composite format string for the mandatory startup warning. ADR 0008 §5 requires the
    /// message to include a specific block of text verbatim; that text is everything up to and
    /// including "...must not be used in production." — the trailing "Store: {0}." sentence is
    /// additive and distinguishes one registration's log line from another's.
    /// </summary>
    internal const string WarningMessageFormat =
        "ZeeKayDa.Auth: in-memory token stores are active. All issued tokens will be lost on " +
        "process restart, and single-use enforcement and reuse detection are disabled across " +
        "multiple instances. This configuration is intended for development and testing only " +
        "and must not be used in production. Store: {0}.";

    internal const string NonDevelopmentOverrideWarningMessageFormat =
        "ZeeKayDa.Auth: in-memory token stores are active outside a Development environment. " +
        "allowOutsideDevelopment has been set to true for this registration ({0}) — ensure " +
        "this is intentional (e.g. an integration test host). Do not use in-memory stores in " +
        "production.";

    private readonly IHostEnvironment _environment;
    private readonly string _storeName;
    private readonly bool _allowOutsideDevelopment;
    private readonly ISanitizingLogger<InMemoryStoreWarningService> _logger;

    public InMemoryStoreWarningService(
        IHostEnvironment environment,
        string storeName,
        bool allowOutsideDevelopment,
        ISanitizingLogger<InMemoryStoreWarningService> logger)
    {
        ArgumentNullException.ThrowIfNull(environment);
        ArgumentException.ThrowIfNullOrWhiteSpace(storeName);
        ArgumentNullException.ThrowIfNull(logger);

        _environment = environment;
        _storeName = storeName;
        _allowOutsideDevelopment = allowOutsideDevelopment;
        _logger = logger;
    }

    /// <inheritdoc/>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (_environment.IsDevelopment())
        {
            _logger.Log(LogLevel.Warning, WarningMessageFormat, _storeName);
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

        _logger.Log(LogLevel.Critical, NonDevelopmentOverrideWarningMessageFormat, _storeName);
        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
