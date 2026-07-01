using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Emits a startup warning when development signing keys are active, enforces the environment
/// gate, and pre-warms the signing key cache so that key generation and file I/O happen at
/// startup rather than on the first token-signing request.
/// </summary>
/// <remarks>
/// When the host environment name is not in
/// <see cref="AuthorizationServerOptions.AllowedDevelopmentJwtSigningKeysEnvironments"/>,
/// startup fails with a <see cref="ZeeKayDaConfigurationException"/> so that an accidental
/// development-key configuration is never silently deployed to a non-permitted host.
/// </remarks>
internal sealed class DevelopmentSigningKeyWarningService : IHostedService
{
    internal const string WarningMessage =
        "ZeeKayDa.Auth: development signing keys are active. The signing key is ephemeral or " +
        "stored in a local file and is not suitable for production. Do not use this " +
        "configuration outside a local development environment.";

    internal const string NonDevelopmentCriticalMessage =
        "ZeeKayDa.Auth: development signing keys are active outside a Development environment. " +
        "AllowedDevelopmentJwtSigningKeysEnvironments has been widened — this is a CRITICAL " +
        "misconfiguration. An ephemeral or local signing key in production breaks signature " +
        "validation for every relying party on restart. Replace AddDevelopmentJwtSigningKeys() " +
        "with a production key provider immediately.";

    internal const string ProductionEnvironmentFailureCode = "signing.dev_keys.production_environment";

    internal const string ProductionEnvironmentFailureMessage =
        "Development signing keys are active in a Production environment. " +
        "AllowedDevelopmentJwtSigningKeysEnvironments cannot include the Production environment. " +
        "Development keys are ephemeral or stored in a local file and are not suitable for production. " +
        "Replace AddDevelopmentJwtSigningKeys() with a production key provider.";

    private readonly IHostEnvironment _environment;
    private readonly IOptions<AuthorizationServerOptions> _serverOptions;
    private readonly IJwtSigningService _signingService;
    private readonly ISanitizingLogger<DevelopmentSigningKeyWarningService> _logger;

    public DevelopmentSigningKeyWarningService(
        IHostEnvironment environment,
        IOptions<AuthorizationServerOptions> serverOptions,
        IJwtSigningService signingService,
        ISanitizingLogger<DevelopmentSigningKeyWarningService> logger)
    {
        ArgumentNullException.ThrowIfNull(environment);
        ArgumentNullException.ThrowIfNull(serverOptions);
        ArgumentNullException.ThrowIfNull(signingService);
        ArgumentNullException.ThrowIfNull(logger);

        _environment = environment;
        _serverOptions = serverOptions;
        _signingService = signingService;
        _logger = logger;
    }

    /// <inheritdoc/>
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var currentEnvironment = _environment.EnvironmentName;
        var isProduction = string.Equals(currentEnvironment, "Production", StringComparison.OrdinalIgnoreCase);

        // Production is always a hard fail, regardless of AllowedDevelopmentJwtSigningKeysEnvironments.
        // The escape hatch cannot be used to enable dev keys in production because that is the
        // exact common footgun the gate exists to prevent.
        if (isProduction)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    ProductionEnvironmentFailureCode,
                    ProductionEnvironmentFailureMessage));
        }

        var allowedEnvironments = _serverOptions.Value.AllowedDevelopmentJwtSigningKeysEnvironments;

        var isAllowed = allowedEnvironments.Any(e =>
            string.Equals(e, currentEnvironment, StringComparison.OrdinalIgnoreCase));

        if (!isAllowed)
        {
            throw new ZeeKayDaConfigurationException(
                new ZeeKayDaConfigurationFailure(
                    "signing.dev_keys.non_development",
                    $"Development signing keys are active in environment '{currentEnvironment}', " +
                    "which is not in AllowedDevelopmentJwtSigningKeysEnvironments. " +
                    "This is a configuration error: development keys are ephemeral or stored in a " +
                    "local file and are not suitable for production. " +
                    "Replace AddDevelopmentJwtSigningKeys() with a production key provider, or add " +
                    "the environment name to AllowedDevelopmentJwtSigningKeysEnvironments if this is " +
                    "an intentional non-Development test host (e.g. an integration test host)."));
        }

        var isDevelopment = string.Equals(currentEnvironment, "Development", StringComparison.OrdinalIgnoreCase);
        if (!isDevelopment)
        {
            _logger.Log(LogLevel.Critical, NonDevelopmentCriticalMessage);
        }
        else
        {
            _logger.Log(LogLevel.Warning, WarningMessage);
        }

        // Pre-warm the cache: generate / load the key at startup so the first signing request
        // does not incur key generation latency, and so any file-I/O or permission errors
        // surface immediately rather than on the first token request.
        await _signingService.GetSigningKeysAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
