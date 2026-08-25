using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Emits a startup warning when development signing keys are active, and enforces the environment
/// gate.
/// </summary>
/// <remarks>
/// When the host environment name is not in
/// <see cref="DevelopmentSigningKeyOptions.AllowedDevelopmentJwtSigningKeysEnvironments"/>,
/// startup fails so that an accidental development-key configuration is never silently deployed
/// to a non-permitted host.
/// </remarks>
internal sealed class DevelopmentSigningKeyWarningService : IStartupVerifier
{
    internal const string WarningMessage =
        "ZeeKayDa.Auth: development signing keys are active. The signing key is ephemeral or " +
        "stored in a local file and is not suitable for production. Do not use this " +
        "configuration outside a local development environment.";

    internal const string NonDevelopmentCriticalMessage =
        "ZeeKayDa.Auth: development signing keys are active outside a Development environment. " +
        "AllowedDevelopmentJwtSigningKeysEnvironments has been widened — this is a CRITICAL " +
        "misconfiguration. An ephemeral or local signing key in production breaks signature " +
        "validation for every relying party on restart. Replace " +
        "AddInMemoryDevelopmentJwtSigningKeys()/AddPersistedDevelopmentJwtSigningKeys() with a " +
        "production key provider immediately.";

    private readonly IHostEnvironment _environment;
    private readonly IOptions<DevelopmentSigningKeyOptions> _devOptions;

    public DevelopmentSigningKeyWarningService(
        IHostEnvironment environment,
        IOptions<DevelopmentSigningKeyOptions> devOptions)
    {
        ArgumentNullException.ThrowIfNull(environment);
        ArgumentNullException.ThrowIfNull(devOptions);

        _environment = environment;
        _devOptions = devOptions;
    }

    /// <inheritdoc/>
    public string Name => "DevelopmentSigningKey";

    /// <inheritdoc/>
    public ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        var currentEnvironment = _environment.EnvironmentName;

        // Production is always a hard fail; non-allowed environments also throw. The runner
        // absorbs a thrown ZeeKayDaConfigurationException, preserving its Code verbatim.
        DevelopmentSigningKeyGate.Enforce(
            currentEnvironment,
            _devOptions.Value.AllowedDevelopmentJwtSigningKeysEnvironments);

        var isDevelopment = string.Equals(currentEnvironment, "Development", StringComparison.OrdinalIgnoreCase);
        if (!isDevelopment)
        {
            context.AddWarning(
                "signing.dev_keys.active_outside_development",
                NonDevelopmentCriticalMessage,
                LogLevel.Critical);
        }
        else
        {
            context.AddWarning("signing.dev_keys.active", WarningMessage);
        }

        return ValueTask.CompletedTask;
    }
}
