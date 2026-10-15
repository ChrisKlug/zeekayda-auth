using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.StartupVerification;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>Enforces the development key's environment gate at startup, and reports that the key is active.</summary>
internal sealed class DevelopmentSigningKeyVerifier(
    IHostEnvironment environment,
    IOptions<DevelopmentSigningOptions> devOptions) : IStartupVerifier
{
    internal const string WarningMessage =
        "ZeeKayDa.Auth: development signing keys are active. The signing key is ephemeral or " +
        "stored in a local file and is not suitable for production. Do not use this " +
        "configuration outside a local development environment.";

    internal const string NonDevelopmentCriticalMessage =
        "ZeeKayDa.Auth: development signing keys are active outside a Development environment. " +
        "AllowedEnvironments has been widened — this is a CRITICAL " +
        "misconfiguration. An ephemeral or local signing key in production breaks signature " +
        "validation for every relying party on restart. Replace " +
        "AddInMemoryDevelopmentSigning()/AddPersistedDevelopmentSigning() with a " +
        "production key provider immediately.";

    /// <inheritdoc/>
    public string Name => "DevelopmentSigningKey";

    /// <inheritdoc/>
    public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
        var currentEnvironment = environment.EnvironmentName;

        DevelopmentSigningKeyGate.Enforce(
            currentEnvironment,
            devOptions.Value.AllowedEnvironments);

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
            // Information: a Warning on every local start teaches operators to scroll past Warnings.
            context.AddWarning("signing.dev_keys.active", WarningMessage, LogLevel.Information);
        }

        return Task.CompletedTask;
    }
}
