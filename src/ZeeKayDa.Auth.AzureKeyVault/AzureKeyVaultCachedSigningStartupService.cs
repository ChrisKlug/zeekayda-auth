using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Pre-warms the registered <see cref="IJwtSigningService"/> at host startup so a Key Vault
/// misconfiguration (missing certificate, non-exportable policy, denied access) aborts startup
/// with a clear <see cref="ZeeKayDaConfigurationException"/> instead of surfacing as the first
/// request's failure, and emits an informational log line recording that the private key has been
/// downloaded and is cached in process memory.
/// </summary>
/// <remarks>
/// <para>
/// Combines the two behaviors that <c>AzureKeyVaultSigningStartupActivator</c> (pre-warm only) and
/// <c>DevelopmentSigningKeyWarningService</c> (startup log only) each provide separately for the
/// other two signing providers, because this provider needs both: pre-warming (common to every
/// Key Vault provider) and a visible log line recording where the private key now lives (specific
/// to this provider's memory-residency tradeoff).
/// </para>
/// <para>
/// The log is emitted at <see cref="LogLevel.Information"/>, not <see cref="LogLevel.Warning"/> or
/// <see cref="LogLevel.Critical"/> — caching the private key in process memory is a legitimate,
/// deliberate architectural choice for this provider (unlike the local-development provider's
/// ephemeral/file-backed key, which is never appropriate outside development), so it does not
/// warrant a warning-level signal. It must still be visible in logs so operators can see, at a
/// glance, that this deployment holds a permanent copy of the signing key in memory.
/// </para>
/// </remarks>
internal sealed class AzureKeyVaultCachedSigningStartupService : IHostedService
{
    private readonly IOptions<AzureKeyVaultCachedSigningOptions> _options;
    private readonly IJwtSigningService _signingService;
    private readonly ISanitizingLogger<AzureKeyVaultCachedSigningStartupService> _logger;

    public AzureKeyVaultCachedSigningStartupService(
        IOptions<AzureKeyVaultCachedSigningOptions> options,
        IJwtSigningService signingService,
        ISanitizingLogger<AzureKeyVaultCachedSigningStartupService> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(signingService);
        ArgumentNullException.ThrowIfNull(logger);

        _options = options;
        _signingService = signingService;
        _logger = logger;
    }

    /// <inheritdoc/>
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        // Resolving the key set triggers LoadKeysAsync: the certificate is downloaded and its
        // private key extracted here. Any ZeeKayDaConfigurationException propagates and aborts
        // startup before Kestrel accepts connections.
        await _signingService.GetSigningKeysAsync(cancellationToken).ConfigureAwait(false);

        var certificateIdentifier = _options.Value.CertificateIdentifier;
        _logger.LogInformation(
            "ZeeKayDa.Auth: the Azure Key Vault signing certificate '{CertificateName}' in vault " +
            "'{VaultUri}' has been downloaded and its private key is now cached in process memory for local " +
            "signing (AddAzureKeyVaultCachedSigning). This is a deliberate architectural choice, not a " +
            "misconfiguration — but it means an attacker who achieves process memory read gets a permanent " +
            "copy of the signing key.",
            certificateIdentifier.Name, certificateIdentifier.VaultUri);
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
