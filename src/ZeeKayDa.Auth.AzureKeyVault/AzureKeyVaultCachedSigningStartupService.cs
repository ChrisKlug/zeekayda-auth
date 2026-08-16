using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Emits an informational log line at host startup recording that this deployment will cache the
/// signing private key in process memory for local signing.
/// </summary>
/// <remarks>
/// <para>
/// Pre-warming (forcing <see cref="IJwtSigningService.GetSigningKeysAsync"/> to run) and full
/// materialize-and-verify of the active signer are now handled once, generically, for every signing
/// provider by the framework-owned <c>SigningStartupSelfTestHostedService</c> (issue #437) — this
/// class keeps only the one genuinely provider-specific behavior: the memory-residency log line
/// below, which no other provider needs.
/// </para>
/// <para>
/// The log is emitted at <see cref="LogLevel.Information"/>, not <see cref="LogLevel.Warning"/> or
/// <see cref="LogLevel.Critical"/> — caching the private key in process memory is a legitimate,
/// deliberate architectural choice for this provider (unlike the local-development provider's
/// ephemeral/file-backed key, which is never appropriate outside development), so it does not
/// warrant a warning-level signal. It must still be visible in logs so operators can see, at a
/// glance, that this deployment will hold a permanent copy of the signing key in memory.
/// </para>
/// </remarks>
internal sealed class AzureKeyVaultCachedSigningStartupService : IHostedService
{
    private readonly IOptions<AzureKeyVaultCachedSigningOptions> _options;
    private readonly ISanitizingLogger<AzureKeyVaultCachedSigningStartupService> _logger;

    public AzureKeyVaultCachedSigningStartupService(
        IOptions<AzureKeyVaultCachedSigningOptions> options,
        ISanitizingLogger<AzureKeyVaultCachedSigningStartupService> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);

        _options = options;
        _logger = logger;
    }

    /// <inheritdoc/>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        var certificateIdentifier = _options.Value.CertificateIdentifier;
        _logger.LogInformation(
            "ZeeKayDa.Auth: the Azure Key Vault signing certificate '{CertificateName}' in vault " +
            "'{VaultUri}' will have its private key downloaded and cached in process memory for local " +
            "signing (AddAzureKeyVaultCachedSigning). This is a deliberate architectural choice, not a " +
            "misconfiguration — but it means an attacker who achieves process memory read gets a permanent " +
            "copy of the signing key.",
            certificateIdentifier.Name, certificateIdentifier.VaultUri);

        return Task.CompletedTask;
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
