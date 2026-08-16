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
/// Pre-warming and materialize-and-verify of the active signer are handled generically for every
/// provider by the framework-owned <c>SigningStartupSelfTestHostedService</c>; this class keeps
/// only the one provider-specific behavior: the memory-residency log line below. It is logged at
/// <see cref="LogLevel.Information"/>, not a warning level, since caching the private key in
/// process memory is a deliberate architectural choice for this provider, not a misconfiguration
/// — but it must still be visible so operators can see this deployment holds a permanent copy of
/// the signing key in memory.
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
