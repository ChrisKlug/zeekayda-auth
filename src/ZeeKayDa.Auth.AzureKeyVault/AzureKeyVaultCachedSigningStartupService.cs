using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Pre-warms the registered <see cref="IJwtSigningService"/> at host startup so a Key Vault
/// misconfiguration (missing certificate, denied access, no enabled/eligible version) aborts startup
/// with a clear <see cref="ZeeKayDaConfigurationException"/> instead of surfacing as the first
/// request's failure, and emits an informational log line recording that this deployment will cache
/// the private key in process memory for local signing.
/// </summary>
/// <remarks>
/// <para>
/// Combines the two behaviors that <c>AzureKeyVaultRemoteSigningStartupService</c> (pre-warm only) and
/// <c>DevelopmentSigningKeyWarningService</c> (startup log only) each provide separately for the
/// other two signing providers, because this provider needs both: pre-warming (common to every
/// Key Vault provider) and a visible log line recording where the private key will live (specific
/// to this provider's memory-residency tradeoff).
/// </para>
/// <para>
/// <b>What pre-warming catches, and what it does not (ADR 0015 Tier B):</b> this only forces
/// <see cref="IJwtSigningService.GetSigningKeysAsync"/> — the version-listing path
/// (<c>ListKeysAsync</c>) — to run, so a listing-time failure (certificate not found, access denied,
/// no enabled/eligible version) aborts startup. Real private key material is fetched lazily by
/// <c>CreateSignerAsync</c>, only once the active key actually needs to sign something (the first
/// <see cref="IJwtSigningService.SignAsync"/> call) — the same lazy-signer pattern every other ADR
/// 0015 provider follows. A private-key-specific failure (e.g. a non-exportable certificate policy)
/// therefore still surfaces on the first sign, not at startup.
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
        // Resolving the key listing triggers ListKeysAsync: the certificate's version history is
        // discovered and validated here. Any ZeeKayDaConfigurationException propagates and aborts
        // startup before Kestrel accepts connections. Real private key material is not fetched here
        // — see the class remarks — so a non-exportable-policy failure is not caught until the first
        // SignAsync call.
        await _signingService.GetSigningKeysAsync(cancellationToken).ConfigureAwait(false);

        var certificateIdentifier = _options.Value.CertificateIdentifier;
        _logger.LogInformation(
            "ZeeKayDa.Auth: the Azure Key Vault signing certificate '{CertificateName}' in vault " +
            "'{VaultUri}' will have its private key downloaded and cached in process memory for local " +
            "signing (AddAzureKeyVaultCachedSigning). This is a deliberate architectural choice, not a " +
            "misconfiguration — but it means an attacker who achieves process memory read gets a permanent " +
            "copy of the signing key.",
            certificateIdentifier.Name, certificateIdentifier.VaultUri);
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
