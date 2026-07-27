using Microsoft.Extensions.Hosting;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Windows;

/// <summary>
/// Forces the registered <see cref="IJwtSigningService"/> to load its signing keys during host
/// startup, so a misconfiguration in the registered certificates themselves (missing certificate,
/// unparsable key material, duplicate <c>kid</c>) aborts startup with a clear
/// <see cref="ZeeKayDaConfigurationException"/> instead of surfacing as the first request's failure.
/// Under ADR 0015 Tier A, listing never reads a private key (see
/// <c>WindowsCertificateStoreSigningJwtSigningService.ListKeysAsync</c>), so a missing private key or
/// an inaccessible key container on the <em>active</em> certificate is not caught by this pre-warm —
/// it surfaces the first time that certificate is selected as active and
/// <c>CreateSignerAsync</c> is called, which may be well after startup.
/// </summary>
/// <remarks>
/// Pre-warm only — all logging (per-certificate load lines, the too-soon-activation warning, the
/// expiring-soon warning) already lives in the base <see cref="JwtSigningService{TOptions}"/>'s
/// snapshot-building logic, driven by <c>WindowsCertificateStoreSigningJwtSigningService.ListKeysAsync</c>,
/// so unlike <c>AzureKeyVaultCachedSigningStartupService</c> this class does not add its own log
/// line — it mirrors <c>AzureKeyVaultRemoteSigningStartupService</c> instead.
/// </remarks>
internal sealed class WindowsCertificateStoreSigningStartupService : IHostedService
{
    private readonly IJwtSigningService _signingService;

    public WindowsCertificateStoreSigningStartupService(IJwtSigningService signingService)
    {
        ArgumentNullException.ThrowIfNull(signingService);
        _signingService = signingService;
    }

    /// <inheritdoc/>
    public async Task StartAsync(CancellationToken cancellationToken) =>
        await _signingService.GetSigningKeysAsync(cancellationToken).ConfigureAwait(false);

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
