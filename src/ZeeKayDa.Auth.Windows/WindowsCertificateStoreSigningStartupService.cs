using Microsoft.Extensions.Hosting;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Windows;

/// <summary>
/// Forces the registered <see cref="IJwtSigningService"/> to load its signing keys during host
/// startup, so a misconfiguration (missing certificate, missing private key, inaccessible store)
/// aborts startup with a clear <see cref="ZeeKayDaConfigurationException"/> instead of surfacing as
/// the first request's failure.
/// </summary>
/// <remarks>
/// Pre-warm only — all logging (per-certificate load lines, the too-soon-NotBefore warning, the
/// expiring-soon warning) already lives in <c>WindowsCertificateStoreSigningJwtSigningService.LoadKeysAsync</c>,
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
