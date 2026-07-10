using Microsoft.Extensions.Hosting;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.MacOS;

/// <summary>
/// Forces the registered <see cref="IJwtSigningService"/> to load its signing keys during host
/// startup, so a misconfiguration (missing label, missing private key, unsupported key type,
/// inaccessible Keychain) aborts startup with a clear <see cref="ZeeKayDaConfigurationException"/>
/// instead of surfacing as the first request's failure.
/// </summary>
/// <remarks>
/// Pre-warm only — all logging (per-item load lines, the too-soon-activation warning, the
/// expiring-soon warning) already lives in <c>MacOsKeychainSigningJwtSigningService.LoadKeysAsync</c>,
/// so this class does not add its own log line, mirroring <c>WindowsCertificateStoreSigningStartupService</c>.
/// </remarks>
internal sealed class MacOsKeychainSigningStartupService : IHostedService
{
    private readonly IJwtSigningService _signingService;

    public MacOsKeychainSigningStartupService(IJwtSigningService signingService)
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
