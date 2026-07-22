using Microsoft.Extensions.Hosting;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// Forces the registered <see cref="IJwtSigningService"/> to load its signing keys during host
/// startup, so a misconfiguration (missing file, invalid PEM/PFX content, permission denied, wrong
/// password) aborts startup with a clear <see cref="ZeeKayDaConfigurationException"/> instead of
/// surfacing as the first request's failure.
/// </summary>
/// <remarks>
/// One shared implementation for both <c>AddPemFileSigning</c> and <c>AddPfxFileSigning</c> — this
/// class depends only on <see cref="IJwtSigningService"/> and is entirely format-agnostic, unlike
/// <c>PemFileSigningJwtSigningService</c>/<c>PfxFileSigningJwtSigningService</c> which need to know
/// how to parse their respective file formats. Pre-warm only — all logging (per-file load lines, the
/// too-soon-NotBefore warning, the expiring-soon warning) already lives in the base
/// <c>JwtSigningService{TOptions}</c>'s snapshot build, driven off each provider's
/// <c>ListKeysAsync</c>, mirroring <c>WindowsCertificateStoreSigningStartupService</c>.
/// </remarks>
internal sealed class FileSigningStartupService : IHostedService
{
    private readonly IJwtSigningService _signingService;

    public FileSigningStartupService(IJwtSigningService signingService)
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
