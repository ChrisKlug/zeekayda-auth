using Microsoft.Extensions.Hosting;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// Forces the registered <see cref="IJwtSigningService"/> to load its signing keys during host
/// startup, so a listing-time misconfiguration (missing file, invalid PEM/PFX content, permission
/// denied) aborts startup with a clear <see cref="ZeeKayDaConfigurationException"/> instead of
/// surfacing as the first request's failure.
/// </summary>
/// <remarks>
/// <para>
/// One shared implementation for both <c>AddPemFileSigning</c> and <c>AddPfxFileSigning</c> — this
/// class depends only on <see cref="IJwtSigningService"/> and is entirely format-agnostic, unlike
/// <c>PemFileSigningJwtSigningService</c>/<c>PfxFileSigningJwtSigningService</c> which need to know
/// how to parse their respective file formats. Pre-warm only — all logging (per-file load lines, the
/// too-soon-NotBefore warning, the expiring-soon warning) already lives in the base
/// <c>JwtSigningService{TOptions}</c>'s snapshot build, driven off each provider's
/// <c>ListKeysAsync</c>, mirroring <c>WindowsCertificateStoreSigningStartupService</c>.
/// </para>
/// <para>
/// Under the ADR 0015 lazy-signer contract, <c>ListKeysAsync</c> only ever extracts each key's
/// public parameters — a PFX file's password is not needed, and therefore not checked, until the
/// active key actually needs to sign something. This pre-warm call no longer catches a wrong PFX
/// password at startup: that failure now surfaces on the first real
/// <see cref="IJwtSigningService.SignAsync"/> call instead. Issue #437 tracks a cross-cutting
/// startup self-test to close this gap for every lazy-signer provider, not just this one.
/// </para>
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
