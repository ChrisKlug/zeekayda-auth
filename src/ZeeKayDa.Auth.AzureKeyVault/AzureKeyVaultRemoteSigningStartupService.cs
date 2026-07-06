using Microsoft.Extensions.Hosting;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AzureKeyVault;

/// <summary>
/// Forces the registered <see cref="IJwtSigningService"/> to load its signing keys during host
/// startup, so a Key Vault misconfiguration (missing key, denied access, no eligible version)
/// aborts startup with a clear <see cref="ZeeKayDaConfigurationException"/> instead of surfacing
/// as the first request's failure.
/// </summary>
/// <remarks>
/// <see cref="IJwtSigningService"/> is safe to constructor-inject directly here: it is always
/// registered as a singleton, unlike scoped services such as <c>IClientRepository</c> that must be
/// resolved from a short-lived scope to avoid capturing a scoped implementation as a root-scope
/// singleton (see <c>ClientRepositoryStartupActivator</c> for that case). <c>LoadKeysAsync</c>
/// on <see cref="JwtSigningService{TOptions}"/> is otherwise entirely lazy — nothing else forces it
/// to run before the first signing or JWKS request.
/// </remarks>
internal sealed class AzureKeyVaultRemoteSigningStartupService : IHostedService
{
    private readonly IJwtSigningService _signingService;

    public AzureKeyVaultRemoteSigningStartupService(IJwtSigningService signingService)
    {
        ArgumentNullException.ThrowIfNull(signingService);
        _signingService = signingService;
    }

    /// <inheritdoc/>
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        // Resolving the key set triggers LoadKeysAsync (key-version discovery and validation).
        // Any ZeeKayDaConfigurationException propagates and aborts startup before Kestrel accepts
        // connections.
        await _signingService.GetSigningKeysAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
