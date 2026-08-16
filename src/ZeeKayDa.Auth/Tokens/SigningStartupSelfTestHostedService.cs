using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Framework-owned <see cref="IHostedService"/> that runs the ADR 0015 startup self-test
/// (<see cref="ISigningStartupSelfTest"/>) against whatever <see cref="IJwtSigningService"/> is
/// registered, once per host startup. Registered once by
/// <c>ZeeKayDaAuthCoreServiceCollectionExtensions.AddZeeKayDaAuthCore</c>, so every signing-provider
/// package (development, File/PEM, PFX, Windows Certificate Store, Azure Key Vault) gets this for
/// free — a provider no longer needs its own hand-rolled self-test or startup pre-warm to catch a
/// private-key-materialization failure at deployment time rather than on the first real
/// <see cref="IJwtSigningService.SignAsync"/> call (issue #437).
/// </summary>
/// <remarks>
/// <para>
/// Unconditional — no HSM/audit-noise opt-out. One extra sign operation (and the
/// <see cref="IJwtSigningService.GetSigningKeysAsync"/> pre-warm that materializing the active
/// signer already requires) per process start is the accepted cost of secure-by-default: a signer
/// whose private key does not match the public key it publishes under a given <c>kid</c> must never
/// silently pass startup.
/// </para>
/// <para>
/// Resolves <see cref="IJwtSigningService"/> lazily from <see cref="IServiceProvider"/> at
/// <see cref="StartAsync"/> time, rather than taking it as a constructor dependency, because
/// <c>AddZeeKayDaAuthCore()</c> is called by hosts that never register a signing key provider at
/// all (for example, a test host that only exercises the discovery endpoint). A constructor
/// dependency on <see cref="IJwtSigningService"/> would make every such host fail to start with a
/// DI resolution error; resolving it lazily and no-op'ing when it is absent keeps this hosted
/// service's registration in <c>AddZeeKayDaAuthCore()</c> harmless for hosts that have not (yet)
/// configured signing.
/// </para>
/// </remarks>
internal sealed class SigningStartupSelfTestHostedService : IHostedService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ISanitizingLogger<SigningStartupSelfTestHostedService> _logger;

    /// <summary>
    /// Initialises the hosted service.
    /// </summary>
    /// <param name="serviceProvider">
    /// The root service provider, used to resolve <see cref="IJwtSigningService"/> lazily at
    /// <see cref="StartAsync"/> time.
    /// </param>
    /// <param name="logger">
    /// Used to emit a <see cref="Microsoft.Extensions.Logging.LogLevel.Warning"/> when a registered
    /// <see cref="IJwtSigningService"/> does not implement <see cref="ISigningStartupSelfTest"/>, so
    /// that case is never silent — see <see cref="StartAsync"/>'s remarks.
    /// </param>
    public SigningStartupSelfTestHostedService(
        IServiceProvider serviceProvider, ISanitizingLogger<SigningStartupSelfTestHostedService> logger)
    {
        ArgumentNullException.ThrowIfNull(serviceProvider);
        ArgumentNullException.ThrowIfNull(logger);

        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    /// <inheritdoc/>
    /// <remarks>
    /// A silent no-op when no <see cref="IJwtSigningService"/> is registered at all — that is the
    /// expected shape for a host that has not (yet) configured any signing provider. But when an
    /// <see cref="IJwtSigningService"/> <em>is</em> registered and does not implement
    /// <see cref="ISigningStartupSelfTest"/> — for example, an external, out-of-tree implementation
    /// written before this interface existed, or a decorator/wrapper registered over a real provider
    /// that only forwards <see cref="IJwtSigningService"/> — this logs a
    /// <see cref="Microsoft.Extensions.Logging.LogLevel.Warning"/> naming the concrete resolved type
    /// rather than silently skipping the self-test: <see cref="IJwtSigningService"/> is registered
    /// with a plain <c>AddSingleton</c> (not <c>TryAdd</c>), so a later registration can shadow the
    /// real provider without any other signal that this control has been disabled. Every provider
    /// shipped in this repository implements <see cref="ISigningStartupSelfTest"/> via
    /// <see cref="JwtSigningService{TOptions}"/>.
    /// </remarks>
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var signingService = _serviceProvider.GetService<IJwtSigningService>();
        if (signingService is null)
            return;

        if (signingService is ISigningStartupSelfTest selfTest)
        {
            await selfTest.VerifyActiveSignerAsync(cancellationToken).ConfigureAwait(false);
            return;
        }

        _logger.LogWarning(
            "ZeeKayDa.Auth: the registered IJwtSigningService ({Type}) does not implement " +
            "ISigningStartupSelfTest; the ADR 0015 self-test was skipped.",
            signingService.GetType());
    }

    /// <inheritdoc/>
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
