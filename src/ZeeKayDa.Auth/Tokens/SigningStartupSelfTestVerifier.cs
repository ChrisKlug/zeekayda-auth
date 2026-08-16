using Microsoft.Extensions.DependencyInjection;

namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Framework-owned <see cref="IStartupVerifier"/> that runs the startup self-test
/// (<see cref="ISigningStartupSelfTest"/>) against whatever <see cref="IJwtSigningService"/> is
/// registered, once per host startup. Registered once by
/// <c>ZeeKayDaAuthCoreServiceCollectionExtensions.AddZeeKayDaAuthCore</c>, so every signing-provider
/// package (development, File/PEM, PFX, Windows Certificate Store, Azure Key Vault) gets this for
/// free — a provider no longer needs its own hand-rolled self-test or startup pre-warm to catch a
/// private-key-materialization failure at deployment time rather than on the first real
/// <see cref="IJwtSigningService.SignAsync"/> call.
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
/// Resolves <see cref="IJwtSigningService"/> lazily from <c>scopedServices</c> at
/// <see cref="VerifyAsync"/> time, rather than taking it as a constructor dependency, because
/// <c>AddZeeKayDaAuthCore()</c> is called by hosts that never register a signing key provider at
/// all (for example, a test host that only exercises the discovery endpoint). Resolving it lazily
/// and no-op'ing when it is absent keeps this verifier's registration in
/// <c>AddZeeKayDaAuthCore()</c> harmless for hosts that have not (yet) configured signing.
/// </para>
/// </remarks>
internal sealed class SigningStartupSelfTestVerifier : IStartupVerifier
{
    /// <inheritdoc/>
    /// <remarks>
    /// A silent no-op when no <see cref="IJwtSigningService"/> is registered at all — that is the
    /// expected shape for a host that has not (yet) configured any signing provider. But when an
    /// <see cref="IJwtSigningService"/> <em>is</em> registered and does not implement
    /// <see cref="ISigningStartupSelfTest"/> — for example, an external, out-of-tree implementation
    /// written before this interface existed, or a decorator/wrapper registered over a real provider
    /// that only forwards <see cref="IJwtSigningService"/> — this records a
    /// <see cref="Microsoft.Extensions.Logging.LogLevel.Warning"/> naming the concrete resolved type
    /// rather than silently skipping the self-test: <see cref="IJwtSigningService"/> is registered
    /// with a plain <c>AddSingleton</c> (not <c>TryAdd</c>), so a later registration can shadow the
    /// real provider without any other signal that this control has been disabled. Every provider
    /// shipped in this repository implements <see cref="ISigningStartupSelfTest"/> via
    /// <see cref="JwtSigningService{TOptions}"/>.
    /// </remarks>
    public async ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        var signingService = scopedServices.GetService<IJwtSigningService>();
        if (signingService is null)
            return;

        if (signingService is ISigningStartupSelfTest selfTest)
        {
            await selfTest.VerifyActiveSignerAsync(cancellationToken).ConfigureAwait(false);
            return;
        }

        context.AddWarning(
            "signing.self_test_skipped",
            "ZeeKayDa.Auth: the registered IJwtSigningService ({Type}) does not implement " +
            "ISigningStartupSelfTest; the startup self-test was skipped.",
            signingService.GetType());
    }

    public string Name => "SigningStartupSelfTest";
}
