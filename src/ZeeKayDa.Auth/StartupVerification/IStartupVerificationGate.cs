namespace ZeeKayDa.Auth;

/// <summary>
/// An internal, framework-only startup check run by <c>StartupVerificationHostedService</c>
/// before any <see cref="IStartupVerifier"/>. Structurally identical to <see cref="IStartupVerifier"/>
/// in shape, but kept in a separate, closed collection so that no third-party check can ever run
/// ahead of a gate — the sanitizing-logger shadow check relies on this.
/// </summary>
/// <remarks>
/// A gate must never log — it inspects and reports through the context passed to
/// <see cref="IStartupCheck.VerifyAsync"/> exactly like a verifier does, since nothing is yet known to be safe to
/// log through until every gate has passed.
/// </remarks>
internal interface IStartupVerificationGate
{
    /// <summary>A stable name used for log attribution and diagnostics only.</summary>
    string Name { get; }

    /// <summary>
    /// Runs this check. See <see cref="IStartupCheck.VerifyAsync"/> for the exception-handling
    /// contract, which is identical.
    /// </summary>
    /// <param name="context">Accumulates the failures and warnings this invocation produces.</param>
    /// <param name="scopedServices">
    /// The <see cref="IServiceProvider"/> for a fresh <c>AsyncServiceScope</c> created for this
    /// invocation.
    /// </param>
    /// <param name="cancellationToken">A token that is signalled if the host is shutting down while startup verification is running.</param>
    ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken);
}
