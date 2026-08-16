namespace ZeeKayDa.Auth;

/// <summary>
/// A single startup check run by <c>StartupVerificationHostedService</c> after every internal
/// startup gate has passed. Implement this to add a framework- or provider-owned check that
/// needs async I/O, a DI scope, or a real side effect (forcing construction, performing a real
/// sign operation) — anything <see cref="Microsoft.Extensions.Options.IValidateOptions{TOptions}"/>
/// structurally cannot host because its <c>Validate</c> method is synchronous.
/// </summary>
/// <remarks>
/// Report failures and warnings by calling <see cref="StartupVerificationContext.AddFailure"/> and
/// <see cref="StartupVerificationContext.AddWarning(string, string, Microsoft.Extensions.Logging.LogLevel, object?[])"/>
/// on the context passed to <see cref="VerifyAsync"/> — never throw except for a genuinely
/// unexpected failure (a DI resolution error, a third-party bug), which the runner wraps or
/// absorbs and still aborts startup on. Never log directly: the runner logs every warning on your
/// behalf, under a log category matching your own implementation type, after the internal gate
/// phase has completed. Resolve only genuine singletons from the constructor; resolve anything
/// scoped from the <see cref="IServiceProvider"/> passed to <see cref="VerifyAsync"/> — the runner
/// creates a fresh <c>AsyncServiceScope</c> for every invocation.
/// </remarks>
public interface IStartupVerifier
{
    /// <summary>
    /// A stable name used for log attribution and diagnostics only. This is <b>not</b> an ordering
    /// or priority hint — execution order is DI registration order, and nothing a verifier returns
    /// can influence it.
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Runs this check. Report outcomes on <paramref name="context"/> rather than throwing; the
    /// runner treats a thrown <see cref="ZeeKayDaConfigurationException"/> as if its
    /// <see cref="ZeeKayDaConfigurationException.AggregatedFailures"/> had been added to
    /// <paramref name="context"/>, and any other exception as an unexpected verifier failure.
    /// </summary>
    /// <param name="context">Accumulates the failures and warnings this invocation produces.</param>
    /// <param name="scopedServices">
    /// The <see cref="IServiceProvider"/> for a fresh <c>AsyncServiceScope</c> created for this
    /// invocation. Resolve scoped dependencies from here, not from the constructor.
    /// </param>
    /// <param name="cancellationToken">A token that is signalled if the host is shutting down while startup verification is running.</param>
    ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken);
}
