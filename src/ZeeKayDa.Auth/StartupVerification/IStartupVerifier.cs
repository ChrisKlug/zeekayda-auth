namespace ZeeKayDa.Auth.StartupVerification;

/// <summary>
/// A cheap startup check that reads configuration or inspects the container, run by
/// <c>StartupVerificationHostedService</c> before any <see cref="IStartupActivator"/>. Implement this
/// for a check that needs an async signature or a DI scope — anything
/// <see cref="Microsoft.Extensions.Options.IValidateOptions{TOptions}"/> structurally cannot host
/// because its <c>Validate</c> method is synchronous.
/// </summary>
/// <remarks>
/// <para>
/// A check that calls into a caller-supplied extension point, performs I/O, or forces expensive
/// construction belongs in <see cref="IStartupActivator"/> instead — its phase does not run at all
/// when a verifier has already failed, so a broken configuration is reported before the work is
/// done.
/// </para>
/// <para>
/// <strong>Register a verifier as scoped</strong> and constructor-inject what it needs, scoped
/// services included. The runner resolves every verifier from one scope it creates for the phase,
/// so <strong>the checks in a phase share a scope</strong>.
/// </para>
/// <para>
/// Report failures and warnings on the context rather than throwing, and never log directly: the
/// runner logs every warning on your behalf, under a log category matching your implementation
/// type. A thrown <see cref="ZeeKayDaConfigurationException"/> counts as if its
/// <see cref="ZeeKayDaConfigurationException.AggregatedFailures"/> had been reported; any other
/// exception is recorded as an unexpected failure, and startup still aborts.
/// </para>
/// </remarks>
public interface IStartupVerifier
{
    /// <summary>
    /// A stable name used for log attribution and diagnostics only. This is <b>not</b> an ordering
    /// or priority hint — execution order is DI registration order within a phase, and nothing a
    /// check returns can influence it.
    /// </summary>
    string Name { get; }

    /// <summary>Runs this check, reporting what it finds on <paramref name="context"/>.</summary>
    /// <param name="context">Accumulates the failures and warnings this invocation produces.</param>
    /// <param name="cancellationToken">Signalled if the host shuts down while startup verification runs.</param>
    Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken);
}
