namespace ZeeKayDa.Auth.StartupVerification;

/// <summary>
/// A cheap startup check that reads configuration or inspects the container, for what the
/// synchronous <see cref="Microsoft.Extensions.Options.IValidateOptions{TOptions}"/> cannot host.
/// A check that calls caller-supplied code or does I/O is an <see cref="IStartupActivator"/>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Register a verifier as scoped</strong>; the verifiers in a phase share one scope.
/// </para>
/// <para>
/// Report on the context rather than throwing or logging; the runner logs warnings under your
/// type's category. A thrown <see cref="ZeeKayDaConfigurationException"/> counts as its failures
/// reported, and any other exception as an unexpected failure.
/// </para>
/// </remarks>
public interface IStartupVerifier
{
    /// <summary>A stable name for log attribution only; it has no effect on execution order.</summary>
    string Name { get; }

    /// <summary>Runs this check, reporting what it finds on <paramref name="context"/>.</summary>
    /// <param name="context">Accumulates the failures and warnings this invocation produces.</param>
    /// <param name="cancellationToken">Signalled if the host shuts down while startup verification runs.</param>
    Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken);
}
