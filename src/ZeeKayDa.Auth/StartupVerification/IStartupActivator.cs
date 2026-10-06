namespace ZeeKayDa.Auth.StartupVerification;

/// <summary>
/// A startup check that does real work — calls into a caller-supplied extension point, performs
/// I/O, or forces expensive construction. Runs in its own phase, after every
/// <see cref="IStartupVerifier"/> has passed.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The membership rule is mechanical:</strong> a check that resolves or calls
/// <em>anything the framework did not itself register</em> is an <see cref="IStartupActivator"/>;
/// everything else is an <see cref="IStartupVerifier"/>. Resolving counts, not just calling — a
/// constructor runs code too. So a check reading <c>IOptions&lt;AuthorizationServerOptions&gt;</c> or
/// asking <c>IServiceProviderIsService</c> a question is a verifier, while one touching an
/// <c>IClientRepository</c>, an <c>ISigningKeySource</c>, or an <c>IDistributedCache</c> is an
/// activator, whether or not that particular implementation turns out to do any work.
/// </para>
/// <para>
/// <strong>No activator runs, or is even resolved, if any verifier failed.</strong> That is the
/// point of the phase: an application with a broken issuer should not open a remote connection to
/// a key vault before it is told about the issuer. Within the phase, execution order is
/// registration order and must not be relied on — a check needing another's work done first asks
/// for it, rather than assuming a position. That is why <c>SigningKeyRing</c> exposes an
/// idempotent initialization call instead of requiring its activator to run first.
/// </para>
/// <para>
/// Registration, scope sharing, and reporting work exactly as for <see cref="IStartupVerifier"/>:
/// register as scoped, constructor-inject, report on the context, never log directly. The
/// activators share one scope, separate from the verifiers'.
/// </para>
/// </remarks>
public interface IStartupActivator
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
