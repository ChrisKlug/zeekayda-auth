namespace ZeeKayDa.Auth.StartupVerification;

/// <summary>
/// A startup check that resolves or calls anything the framework did not itself register, such as
/// an <c>IClientRepository</c> or <c>ISigningKeySource</c>. Runs after every <see cref="IStartupVerifier"/> passed.
/// </summary>
/// <remarks>
/// <para>
/// No activator is resolved if a verifier failed, so a broken issuer is reported before a key vault
/// is contacted. Order within the phase must not be relied on: a check that needs another's work asks for it.
/// </para>
/// <para>
/// Register, inject and report as for <see cref="IStartupVerifier"/>; the activators share their own scope.
/// </para>
/// </remarks>
public interface IStartupActivator
{
    /// <summary>A stable name for log attribution only; it has no effect on execution order.</summary>
    string Name { get; }

    /// <summary>Runs this check, reporting what it finds on <paramref name="context"/>.</summary>
    /// <param name="context">Accumulates the failures and warnings this invocation produces.</param>
    /// <param name="cancellationToken">Signalled if the host shuts down while startup verification runs.</param>
    Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken);
}
