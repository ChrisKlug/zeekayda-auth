namespace ZeeKayDa.Auth;

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
/// <strong>No activator runs if any verifier failed.</strong> That is the point of the phase: an
/// application with a broken issuer should not open a remote connection to a key vault before it is
/// told about the issuer. Within the phase, execution order is registration order and must not be
/// relied on — a check needing another's work done first asks for it, rather than assuming a
/// position. That is why <c>ISigningKeyRing</c> exposes an idempotent initialization call instead of
/// requiring its activator to run first.
/// </para>
/// </remarks>
public interface IStartupActivator : IStartupCheck;
