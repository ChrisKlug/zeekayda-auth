namespace ZeeKayDa.Auth;

/// <summary>
/// A startup check that does real work — calls into a caller-supplied extension point, performs
/// I/O, or forces expensive construction. Runs in its own phase, after every
/// <see cref="IStartupVerifier"/> has passed.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The membership rule is mechanical.</strong> A check that only reads options or inspects
/// the container is an <see cref="IStartupVerifier"/>. A check that calls into a caller-supplied
/// extension point — a repository, a signing key source, a scope store — is an
/// <see cref="IStartupActivator"/>, because what that implementation does is not knowable from
/// here. Resolving a service whose construction runs caller code counts as calling into it.
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
