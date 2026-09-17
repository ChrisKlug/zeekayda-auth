namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Base interface for all credential types that can be stored on a client registration.
/// </summary>
/// <remarks>
/// <para>
/// Use <c>Credentials.OfType&lt;IClientSecret&gt;()</c> to obtain shared-secret credentials.
/// Additional credential subtypes (for example <c>IJwksCredential</c> for
/// <c>private_key_jwt</c>) will be added in future versions.
/// </para>
/// <para>
/// A custom credential type implements <see cref="Snapshot"/>, either on the type itself or as a
/// default on its own sub-interface, as <see cref="IPbkdf2ClientSecret"/> does.
/// </para>
/// </remarks>
public interface IClientCredential
{
    /// <summary>
    /// Returns a new instance holding the same credential, sharing no mutable state with this one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The framework validates a registration and then authenticates the client against the same
    /// credential, so it copies every credential once, at the point the client store hands the
    /// registration over, and uses only the copy. A copy that shares a mutable buffer with this
    /// instance — a <c>byte[]</c> handed on rather than copied — lets a store that edits the buffer
    /// in place change the credential after validation approved it. Values that cannot change,
    /// such as a <see langword="string"/>, may be shared.
    /// </para>
    /// <para>
    /// Always return a new instance, even from an immutable type (<c>this with { }</c> for a
    /// record). A registration whose credential returns itself or <see langword="null"/> fails
    /// validation with <c>client.credentials.not_copied</c>; the framework cannot see whether a
    /// new instance still shares a buffer, so that part of the contract is the implementer's.
    /// </para>
    /// <para>
    /// The copy is what the client is authenticated against, so it must be a type the framework can
    /// verify: a shared secret's copy must itself be an <see cref="IClientSecret"/> that a registered
    /// <see cref="IClientSecretHasher"/> handles. Registration validation checks the copy, not this
    /// instance.
    /// </para>
    /// </remarks>
    IClientCredential Snapshot();
}
