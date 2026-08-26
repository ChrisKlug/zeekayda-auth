namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Represents a registered OAuth 2.0 / OpenID Connect client, credentials included.
/// </summary>
/// <remarks>
/// <para>
/// Custom <c>IClientRepository</c> implementations may make their own entity types implement
/// this interface directly, avoiding a framework-type mapping step on the hot path.
/// </para>
/// <para>
/// This adds <see cref="Credentials"/> to <see cref="IClientMetadata"/> and nothing else. Depend on it
/// only where authenticating the client is the job; everything else takes
/// <see cref="IClientMetadata"/>, so secrets stay off code paths that never need them.
/// </para>
/// <para>
/// See <see cref="IClientMetadata"/> for the string-set comparison invariant, which is a security
/// contract binding on every implementation of this interface.
/// </para>
/// <para>
/// See <see href="https://www.rfc-editor.org/rfc/rfc6749#section-2">RFC 6749 §2</see> for the
/// public/confidential client distinction.
/// </para>
/// </remarks>
public interface IClientRegistration : IClientMetadata
{
    /// <summary>
    /// Credentials stored for this client. An empty list indicates a public client — see
    /// <see cref="IClientMetadata.IsPublic"/> for the consistency rule the two must satisfy.
    /// Use <c>Credentials.OfType&lt;IClientSecret&gt;()</c> to obtain shared-secret credentials.
    /// </summary>
    IReadOnlyList<IClientCredential> Credentials { get; }
}
