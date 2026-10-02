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
/// This adds the client's credentials to <see cref="IClient"/> and nothing else. Depend on it
/// only where authenticating the client is the job; everything else takes
/// <see cref="IClient"/>, so secrets stay off code paths that never need them.
/// </para>
/// <para>
/// See <see cref="IClient"/> for the string-set comparison invariant: which code may rely
/// on the framework's ordinal copy of a registration, and which code MUST compare ordinally
/// itself.
/// </para>
/// <para>
/// See <see href="https://www.rfc-editor.org/rfc/rfc6749#section-2">RFC 6749 §2</see> for the
/// public/confidential client distinction.
/// </para>
/// </remarks>
public interface IClientWithCredentials : IClient
{
    /// <summary>
    /// The client's hashed secrets, for <c>client_secret_basic</c> and <c>client_secret_post</c>.
    /// Empty for a public client — see <see cref="IClient.IsPublic"/> for the consistency rule the
    /// two must satisfy. At most two, so a secret can be rotated without downtime.
    /// </summary>
    IReadOnlyList<ClientSecret> Secrets { get; }
}
