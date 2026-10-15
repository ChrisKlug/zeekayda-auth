namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Represents a registered OAuth 2.0 / OpenID Connect client, credentials included.
/// </summary>
/// <remarks>
/// <para>
/// A custom repository's own entity may implement it directly. Depend on it only where authenticating the
/// client is the job; everything else takes <see cref="IClient"/>, which also holds the string-set
/// comparison invariant.
/// </para>
/// <para>
/// See <see href="https://www.rfc-editor.org/rfc/rfc6749#section-2">RFC 6749 §2</see> for public and
/// confidential clients.
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
