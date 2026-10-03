namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Provides read access to registered OAuth 2.0 / OpenID Connect clients.
/// </summary>
/// <remarks>
/// <para>
/// The framework calls this only with a well-formed <c>client_id</c>: a malformed one is answered
/// as an unknown client before the repository is reached.
/// </para>
/// </remarks>
public interface IClientRepository
{
    /// <summary>
    /// Returns the client registration for the given <paramref name="clientId"/>, or
    /// <see langword="null"/> if no client with that identifier is registered.
    /// </summary>
    /// <remarks>
    /// Implementations MUST return <see langword="null"/> for an unknown <c>client_id</c>, never
    /// throw: throwing changes response timing and enables client enumeration (RFC 9700 §2.1).
    /// Throwing when the store itself cannot answer — an outage, a timeout — is allowed; the
    /// request fails as a server error, never as <c>invalid_client</c>.
    /// </remarks>
    Task<IClientWithCredentials?> FindByClientIdAsync(
        string clientId,
        CancellationToken cancellationToken = default);
}
