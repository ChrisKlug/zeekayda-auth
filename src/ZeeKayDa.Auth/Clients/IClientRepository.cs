namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Provides read access to registered OAuth 2.0 / OpenID Connect clients.
/// </summary>
/// <remarks>
/// Called only with a well-formed <c>client_id</c>.
/// </remarks>
public interface IClientRepository
{
    /// <summary>
    /// Returns the client registration for the given <paramref name="clientId"/>, or
    /// <see langword="null"/> if no client with that identifier is registered.
    /// </summary>
    /// <remarks>
    /// MUST return <see langword="null"/> for an unknown <c>client_id</c>, never throw, since throwing changes
    /// timing and enables enumeration (RFC 9700 §2.1). Throwing for an outage is allowed and answers HTTP 500.
    /// </remarks>
    Task<IClientWithCredentials?> FindByClientIdAsync(
        string clientId,
        CancellationToken cancellationToken = default);
}
