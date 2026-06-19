namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Provides read access to registered OAuth 2.0 / OpenID Connect clients.
/// </summary>
/// <remarks>
/// <para>
/// Custom implementations must return <see langword="null"/> (never throw) for unknown or
/// malformed <c>client_id</c> values — throwing changes timing and undermines enumeration
/// defence. See ADR 0007 §6 and RFC 9700 §2.1.
/// </para>
/// <para>
/// Custom implementations MUST resolve <see cref="IClientRegistrationValidator"/> from DI and
/// invoke it before persisting a new or updated client registration.
/// </para>
/// <para>
/// For read-only or read-mostly stores (e.g. a read replica or a migrated credential store),
/// implementations MUST call <see cref="IClientRegistrationValidator.Validate"/> at a
/// deterministic point before serving a registration — typically when loading into an internal
/// cache — and MUST NOT return a registration that fails validation.
/// </para>
/// </remarks>
public interface IClientRepository
{
    /// <summary>
    /// Returns the client registration for the given <paramref name="clientId"/>, or
    /// <see langword="null"/> if no client with that identifier is registered.
    /// </summary>
    /// <remarks>
    /// Implementations MUST return <see langword="null"/> for unknown or malformed
    /// <c>client_id</c> values — never throw. Throwing from this method changes response
    /// timing and enables client enumeration attacks. See ADR 0007 §6.
    /// </remarks>
    ValueTask<IClientRegistration?> FindByClientIdAsync(
        string clientId,
        CancellationToken cancellationToken = default);
}
