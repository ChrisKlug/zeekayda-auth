using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.AspNetCore.ClientAuthentication;

/// <summary>
/// Extends <see cref="TokenRequestContext"/> with the registered client that was resolved
/// from <see cref="ZeeKayDa.Auth.Clients.IClientRepository"/> for the presented
/// <see cref="TokenRequestContext.ClientId"/>. Passed to
/// <see cref="IClientAuthenticator.AuthenticateAsync"/> after all pre-authentication checks pass.
/// </summary>
public sealed class ClientAuthenticationContext : TokenRequestContext
{
    /// <summary>
    /// The registered client for the presented <see cref="TokenRequestContext.ClientId"/>.
    /// Guaranteed non-null — the <see cref="CompositeClientAuthenticator"/> only creates this
    /// context when the client exists in the repository.
    /// </summary>
    public required IClientRegistration Client { get; init; }
}
