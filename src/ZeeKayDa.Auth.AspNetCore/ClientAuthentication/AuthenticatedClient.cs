using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.AspNetCore.ClientAuthentication;

/// <summary>
/// The composite's answer: whether the client authenticated and, when it did, the exact
/// registration the credential was checked against. Everything the request goes on to decide —
/// the grant allowlist, the lifetimes — reads that registration and never looks the client up
/// again, so a repository that changes between two reads cannot hand the request a registration
/// nobody authenticated.
/// </summary>
internal sealed class AuthenticatedClient
{
    public static readonly AuthenticatedClient Refused = new(null);

    private AuthenticatedClient(IClientRegistration? client) => Client = client;

    /// <summary>The authenticated registration, or <see langword="null"/> when authentication failed.</summary>
    public IClientRegistration? Client { get; }

    public bool Authenticated => Client is not null;

    public static AuthenticatedClient Accepted(IClientRegistration client)
    {
        ArgumentNullException.ThrowIfNull(client);
        return new AuthenticatedClient(client);
    }
}
