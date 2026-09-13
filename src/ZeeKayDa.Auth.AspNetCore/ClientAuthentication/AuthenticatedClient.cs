using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.AspNetCore.ClientAuthentication;

/// <summary>
/// The composite's answer: whether the client authenticated and, when it did, the exact
/// registration the credential was checked against. Everything the request goes on to decide —
/// the grant allowlist, the lifetimes — reads that registration and never looks the client up
/// again, so a repository that changes between two reads cannot hand the request a registration
/// nobody authenticated. Typed as metadata: the credentials stop at the composite.
/// </summary>
internal sealed class AuthenticatedClient
{
    public static readonly AuthenticatedClient Refused = new(null);

    private AuthenticatedClient(IClientMetadata? client) => Client = client;

    public static AuthenticatedClient Accepted(IClientMetadata client)
    {
        ArgumentNullException.ThrowIfNull(client);
        return new AuthenticatedClient(client);
    }

    /// <summary>The authenticated registration, or <see langword="null"/> when authentication failed.</summary>
    public IClientMetadata? Client { get; }

    public bool Authenticated => Client is not null;
}
