namespace ZeeKayDa.Auth.Samples.IdentityServer;

/// <summary>The sample's own configuration, bound from the <c>IdentityServer</c> section.</summary>
public sealed class IdentityServerSettings
{
    public required string Issuer { get; init; }

    public required string SigningKeyPath { get; init; }

    public IReadOnlyList<ClientSettings> Clients { get; init; } = [];
}

/// <summary>A client to register. A client with a secret is confidential; one without is public.</summary>
public sealed class ClientSettings
{
    public required string ClientId { get; init; }

    public string? Secret { get; init; }

    public IReadOnlyList<string> RedirectUris { get; init; } = [];

    public IReadOnlyList<string> PostLogoutRedirectUris { get; init; } = [];

    public IReadOnlyList<string> Scopes { get; init; } = [];

    /// <summary>
    /// Where the client starts a new sign-in. A login or consent page submitted after its request
    /// is gone — a double click, a page left open too long — sends the user there to start again.
    /// </summary>
    public string? InitiateLoginUri { get; init; }

    /// <summary>
    /// Whether the user is shown the consent page for this client. Turn it off only for an
    /// operator's own applications: consent is what lets a user notice a request they never started.
    /// </summary>
    public bool RequireConsent { get; init; } = true;

    /// <summary>
    /// Whether the client must use PKCE. Only a confidential client can turn it off, and then only
    /// when the operator knows it checks the OpenID Connect nonce (OAuth 2.1 §7.5.1.1); the
    /// framework refuses to start with it off on a public one.
    /// </summary>
    public bool RequirePkce { get; init; } = true;

    /// <summary>
    /// The token endpoint authentication methods this confidential client may use, as the
    /// <c>token_endpoint_auth_method</c> strings of OpenID Connect Discovery 1.0 §3 — for example
    /// <c>client_secret_post</c>. Empty, the default, leaves the framework's own default of
    /// <c>client_secret_basic</c>; a non-empty list replaces it. Every entry must also be advertised
    /// by the server, or startup rejects the registration. Ignored for a public client, which
    /// authenticates with nothing.
    /// </summary>
    public IReadOnlyList<string> TokenEndpointAuthMethods { get; init; } = [];
}
