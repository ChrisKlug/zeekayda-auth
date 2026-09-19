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
    /// Lets a confidential client omit PKCE and rely on the OpenID Connect nonce instead
    /// (OAuth 2.1 §7.5.1.1). Only a confidential client can set it; the framework refuses to start
    /// with it on a public one. Set it only for a client the operator knows checks the nonce.
    /// </summary>
    public bool AllowNonceInsteadOfPkce { get; init; }
}
