namespace ZeeKayDa.Auth.Samples.IdentityServer;

/// <summary>The sample's own configuration, bound from the <c>IdentityServer</c> section.</summary>
public sealed class IdentityServerSettings
{
    public required string Issuer { get; init; }

    public IReadOnlyList<ClientSettings> Clients { get; init; } = [];
}

/// <summary>
/// A client to register. A client with a <see cref="Secret"/> or a <see cref="SecretHash"/> is
/// confidential; one with neither is public.
/// </summary>
public sealed class ClientSettings
{
    public required string ClientId { get; init; }

    /// <summary>A plaintext secret, hashed with the default hasher when the host starts.</summary>
    public string? Secret { get; init; }

    /// <summary>
    /// An already hashed secret, stored as it is, such as one another system produced. A registered
    /// hasher must declare its algorithm id.
    /// </summary>
    public string? SecretHash { get; init; }

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
}
