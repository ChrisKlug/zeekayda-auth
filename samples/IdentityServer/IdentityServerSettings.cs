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

    public IReadOnlyList<string> Scopes { get; init; } = [];
}
