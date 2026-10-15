namespace ZeeKayDa.Auth.ConformanceHost;

/// <summary>The host's own configuration, bound from the <c>IdentityServer</c> section.</summary>
internal sealed class IdentityServerSettings
{
    public required string Issuer { get; init; }

    public required string SigningKeyPath { get; init; }
}

