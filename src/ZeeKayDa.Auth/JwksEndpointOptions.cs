namespace ZeeKayDa.Auth;

/// <summary>
/// JSON Web Key Set endpoint configuration options.
/// </summary>
public sealed class JwksEndpointOptions
{
    /// <summary>
    /// Gets or sets an explicit override for the <c>jwks_uri</c> URI published in the discovery
    /// document. When <see langword="null"/>, the value is derived from the issuer.
    /// </summary>
    public string? Uri { get; set; }
}
