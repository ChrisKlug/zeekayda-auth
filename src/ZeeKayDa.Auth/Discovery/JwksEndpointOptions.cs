namespace ZeeKayDa.Auth.Discovery;

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

    /// <summary>
    /// Gets or sets the JWKS response's <c>Cache-Control</c> <c>max-age</c>, in whole seconds;
    /// below one second emits <c>no-store</c>. Defaults to one hour.
    /// </summary>
    /// <remarks>
    /// How long a relying party may keep trusting a removed key: shorter narrows that window at
    /// the cost of more JWKS traffic.
    /// </remarks>
    public TimeSpan CacheMaxAge { get; set; } = TimeSpan.FromHours(1);
}
